//! Post-election pipeline (SPEC.md §16.2, §16.5, §17.7, §18, §19.1, §20.5,
//! §21 and §22).
//!
//! Everything here is a pure, deterministic function of the board entries, the
//! manifest and the context, so a verifier calls the same functions and gets the
//! same bytes. The stages are:
//!
//! 1. [`board_view`] ingests the board up to `tally_cutoff` (§17.7) and judges
//!    every cast ballot once, in board order (§12.6).
//! 2. [`section_tallies`] builds one section tally per pre-BU (§18.1).
//! 3. [`pool_tally`] and [`encrypted_tally`] build the pool and the index (§18.2,
//!    §18.3).
//! 4. [`mix_plan`] gives the mix units and their input lists (§19.1).
//! 5. [`trustee_decrypt`] is what a trustee signs, and only after recomputing
//!    the target itself (§20.5). [`final_bu`] (§16.5) and [`election_result`]
//!    (§21) combine the share sets into published numbers.
//!
//! Deviation (documented in `docs/spec-issues.md` item 9): the trustee and the
//! verifier call the same functions here, so they share the code that decides
//! what a target is.

use std::collections::BTreeMap;

use rand_core::{CryptoRng, RngCore};

use crate::apportionment::{apportion, party_totals};
use crate::ballot::{Ballot, ContestStatus, Election};
use crate::board::record_id;
use crate::cbor::Value;
use crate::ceremony::Context;
use crate::chain::Reveal;
use crate::decrypt::{
    check_final_bu, combine, count_mix_rows, decode_slot, decode_sums, mix_list_items,
    pool_tally_items, section_tally_items, ContestResult, DecryptionShareSet, ElectionResult,
    FinalBu, SectionResult,
};
use crate::elgamal::Ciphertext;
use crate::error::Error;
use crate::group::{Scalar, B};
use crate::journal::{PreBu, Record};
use crate::manifest::{Contest, ContestKind, Manifest, Method};
use crate::mixnet::{check_mix_chain, plan, CastBallot, MixUnit};
use crate::package::{BoardState, Ingest, Package, PackageKind, RecoveredPackage};
use crate::registry::Registry;
use crate::shuffle::{MixOutput, Row};
use crate::sign::{SigningKey, VerifyingKey};
use crate::tally::{
    fingerprint, indices, judge_cast, merge_sums, split_pooled, sum_ballots, ContestSum,
    EncryptedTally, JudgedBallot, PoolTally, Reservations, SectionTally,
};

fn tally(msg: impl Into<String>) -> Error {
    Error::Tally(msg.into())
}

fn decryption(msg: impl Into<String>) -> Error {
    Error::Decryption(msg.into())
}

/// `section_result.final_bu_id` of a section with nothing to open. A final BU
/// needs at least one share, so such a section has none (see the report).
const NO_FINAL_BU: [u8; 32] = [0; 32];

/// Everything derived from the board up to `tally_cutoff` (§17.7).
pub struct BoardView<'a> {
    pub manifest: &'a Manifest,
    pub context: &'a Context,
    pub entries: &'a [Value],
    /// Entry index of `tally_cutoff`: the tree size the tally covers.
    pub cutoff_index: u64,
    /// The registry in force at the cutoff.
    pub registry: Registry,
    /// Accepted packages and recovered packages before the cutoff, in board
    /// order. Superseded recovered packages are listed with `superseded` set and
    /// no ballots, so they are skipped for tallying.
    pub packages: Vec<ViewPackage>,
    /// Entries before the cutoff that the board refused, with the reason.
    pub rejected: Vec<(u64, String)>,
}

impl BoardView<'_> {
    /// The election as the ballot checks see it.
    fn election(&self) -> Election<'_> {
        Election {
            context_hash: self.context.hash(),
            k: self.context.k,
            manifest: self.manifest,
        }
    }
}

/// One accepted package (or recovered package) as the tally sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct ViewPackage {
    pub entry_index: u64,
    /// RecordId of the package entry.
    pub id: [u8; 32],
    pub recovered: bool,
    pub superseded: bool,
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    /// Region of the section (§19.1).
    pub region: String,
    /// Contests the machine offered (from the registry).
    pub offered: Vec<u64>,
    /// The pre-BU in the package, with its machine-signed value. Recovered
    /// packages have none.
    pub pre_bu: Option<(PreBu, Value)>,
    /// Cast ballots in package order, judged with the board-wide reservations.
    pub cast: Vec<(Ballot, JudgedBallot)>,
    /// Spoiled ballots with their reveals, in package order. Not tallied.
    pub spoiled: Vec<(Ballot, Reveal)>,
}

/// Field 0 of a board entry.
fn entry_tag(e: &Value) -> Option<&str> {
    e.get(0).ok().flatten().and_then(|t| t.as_text().ok())
}

/// Cast and spoiled ballots of a journal, in journal order (§18.1).
fn ballots_of(records: &[Record]) -> (Vec<Ballot>, Vec<(Ballot, Reveal)>) {
    let mut cast = Vec::new();
    let mut spoiled = Vec::new();
    let mut open: Option<&Ballot> = None;
    for rec in records {
        match rec {
            Record::Committed { ballot, .. } => open = Some(ballot),
            Record::Cast { .. } => cast.extend(open.take().cloned()),
            Record::Spoiled { reveal, .. } => {
                spoiled.extend(open.take().map(|b| (b.clone(), reveal.clone())));
            }
            Record::Abandoned { .. } => open = None,
            _ => {}
        }
    }
    (cast, spoiled)
}

/// The machine-signed pre-BU of a package's journal, if it has one (§16.2).
fn pre_bu_of(
    records: &[Record],
    machine_key: &VerifyingKey,
) -> Result<Option<(PreBu, Value)>, Error> {
    let found = records.iter().find_map(|r| match r {
        Record::PreBuSigned { pre_bu, .. } => Some(pre_bu.clone()),
        _ => None,
    });
    found
        .map(|v| Ok((PreBu::from_signed(&v, machine_key)?, v)))
        .transpose()
}

/// Ingests `entries` up to `tally_cutoff` (§17.7) and judges every cast ballot
/// (§12.6). One [`Reservations`] covers all ballots, in board order, then package
/// order.
///
/// Errors if the board has no accepted `tally_cutoff` or no registry.
pub fn board_view<'a>(
    manifest: &'a Manifest,
    context: &'a Context,
    entries: &'a [Value],
) -> Result<BoardView<'a>, Error> {
    let cutoff = entries
        .iter()
        .position(|e| entry_tag(e) == Some("tally_cutoff"))
        .ok_or_else(|| tally("the board has no tally_cutoff entry"))?;

    let mut state = BoardState::new(manifest, context);
    let mut rejected = Vec::new();
    for (i, entry) in entries[..=cutoff].iter().enumerate() {
        if let Ingest::Rejected(reason) = state.ingest(entry) {
            if i == cutoff {
                return Err(tally(format!("tally_cutoff is not accepted: {reason}")));
            }
            rejected.push((i as u64, reason));
        }
    }
    let registry = state
        .registry()
        .cloned()
        .ok_or_else(|| tally("no signed registry before tally_cutoff"))?;

    let election = Election {
        context_hash: context.hash(),
        k: context.k,
        manifest,
    };
    let mut reservations = Reservations::new();
    let mut packages = Vec::new();
    for ap in state.accepted_packages() {
        let entry = &entries[ap.entry_index as usize];
        let machine = registry.machine(&ap.header.machine_id).ok_or_else(|| {
            tally(format!(
                "machine {:?} is not registered",
                ap.header.machine_id
            ))
        })?;
        let section = registry.section(&ap.summary.section_id).ok_or_else(|| {
            tally(format!(
                "section {:?} is not registered",
                ap.summary.section_id
            ))
        })?;

        let recovered = ap.kind == PackageKind::Recovered;
        let records = match ap.kind {
            PackageKind::Package => Package::from_signed(entry, &machine.key)?.records,
            PackageKind::Recovered => RecoveredPackage::from_value(entry)?.records,
        };
        let pre_bu = if recovered {
            None
        } else {
            pre_bu_of(&records, &machine.key)?
        };
        let offered = machine.contests.clone();

        let mut cast = Vec::new();
        let mut spoiled = Vec::new();
        if !ap.superseded {
            let (cast_ballots, spoiled_ballots) = ballots_of(&records);
            for ballot in cast_ballots {
                let judged = judge_cast(&election, &offered, &ballot, &mut reservations);
                cast.push((ballot, judged));
            }
            spoiled = spoiled_ballots;
        }

        packages.push(ViewPackage {
            entry_index: ap.entry_index,
            id: ap.package_id,
            recovered,
            superseded: ap.superseded,
            machine_id: ap.summary.machine_id.clone(),
            section_id: ap.summary.section_id.clone(),
            session_id: ap.summary.session_id.clone(),
            region: section.region.clone(),
            offered,
            pre_bu,
            cast,
            spoiled,
        });
    }

    Ok(BoardView {
        manifest,
        context,
        entries,
        cutoff_index: cutoff as u64,
        registry,
        packages,
        rejected,
    })
}

/// Homomorphic contests of the manifest, ascending, with a zero sum each
/// (identity ciphertexts, `counted = 0`).
fn zero_sums(manifest: &Manifest) -> Vec<ContestSum> {
    let mut contests: Vec<&Contest> = manifest
        .contests
        .iter()
        .filter(|c| c.method == Method::Homomorphic)
        .collect();
    contests.sort_by_key(|c| c.index);
    contests
        .into_iter()
        .map(|c| ContestSum {
            contest: c.index,
            counted: 0,
            sums: vec![Ciphertext::zero(); c.options.len()],
        })
        .collect()
}

/// Per contest, how many cast ballots of `p` were excluded (§12.6). A ballot that
/// is not well-formed excludes every offered contest.
fn exclusions(p: &ViewPackage) -> BTreeMap<u64, u64> {
    let mut out: BTreeMap<u64, u64> = p.offered.iter().map(|&c| (c, 0)).collect();
    for (_, judged) in &p.cast {
        match &judged.well_formed {
            Err(_) => {
                for &c in &p.offered {
                    *out.entry(c).or_insert(0) += 1;
                }
            }
            Ok(()) => {
                for (c, status) in &judged.contests {
                    if matches!(status, ContestStatus::Excluded(_)) {
                        *out.entry(*c).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    out
}

fn add_counts(acc: &mut BTreeMap<u64, u64>, more: &BTreeMap<u64, u64>) {
    for (&c, &n) in more {
        *acc.entry(c).or_insert(0) += n;
    }
}

/// §18.1: one section tally per package that carries a pre-BU, in board order.
///
/// Each covers the package's own cast ballots and those of the recovered packages
/// its pre-BU imports (matched by RecordId among the view's packages; an import
/// that is not on the board contributes nothing). Contests with fewer than
/// `min_section_ballots` counted ballots are pooled. The returned flag is true
/// when the fingerprint recomputed from the board equals the pre-BU's field 14.
/// The third element is the pooled sums of that section.
pub fn section_tallies(view: &BoardView) -> Vec<(SectionTally, bool, Vec<ContestSum>)> {
    let election = view.election();
    let min = view.manifest.min_section_ballots;
    let mut out = Vec::new();
    for p in &view.packages {
        let Some((pb, value)) = &p.pre_bu else {
            continue;
        };
        let mut covered: Vec<&ViewPackage> = vec![p];
        let mut ids = vec![p.id];
        for imp in &pb.imported {
            ids.push(imp.package_id);
            if let Some(q) = view.packages.iter().find(|q| q.id == imp.package_id) {
                covered.push(q);
            }
        }
        let pairs: Vec<(&Ballot, &JudgedBallot)> = covered
            .iter()
            .copied()
            .flat_map(|q| q.cast.iter().map(|(b, j)| (b, j)))
            .collect();
        let (kept, pooled) = split_pooled(sum_ballots(&election, &pairs), min);
        let pooled_indices = indices(&pooled);
        let context_hash = view.context.hash();
        let fp = fingerprint(
            &context_hash,
            &pb.machine_id,
            &pb.session_id,
            &pb.imported,
            &kept,
            &pooled_indices,
        );
        let tally = SectionTally {
            context_hash,
            pre_bu_id: record_id(value),
            section_id: pb.section_id.clone(),
            packages: ids,
            contests: kept,
            pooled: pooled_indices,
        };
        out.push((tally, fp == pb.fingerprint, pooled));
    }
    out
}

/// §18.2: the pool. It sums the pooled contests of every section tally and the
/// cast ballots of non-superseded packages that no pre-BU covers. Every
/// homomorphic contest is listed, with the zero sum if nothing was pooled into
/// it.
pub fn pool_tally(
    view: &BoardView,
    sections: &[(SectionTally, bool, Vec<ContestSum>)],
) -> PoolTally {
    let election = view.election();
    // Packages a pre-BU covers: its own, and every import it lists.
    let covered: Vec<[u8; 32]> = view
        .packages
        .iter()
        .filter_map(|p| p.pre_bu.as_ref().map(|(pb, _)| (p.id, pb)))
        .flat_map(|(id, pb)| std::iter::once(id).chain(pb.imported.iter().map(|i| i.package_id)))
        .collect();
    let uncovered: Vec<(&Ballot, &JudgedBallot)> = view
        .packages
        .iter()
        .filter(|p| !p.superseded && !covered.contains(&p.id))
        .flat_map(|p| p.cast.iter().map(|(b, j)| (b, j)))
        .collect();

    let mut total = zero_sums(view.manifest);
    for (_, _, pooled) in sections {
        total = merge_sums(&total, pooled);
    }
    total = merge_sums(&total, &sum_ballots(&election, &uncovered));
    PoolTally {
        context_hash: view.context.hash(),
        tree_size: view.cutoff_index,
        contests: total,
    }
}

/// §18.3: the index of the tally, for the given STH root at `tally_cutoff`.
pub fn encrypted_tally(
    view: &BoardView,
    sections: &[(SectionTally, bool, Vec<ContestSum>)],
    pool: &PoolTally,
    sth_root: [u8; 32],
) -> EncryptedTally {
    EncryptedTally {
        context_hash: view.context.hash(),
        sth_root,
        tree_size: view.cutoff_index,
        section_tallies: sections.iter().map(|(s, _, _)| s.record_id()).collect(),
        pool: record_id(&pool.to_value()),
    }
}

/// §19.1: the mix units with their input lists, from every cast ballot of the
/// non-superseded packages, in board order.
pub fn mix_plan(view: &BoardView) -> Vec<(MixUnit, Vec<Row>)> {
    let cast: Vec<CastBallot> = view
        .packages
        .iter()
        .filter(|p| !p.superseded)
        .flat_map(|p| {
            p.cast.iter().map(move |(ballot, judged)| CastBallot {
                region: p.region.as_str(),
                ballot,
                judged,
            })
        })
        .collect();
    plan(view.manifest, &view.registry, &cast)
}

/// What a trustee opens (§20.1).
#[derive(Clone, Debug)]
pub enum Target {
    /// A section tally (§18.1).
    Section(SectionTally),
    /// The pool (§18.2).
    Pool(PoolTally),
    /// The final list of a mix unit (§19.4). `last_output_value` is the signed
    /// `mix_output` of the last step, whose RecordId is the target digest.
    MixFinal {
        unit: MixUnit,
        input: Vec<Row>,
        outputs: Vec<MixOutput>,
        last_output_value: Value,
    },
}

impl Target {
    /// RecordId of the target, as bound into the share proofs (§20.1).
    pub fn digest(&self) -> [u8; 32] {
        match self {
            Target::Section(t) => t.record_id(),
            Target::Pool(t) => record_id(&t.to_value()),
            Target::MixFinal {
                last_output_value, ..
            } => record_id(last_output_value),
        }
    }

    /// The ciphertexts to open, in canonical order (§20.1).
    pub fn items(&self) -> Vec<Ciphertext> {
        match self {
            Target::Section(t) => section_tally_items(t),
            Target::Pool(t) => pool_tally_items(t),
            Target::MixFinal { outputs, .. } => outputs
                .last()
                .map(|o| mix_list_items(&o.output))
                .unwrap_or_default(),
        }
    }
}

/// §20.5: a trustee recomputes the target from the board and signs its share set
/// only if the target is byte-identical to its own recomputation.
///
/// `sections` must be [`section_tallies`] of `view`. The trustee checks that it
/// is, and refuses otherwise. It also checks that `z_j` matches its `Z_j` in the
/// context and that `trustee_sk` is its signing key.
///
/// - `Section`: must equal a recomputed section tally. Pooled contests are not in
///   it, so they are never opened.
/// - `Pool`: must equal [`pool_tally`] of `view`.
/// - `MixFinal`: the input must be the planned input of its unit, the chain must
///   pass [`check_mix_chain`] (which enforces `min_mixers`), and the signed last
///   value must decode to the last step.
pub fn trustee_decrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &BoardView,
    sections: &[(SectionTally, bool, Vec<ContestSum>)],
    target: &Target,
    trustee: u64,
    z_j: &Scalar,
    trustee_sk: &SigningKey,
) -> Result<Value, Error> {
    let refuse = |why: &str| {
        decryption(format!(
            "trustee {trustee} refuses to open the target: {why}"
        ))
    };

    let info = view
        .manifest
        .trustees
        .get(trustee)
        .ok_or_else(|| refuse("not a trustee of this election"))?;
    if trustee_sk.verifying_key() != info.sig_key {
        return Err(refuse("the signing key is not the trustee's"));
    }
    let idx = usize::try_from(trustee.saturating_sub(1)).unwrap_or(usize::MAX);
    match view.context.z.get(idx) {
        Some(z_big) if *z_j * B == *z_big => {}
        _ => return Err(refuse("z_j does not match Z_j in the context")),
    }

    let recomputed = section_tallies(view);
    if sections != recomputed.as_slice() {
        return Err(refuse(
            "the section tallies given differ from those recomputed from the board",
        ));
    }

    match target {
        Target::Section(t) => {
            if !recomputed.iter().any(|(s, _, _)| s == t) {
                return Err(refuse(
                    "the section tally is not the one recomputed from the board",
                ));
            }
        }
        Target::Pool(t) => {
            if *t != pool_tally(view, &recomputed) {
                return Err(refuse("the pool is not the one recomputed from the board"));
            }
        }
        Target::MixFinal {
            unit,
            input,
            outputs,
            last_output_value,
        } => {
            let planned = mix_plan(view);
            match planned.iter().find(|(u, _)| u == unit) {
                Some((_, rows)) if rows == input => {}
                _ => {
                    return Err(refuse(
                        "the input list is not the one planned from the board",
                    ))
                }
            }
            check_mix_chain(view.context, view.manifest, unit, input, outputs)
                .map_err(|e| refuse(&e.to_string()))?;
            let last = outputs
                .last()
                .ok_or_else(|| refuse("the unit has no mix steps"))?;
            let mixer = view
                .manifest
                .trustees
                .get(last.mixer)
                .ok_or_else(|| refuse("the last mixer is not a trustee"))?;
            let decoded = MixOutput::from_signed(last_output_value, &mixer.sig_key)
                .map_err(|e| refuse(&e.to_string()))?;
            if decoded != *last {
                return Err(refuse(
                    "the signed last value differs from the last mix step",
                ));
            }
        }
    }

    let items = target.items();
    if items.is_empty() {
        return Err(refuse("there is nothing to open"));
    }
    let set = DecryptionShareSet::create(
        rng,
        &view.context.hash(),
        &target.digest(),
        trustee,
        z_j,
        &items,
    );
    Ok(set.sign(trustee_sk))
}

/// The share sets among `values` that decode, come from a trustee of the
/// manifest, have a valid trustee signature and (if given) name `target`. Proofs
/// are checked by [`combine`].
fn verified_sets<'v>(
    view: &BoardView,
    values: &'v [Value],
    target: Option<[u8; 32]>,
) -> Vec<(&'v Value, DecryptionShareSet)> {
    values
        .iter()
        .filter_map(|v| {
            let j = v.get(4).ok().flatten()?.as_uint().ok()?;
            let info = view.manifest.trustees.get(j)?;
            let set = DecryptionShareSet::from_signed(v, &info.sig_key).ok()?;
            match target {
                Some(t) if set.target != t => None,
                _ => Some((v, set)),
            }
        })
        .collect()
}

/// Trustee keys in index order, for [`check_final_bu`].
fn trustee_keys(manifest: &Manifest) -> Vec<VerifyingKey> {
    let mut infos: Vec<_> = manifest.trustees.trustees.iter().collect();
    infos.sort_by_key(|t| t.index);
    infos.into_iter().map(|t| t.sig_key).collect()
}

/// §16.5: assembles the final BU of a section from signed share sets. The section
/// must be one that [`section_tallies`] recomputes from `view`. Share sets that
/// fail are dropped, and the `k` lowest valid trustees are kept in the result.
pub fn final_bu(
    view: &BoardView,
    section: &SectionTally,
    share_sets: &[Value],
) -> Result<FinalBu, Error> {
    if !section_tallies(view).iter().any(|(s, _, _)| s == section) {
        return Err(decryption(
            "the section tally is not the one recomputed from the board",
        ));
    }
    let items = section_tally_items(section);
    if items.is_empty() {
        return Err(decryption("the section tally has no contests to open"));
    }
    let verified = verified_sets(view, share_sets, Some(section.record_id()));
    let sets: Vec<DecryptionShareSet> = verified.iter().map(|(_, s)| s.clone()).collect();
    let combined = combine(view.context, view.manifest.trustees.k, &items, &sets)?;
    let results = decode_sums(&section.contests, &combined.plaintext_points)?;
    let used_values: Vec<Value> = verified
        .iter()
        .filter(|(_, s)| combined.used.contains(&s.trustee))
        .map(|(v, _)| (**v).clone())
        .collect();
    Ok(FinalBu {
        context_hash: view.context.hash(),
        pre_bu_id: section.pre_bu_id,
        section_tally_id: section.record_id(),
        results,
        share_sets: used_values,
    })
}

/// Accumulated counts of one contest across sections, the pool and the mix units.
#[derive(Clone, Debug, Default)]
struct Tot {
    counted: u64,
    invalid: u64,
    votes: Vec<u64>,
}

impl Tot {
    fn add(&mut self, counted: u64, invalid: u64, votes: &[u64]) {
        self.counted += counted;
        self.invalid += invalid;
        if self.votes.len() < votes.len() {
            self.votes.resize(votes.len(), 0);
        }
        for (acc, v) in self.votes.iter_mut().zip(votes) {
            *acc += v;
        }
    }
}

/// Manifest contests in ascending index order.
fn contests_sorted(manifest: &Manifest) -> Vec<&Contest> {
    let mut contests: Vec<&Contest> = manifest.contests.iter().collect();
    contests.sort_by_key(|c| c.index);
    contests
}

/// Everything the trustees and the mixnet produced, for [`election_result`].
#[derive(Clone, Debug)]
pub struct TallyInputs {
    /// Final BUs of the sections, with the RecordId of each.
    pub final_bus: Vec<(FinalBu, [u8; 32])>,
    /// Signed share sets of the pool.
    pub pool_share_sets: Vec<Value>,
    /// Per mix unit that has rows: its steps and the signed share sets of the
    /// final list.
    pub mix: Vec<(MixUnit, Vec<MixOutput>, Vec<Value>)>,
}

/// §21: the election result. Homomorphic votes are the final BUs plus the decoded
/// pool. Mixnet contests are decrypted per unit and counted (§19.6). Ballots
/// excluded under §12.6 are counted per contest and per section. Proportional
/// contests get party totals and seats (§22).
///
/// `sections` and `pool` must be those [`section_tallies`] and [`pool_tally`]
/// give for `view`, and they are checked against it.
pub fn election_result(
    view: &BoardView,
    sections: &[(SectionTally, bool, Vec<ContestSum>)],
    pool: &PoolTally,
    inputs: &TallyInputs,
) -> Result<ElectionResult, Error> {
    let recomputed = section_tallies(view);
    if sections != recomputed.as_slice() {
        return Err(tally("the section tallies do not match the board"));
    }
    if *pool != pool_tally(view, sections) {
        return Err(tally("the pool does not match the board"));
    }
    let manifest = view.manifest;
    let context = view.context;
    let k = manifest.trustees.k;
    let keys = trustee_keys(manifest);

    let mut excluded: BTreeMap<u64, u64> = BTreeMap::new();
    for p in &view.packages {
        add_counts(&mut excluded, &exclusions(p));
    }

    let mut hom: BTreeMap<u64, Tot> = BTreeMap::new();
    let mut section_results = Vec::new();
    for (st, matches, _) in sections {
        let (contests, final_bu_id) = if section_tally_items(st).is_empty() {
            (Vec::new(), NO_FINAL_BU)
        } else {
            let (fb, id) = inputs
                .final_bus
                .iter()
                .find(|(fb, _)| fb.section_tally_id == st.record_id())
                .ok_or_else(|| tally(format!("no final BU for section {:?}", st.section_id)))?;
            if record_id(&fb.to_value()) != *id {
                return Err(tally("a final BU id does not match its record"));
            }
            check_final_bu(fb, st, context, k, &keys)?;
            (fb.results.clone(), *id)
        };
        for (c, n, votes) in &contests {
            hom.entry(*c).or_default().add(*n, 0, votes);
        }
        let mut section_excluded: BTreeMap<u64, u64> = BTreeMap::new();
        for p in view.packages.iter().filter(|p| st.packages.contains(&p.id)) {
            add_counts(&mut section_excluded, &exclusions(p));
        }
        section_results.push(SectionResult {
            section_id: st.section_id.clone(),
            pre_bu_id: st.pre_bu_id,
            final_bu_id,
            contests,
            excluded: section_excluded.into_iter().collect(),
            matches: *matches,
        });
    }

    // Pool: decode the contests with counted ballots, zero for the rest.
    let pool_id = record_id(&pool.to_value());
    let nonzero: Vec<ContestSum> = pool
        .contests
        .iter()
        .filter(|s| s.counted > 0)
        .cloned()
        .collect();
    let decoded = if pool_tally_items(pool).is_empty() {
        Vec::new()
    } else {
        let sets: Vec<DecryptionShareSet> =
            verified_sets(view, &inputs.pool_share_sets, Some(pool_id))
                .into_iter()
                .map(|(_, s)| s)
                .collect();
        let combined = combine(context, k, &pool_tally_items(pool), &sets)?;
        decode_sums(&nonzero, &combined.plaintext_points)?
    };
    let mut pool_rows = Vec::new();
    for s in &pool.contests {
        let (n, votes) = match decoded.iter().find(|(c, _, _)| *c == s.contest) {
            Some((_, n, votes)) => (*n, votes.clone()),
            None => (0, vec![0; s.sums.len()]),
        };
        hom.entry(s.contest).or_default().add(n, 0, &votes);
        pool_rows.push((s.contest, n, votes));
    }

    // Mixnet units.
    let planned = mix_plan(view);
    for (u, _, _) in &inputs.mix {
        if !planned.iter().any(|(p, _)| p == u) {
            return Err(tally("mix steps for a unit that is not planned"));
        }
    }
    let mut mixed: BTreeMap<u64, Tot> = BTreeMap::new();
    for (unit, rows) in &planned {
        let unit_contests: Vec<&Contest> = unit
            .contests
            .iter()
            .map(|&c| {
                manifest
                    .contest(c)
                    .ok_or_else(|| tally(format!("mix unit names unknown contest {c}")))
            })
            .collect::<Result<_, _>>()?;
        let decoded_rows: Vec<Vec<Option<u64>>> = if rows.is_empty() {
            Vec::new()
        } else {
            let (_, outputs, sets_v) =
                inputs
                    .mix
                    .iter()
                    .find(|(u, _, _)| u == unit)
                    .ok_or_else(|| {
                        tally(format!(
                            "mix unit {} has no mix steps",
                            unit.contest_index()
                        ))
                    })?;
            let final_list = check_mix_chain(context, manifest, unit, rows, outputs)?;
            let items = mix_list_items(&final_list);
            let sets: Vec<DecryptionShareSet> = verified_sets(view, sets_v, None)
                .into_iter()
                .map(|(_, s)| s)
                .collect();
            let combined = combine(context, k, &items, &sets)?;
            let slot_options: Vec<usize> = unit_contests
                .iter()
                .flat_map(|c| vec![c.options.len(); c.limit as usize])
                .collect();
            let width = slot_options.len();
            if width == 0 {
                return Err(tally("mix unit has no slots"));
            }
            combined
                .plaintext_points
                .chunks(width)
                .map(|row| {
                    row.iter()
                        .zip(&slot_options)
                        .map(|(p, &n)| decode_slot(p, n))
                        .collect()
                })
                .collect()
        };
        for m in count_mix_rows(&unit_contests, &decoded_rows) {
            mixed
                .entry(m.contest)
                .or_default()
                .add(m.counted, m.invalid, &m.votes);
        }
    }

    let mut contests = Vec::new();
    for c in contests_sorted(manifest) {
        let empty = || Tot {
            votes: vec![0; c.options.len()],
            ..Tot::default()
        };
        let t = match c.method {
            Method::Homomorphic => hom.get(&c.index).cloned().unwrap_or_else(empty),
            Method::Mixnet => mixed.get(&c.index).cloned().unwrap_or_else(empty),
        };
        let (totals, seats) = if c.kind == ContestKind::Proportional {
            (
                Some(party_totals(manifest, c, &t.votes)?),
                Some(apportion(manifest, c, &t.votes)?),
            )
        } else {
            (None, None)
        };
        contests.push(ContestResult {
            contest: c.index,
            votes: t.votes,
            counted: t.counted,
            invalid: t.invalid,
            excluded: excluded.get(&c.index).copied().unwrap_or(0),
            party_totals: totals,
            seats,
        });
    }

    Ok(ElectionResult {
        context_hash: context.hash(),
        tree_size: view.cutoff_index,
        contests,
        sections: section_results,
        pool: pool_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{ContestBallot, ContestPlain};
    use crate::board::{PollsOpen, TallyCutoff};
    use crate::chain::Measurement;
    use crate::dkg::{joint_public_key, verification_key, Polynomial};
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::group::RistrettoPoint;
    use crate::journal::{auth_signature, SectionSig};
    use crate::machine::{MachineConfig, Session};
    use crate::manifest::sign_manifest;
    use crate::mixnet::run_mix_chain;
    use crate::registry::sign_registry;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const APPROVED: Measurement = Measurement([0xaa; 32]);
    const OPENED_AT: u64 = 1_700_000_000;
    const CHALLENGE: [u8; 16] = [5; 16];
    const TRUSTEES: [u64; 2] = [1, 2];

    /// The election: manifest with the given `min_section_ballots`, registry,
    /// context from three trustees (k = 2) and their secret shares z_j.
    struct World {
        manifest: Manifest,
        keys: Keys,
        registry: Registry,
        context: Context,
        zs: Vec<Scalar>,
    }

    fn world(min_section_ballots: u64) -> World {
        let (mut manifest, keys) = sample_manifest(1);
        manifest.min_section_ballots = min_section_ballots;
        let registry = sample_registry(&manifest, &keys);
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let polys: Vec<Polynomial> = (0..3).map(|_| Polynomial::random(&mut rng, 2)).collect();
        let all: Vec<Vec<RistrettoPoint>> = polys.iter().map(Polynomial::commitments).collect();
        let k = joint_public_key(&all).expect("K");
        let zs: Vec<Scalar> = (1..=3u64)
            .map(|j| polys.iter().fold(Scalar::ZERO, |acc, p| acc + p.eval(j)))
            .collect();
        let z = (1..=3u64).map(|j| verification_key(&all, j)).collect();
        let context = Context {
            manifest_hash: manifest.hash(),
            transcript_hash: [2; 32],
            k,
            z,
        };
        World {
            manifest,
            keys,
            registry,
            context,
            zs,
        }
    }

    /// One voter: the choices of all six contests, and whether the voter first
    /// spoils a ballot under the same authorization.
    struct Voter {
        choices: Vec<ContestPlain>,
        spoil_first: bool,
    }

    /// Choices for the six contests of the sample manifest, by row.
    fn picks(row: usize) -> Vec<ContestPlain> {
        let rows: [[Vec<u64>; 6]; 3] = [
            [vec![1], vec![1], vec![4], vec![1], vec![0], vec![2]],
            [vec![1], vec![0, 3], vec![4], vec![1], vec![0], vec![1]],
            [vec![0], vec![], vec![0], vec![1], vec![1], vec![2]],
        ];
        rows[row]
            .iter()
            .enumerate()
            .map(|(c, sel)| ContestPlain {
                contest: c as u64,
                selected: sel.clone(),
            })
            .collect()
    }

    fn voter(row: usize, spoil_first: bool) -> Voter {
        Voter {
            choices: picks(row),
            spoil_first,
        }
    }

    /// Runs one voting session and returns its signed package. `k` is the key the
    /// machine encrypts under, which is the election key unless a test breaks it.
    fn session(
        w: &World,
        rng: &mut ChaCha20Rng,
        machine_idx: usize,
        pw_idx: usize,
        (section, session_id): (&str, &str),
        k: RistrettoPoint,
        voters: &[Voter],
    ) -> Value {
        let machine_id = w.registry.machines[machine_idx].machine_id.clone();
        let pw = &w.keys.poll_workers[pw_idx];
        let ctx_hash = w.context.hash();
        let cfg = MachineConfig {
            election: Election {
                context_hash: ctx_hash,
                k,
                manifest: &w.manifest,
            },
            registry: &w.registry,
            machine_id: machine_id.clone(),
            machine_sk: w.keys.machines[machine_idx].clone(),
            measurement: APPROVED,
        };
        let (mut s, zeresima) =
            Session::open(cfg, section, session_id, OPENED_AT, CHALLENGE).expect("open");
        s.sign_zeresima(vec![SectionSig::create(pw, &zeresima)])
            .expect("zeresima");
        for v in voters {
            let seq = s.next_auth_seq();
            let sig = auth_signature(pw, &ctx_hash, &machine_id, session_id, seq);
            s.authorize(pw.verifying_key(), sig).expect("authorize");
            if v.spoil_first {
                s.encrypt(rng, v.choices.clone()).expect("encrypt");
                s.spoil().expect("spoil");
            }
            s.encrypt(rng, v.choices.clone()).expect("encrypt");
            s.cast().expect("cast");
        }
        let pb = s
            .prepare_pre_bu(voters.len() as u64)
            .expect("prepare pre-bu");
        s.sign_pre_bu(vec![SectionSig::create(pw, &pb)])
            .expect("sign pre-bu");
        s.close(OPENED_AT + 100).expect("close")
    }

    /// The board: manifest, registry, polls open, the packages, tally cutoff.
    fn board(w: &World, packages: Vec<Value>) -> Vec<Value> {
        let reg = sign_registry(&w.registry, &w.keys.ea);
        let polls = PollsOpen {
            context_hash: w.context.hash(),
            registry_id: record_id(&reg),
            time: 1,
        }
        .sign(&w.keys.ea);
        let mut entries = vec![sign_manifest(&w.manifest, &w.keys.ea), reg, polls];
        entries.extend(packages);
        entries.push(
            TallyCutoff {
                context_hash: w.context.hash(),
                time: 2,
            }
            .sign(&w.keys.ea),
        );
        entries
    }

    /// Plaintext counts per contest index and option, from the honest voters.
    fn expected_votes(w: &World, voters: &[&Voter]) -> Vec<Vec<u64>> {
        let mut out: Vec<Vec<u64>> = contests_sorted(&w.manifest)
            .iter()
            .map(|c| vec![0; c.options.len()])
            .collect();
        for v in voters {
            for cp in &v.choices {
                for &sel in &cp.selected {
                    out[cp.contest as usize][sel as usize] += 1;
                }
            }
        }
        out
    }

    /// Trustees 1 and 2 sign share sets for `target`.
    fn shares(
        w: &World,
        rng: &mut ChaCha20Rng,
        view: &BoardView,
        sections: &[(SectionTally, bool, Vec<ContestSum>)],
        target: &Target,
    ) -> Vec<Value> {
        TRUSTEES
            .iter()
            .map(|&j| {
                trustee_decrypt(
                    rng,
                    view,
                    sections,
                    target,
                    j,
                    &w.zs[(j - 1) as usize],
                    &w.keys.trustee_sig[(j - 1) as usize],
                )
                .expect("trustee shares")
            })
            .collect()
    }

    /// Trustees open every section with items, the pool, and every mix unit with
    /// rows. Returns the inputs of `election_result`.
    fn decrypt_all(
        w: &World,
        rng: &mut ChaCha20Rng,
        view: &BoardView,
        sections: &[(SectionTally, bool, Vec<ContestSum>)],
        pool: &PoolTally,
    ) -> TallyInputs {
        let mut final_bus = Vec::new();
        for (st, _, _) in sections {
            if section_tally_items(st).is_empty() {
                continue;
            }
            let sets = shares(w, rng, view, sections, &Target::Section(st.clone()));
            let fb = final_bu(view, st, &sets).expect("final BU");
            check_final_bu(&fb, st, &w.context, 2, &trustee_keys(&w.manifest))
                .expect("final BU checks");
            let id = record_id(&fb.to_value());
            final_bus.push((fb, id));
        }

        let pool_target = Target::Pool(pool.clone());
        let pool_share_sets = if pool_target.items().is_empty() {
            Vec::new()
        } else {
            shares(w, rng, view, sections, &pool_target)
        };

        let mut mix = Vec::new();
        for (unit, rows) in mix_plan(view) {
            if rows.is_empty() {
                continue;
            }
            let mixers: Vec<(u64, &SigningKey)> = TRUSTEES
                .iter()
                .map(|&j| (j, &w.keys.trustee_sig[(j - 1) as usize]))
                .collect();
            let chain = run_mix_chain(rng, &w.context, &unit, &rows, &mixers);
            let outputs: Vec<MixOutput> = chain.iter().map(|(_, mo)| mo.clone()).collect();
            let target = Target::MixFinal {
                unit: unit.clone(),
                input: rows,
                outputs: outputs.clone(),
                last_output_value: chain.last().expect("a mix step").0.clone(),
            };
            let sets = shares(w, rng, view, sections, &target);
            mix.push((unit, outputs, sets));
        }

        TallyInputs {
            final_bus,
            pool_share_sets,
            mix,
        }
    }

    /// Asserts that every contest matches the plaintext counts of `honest`.
    /// Asserts that every contest's votes and counted ballots match the plaintext
    /// counts of `honest`, with the expected `(invalid, excluded)` per contest.
    fn assert_counts(
        w: &World,
        result: &ElectionResult,
        honest: &[&Voter],
        expect: impl Fn(u64) -> (u64, u64),
    ) {
        let expected = expected_votes(w, honest);
        assert_eq!(result.contests.len(), w.manifest.contests.len());
        for cr in &result.contests {
            assert_eq!(
                cr.votes, expected[cr.contest as usize],
                "contest {}",
                cr.contest
            );
            assert_eq!(
                cr.counted,
                honest.len() as u64,
                "contest {} counted",
                cr.contest
            );
            let (invalid, excluded) = expect(cr.contest);
            assert_eq!(cr.invalid, invalid, "contest {} invalid", cr.contest);
            assert_eq!(cr.excluded, excluded, "contest {} excluded", cr.contest);
        }
    }

    #[test]
    fn end_to_end_election_matches_the_cast_choices() {
        let w = world(1);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let s1 = [voter(0, true), voter(1, false), voter(2, false)];
        let s2 = [voter(1, false), voter(2, false), voter(0, false)];
        let pkg1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), w.context.k, &s1);
        let pkg2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), w.context.k, &s2);
        let entries = board(&w, vec![pkg1, pkg2]);

        let view = board_view(&w.manifest, &w.context, &entries).expect("view");
        assert_eq!(view.packages.len(), 2);
        assert!(view.rejected.is_empty());
        assert_eq!(view.cutoff_index, entries.len() as u64 - 1);

        let sections = section_tallies(&view);
        assert_eq!(sections.len(), 2);
        assert!(sections.iter().all(|(_, matches, _)| *matches));

        let pool = pool_tally(&view, &sections);
        assert!(pool.contests.iter().all(|c| c.counted == 0));
        let index = encrypted_tally(&view, &sections, &pool, [4; 32]);
        assert_eq!(index.section_tallies.len(), 2);

        let plan = mix_plan(&view);
        assert_eq!(plan.len(), 2, "contest 3 is regional: one unit per region");
        assert!(plan.iter().all(|(_, rows)| rows.len() == 3));

        let inputs = decrypt_all(&w, &mut rng, &view, &sections, &pool);
        let result = election_result(&view, &sections, &pool, &inputs).expect("result");
        let honest: Vec<&Voter> = s1.iter().chain(&s2).collect();
        assert_counts(&w, &result, &honest, |_| (0, 0));

        // Proportional contest: party totals and seats are present.
        let prop = &result.contests[2];
        assert_eq!(prop.contest, 2);
        assert!(prop.party_totals.is_some());
        assert!(prop.seats.is_some());
        // The spoiled ballot was not counted.
        assert_eq!(prop.counted, 6);

        assert_eq!(result.sections.len(), 2);
        assert!(result.sections.iter().all(|s| s.matches));
        assert!(result.pool.iter().all(|(_, n, _)| *n == 0));
    }

    #[test]
    fn pooled_election_counts_through_the_pool() {
        let w = world(100);
        let mut rng = ChaCha20Rng::from_seed([10; 32]);
        let s1 = [voter(0, false), voter(1, false), voter(2, false)];
        let s2 = [voter(1, false), voter(2, false), voter(0, false)];
        let pkg1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), w.context.k, &s1);
        let pkg2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), w.context.k, &s2);
        let entries = board(&w, vec![pkg1, pkg2]);

        let view = board_view(&w.manifest, &w.context, &entries).expect("view");
        let sections = section_tallies(&view);
        assert!(sections
            .iter()
            .all(|(st, matches, _)| *matches && st.contests.is_empty()));
        let pool = pool_tally(&view, &sections);
        assert!(pool.contests.iter().all(|c| c.counted == 6));

        let inputs = decrypt_all(&w, &mut rng, &view, &sections, &pool);
        assert!(
            inputs.final_bus.is_empty(),
            "nothing is left in the sections"
        );
        let result = election_result(&view, &sections, &pool, &inputs).expect("result");
        let honest: Vec<&Voter> = s1.iter().chain(&s2).collect();
        assert_counts(&w, &result, &honest, |_| (0, 0));
        assert!(result.sections.iter().all(|s| s.contests.is_empty()));
    }

    #[test]
    fn doctored_section_tally_is_refused() {
        let w = world(1);
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        let s1 = [voter(0, false), voter(1, false), voter(2, false)];
        let pkg1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), w.context.k, &s1);
        let entries = board(&w, vec![pkg1]);
        let view = board_view(&w.manifest, &w.context, &entries).expect("view");
        let sections = section_tallies(&view);
        let honest = Target::Section(sections[0].0.clone());
        let mut trustee = |target: &Target| {
            trustee_decrypt(
                &mut rng,
                &view,
                &sections,
                target,
                1,
                &w.zs[0],
                &w.keys.trustee_sig[0],
            )
        };
        assert!(trustee(&honest).is_ok());

        // Swap one section sum for an individual ballot's selection.
        let ballot_ct = view.packages[0]
            .cast
            .iter()
            .find_map(|(b, _)| {
                b.contests.iter().find_map(|cb| match cb {
                    ContestBallot::Hom {
                        contest: 0,
                        selections,
                        ..
                    } => Some(selections[0].0),
                    _ => None,
                })
            })
            .expect("a ballot selection");
        let mut doctored = sections[0].0.clone();
        doctored.contests[0].sums[0] = ballot_ct;
        assert!(trustee(&Target::Section(doctored)).is_err());

        // A pool that is not the recomputed one is refused as well.
        let mut pool = pool_tally(&view, &sections);
        pool.tree_size += 1;
        assert!(trustee(&Target::Pool(pool)).is_err());
    }

    #[test]
    fn broken_proof_ballot_is_excluded_and_its_section_mismatches() {
        let w = world(1);
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let s1 = [voter(0, false), voter(1, false)];
        let s2 = [voter(2, false)];
        // A second session on S2's machine, encrypted under a key that is not the
        // election key: every proof of its one ballot fails.
        let wrong_k = Scalar::from(7u64) * B;
        let pkg1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), w.context.k, &s1);
        let pkg2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), w.context.k, &s2);
        let broken = [voter(0, false)];
        let pkg3 = session(&w, &mut rng, 1, 2, ("S2", "S-2b"), wrong_k, &broken);
        let entries = board(&w, vec![pkg1, pkg2, pkg3]);

        let view = board_view(&w.manifest, &w.context, &entries).expect("view");
        let sections = section_tallies(&view);
        assert_eq!(sections.len(), 3);
        assert!(sections[0].1 && sections[1].1);
        assert!(
            !sections[2].1,
            "the machine counted a ballot the board rejects"
        );

        let pool = pool_tally(&view, &sections);
        let inputs = decrypt_all(&w, &mut rng, &view, &sections, &pool);
        let result = election_result(&view, &sections, &pool, &inputs).expect("result");
        let honest: Vec<&Voter> = s1.iter().chain(&s2).collect();
        // The wrong-key ballot is excluded in every homomorphic contest. In the
        // mixnet contest 3 its slot proofs (over alpha) still pass, so it is
        // counted and its row decodes as invalid (§19.6).
        assert_counts(
            &w,
            &result,
            &honest,
            |c| if c == 3 { (1, 0) } else { (0, 1) },
        );
        assert_eq!(
            result
                .sections
                .iter()
                .map(|s| s.matches)
                .collect::<Vec<_>>(),
            vec![true, true, false]
        );
    }
}
