//! Steps 9 to 12 of §23: homomorphic tally, mixnet, decryption and final BUs.

use std::collections::BTreeMap;

use eg_core::authority::{
    encrypted_tally, mix_plan, pool_tally, section_tallies, BoardView, ViewPackage,
};
use eg_core::board::{record_id, Log};
use eg_core::cbor::{self, Value};
use eg_core::ceremony::Context;
use eg_core::decrypt::{
    check_final_bu, combine, mix_list_items, pool_tally_items, section_tally_items,
    DecryptionShareSet, FinalBu,
};
use eg_core::elgamal::Ciphertext;
use eg_core::manifest::Manifest;
use eg_core::mixnet::{check_mix_chain, MixUnit};
use eg_core::shuffle::{MixOutput, Row};
use eg_core::sign::VerifyingKey;
use eg_core::tally::{ContestSum, EncryptedTally, PoolTally, SectionTally};

use crate::{fail, tag, text_at, uint_at, warn, Report};

/// The homomorphic side of the tally, recomputed from the board (§18).
pub(crate) struct Homo {
    /// One section tally per pre-BU, with its fingerprint check and pooled sums.
    pub sections: Vec<(SectionTally, bool, Vec<ContestSum>)>,
    pub pool: PoolTally,
}

/// §23 step 9: recomputes every section tally, the pool and the encrypted tally at
/// the cutoff, and compares them byte for byte with the published ones. Each
/// pre-BU's fingerprint (field 14) is compared with the recomputed subtotal.
pub(crate) fn step9_homomorphic(
    view: &BoardView,
    entries: &[Value],
    log: &Log,
    manifest: &Manifest,
    rep: &mut Report,
) -> Homo {
    let sections = section_tallies(view);
    // `section_tallies` yields one entry per package that carries a pre-BU, in order.
    let pre_bu_packages: Vec<&ViewPackage> = view
        .packages
        .iter()
        .filter(|p| p.pre_bu.is_some())
        .collect();
    for ((_, matches, _), p) in sections.iter().zip(&pre_bu_packages) {
        if !matches {
            fail(
                rep,
                9,
                Some(p.entry_index),
                "§18.1",
                format!(
                    "machine {} session {}: the pre-BU's fingerprint (field 14) mismatches the recomputed subtotal",
                    p.machine_id, p.session_id
                ),
            );
        }
    }

    let pool = pool_tally(view, &sections);
    let root = log.root_at(view.cutoff_index);
    let encrypted = encrypted_tally(view, &sections, &pool, root);

    let mut published_sections = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let entry = Some(i as u64);
        match tag(e) {
            Some("section_tally") => match SectionTally::from_value(e) {
                Err(err) => fail(
                    rep,
                    9,
                    entry,
                    "§18.1",
                    format!("section tally does not decode: {err}"),
                ),
                Ok(published) => match sections
                    .iter()
                    .find(|(s, _, _)| s.pre_bu_id == published.pre_bu_id)
                {
                    None => fail(
                        rep,
                        9,
                        entry,
                        "§18.1",
                        "section tally names a pre-BU that is not in an accepted package",
                    ),
                    Some((s, _, _)) => {
                        published_sections += 1;
                        if cbor::encode(e) != cbor::encode(&s.to_value()) {
                            fail(
                                rep,
                                9,
                                entry,
                                "§18.1",
                                format!(
                                    "section tally of section {} differs from the recomputed one",
                                    s.section_id
                                ),
                            );
                        }
                    }
                },
            },
            Some("pool_tally") => match PoolTally::from_value(e) {
                Err(err) => fail(
                    rep,
                    9,
                    entry,
                    "§18.2",
                    format!("pool tally does not decode: {err}"),
                ),
                Ok(_) => {
                    if cbor::encode(e) != cbor::encode(&pool.to_value()) {
                        fail(
                            rep,
                            9,
                            entry,
                            "§18.2",
                            "pool tally differs from the recomputed one",
                        );
                    }
                }
            },
            Some("encrypted_tally") => match EncryptedTally::from_value(e) {
                Err(err) => fail(
                    rep,
                    9,
                    entry,
                    "§18.3",
                    format!("encrypted tally does not decode: {err}"),
                ),
                Ok(_) => {
                    if cbor::encode(e) != cbor::encode(&encrypted.to_value()) {
                        fail(
                            rep,
                            9,
                            entry,
                            "§18.3",
                            "encrypted tally differs from the recomputed one",
                        );
                    }
                }
            },
            _ => {}
        }
    }
    if published_sections < sections.len() {
        warn(
            rep,
            9,
            None,
            "§18.1",
            format!(
                "{} of {} section tallies are not published",
                sections.len() - published_sections,
                sections.len()
            ),
        );
    }
    let published_pool = entries.iter().any(|e| tag(e) == Some("pool_tally"));
    if !published_pool {
        warn(rep, 9, None, "§18.2", "no pool tally is published");
    }
    if !entries.iter().any(|e| tag(e) == Some("encrypted_tally")) {
        warn(rep, 9, None, "§18.3", "no encrypted tally is published");
    }

    for c in &pool.contests {
        if c.counted > 0 && c.counted < manifest.min_section_ballots {
            warn(
                rep,
                9,
                None,
                "§18.3",
                format!(
                    "the pool holds {} ballots in contest {}, fewer than min_section_ballots = {}",
                    c.counted, c.contest, manifest.min_section_ballots
                ),
            );
        }
    }
    Homo { sections, pool }
}

/// One mix unit as it appears on the board after step 10.
pub(crate) struct MixState {
    pub unit: MixUnit,
    /// The unit's input list E^(0) (§19.1).
    pub rows: Vec<Row>,
    /// The verified mix steps, in step order.
    pub outputs: Vec<MixOutput>,
    /// The final list, which the trustees open (§19.4).
    pub final_list: Vec<Row>,
    /// RecordId of the last `mix_output` entry: the digest share sets name (spec
    /// issue 23).
    pub last_digest: Option<[u8; 32]>,
}

/// §23 step 10: each mix unit's chain is checked (§19.2): every step is signed by
/// a trustee, the steps are in order, each input is the previous output, every
/// shuffle proof verifies, and at least `min_mixers` trustees mixed.
pub(crate) fn step10_mixnet(
    view: &BoardView,
    entries: &[Value],
    manifest: &Manifest,
    context: &Context,
    rep: &mut Report,
) -> Vec<MixState> {
    let planned = mix_plan(view);
    let mut steps: Vec<Vec<(u64, [u8; 32], MixOutput)>> = vec![Vec::new(); planned.len()];
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("mix_output") {
            continue;
        }
        let entry = Some(i as u64);
        let (Some(contest), Some(mixer)) = (uint_at(e, 3), uint_at(e, 4)) else {
            fail(
                rep,
                10,
                entry,
                "§19.2",
                "mix_output has no contest or mixer",
            );
            continue;
        };
        let region = text_at(e, 9).unwrap_or("");
        let Some(unit) = planned
            .iter()
            .position(|(u, _)| u.contest_index() == contest && u.region == region)
        else {
            fail(
                rep,
                10,
                entry,
                "§19.2",
                "mix_output for a unit the board does not plan",
            );
            continue;
        };
        let Some(trustee) = manifest.trustees.get(mixer) else {
            fail(
                rep,
                10,
                entry,
                "§19.2",
                "mix_output signed for a key that is not a trustee",
            );
            continue;
        };
        match MixOutput::from_signed(e, &trustee.sig_key) {
            Ok(mo) => steps[unit].push((mo.step, record_id(e), mo)),
            Err(err) => fail(
                rep,
                10,
                entry,
                "§19.2",
                format!("mix_output does not verify: {err}"),
            ),
        }
    }

    let mut states = Vec::new();
    for ((unit, rows), mut outs) in planned.into_iter().zip(steps) {
        outs.sort_by_key(|o| o.0);
        let outputs: Vec<MixOutput> = outs.iter().map(|(_, _, m)| m.clone()).collect();
        let last_digest = outs.last().map(|(_, d, _)| *d);
        match check_mix_chain(context, manifest, &unit, &rows, &outputs) {
            Ok(final_list) => states.push(MixState {
                unit,
                rows,
                outputs,
                final_list,
                last_digest,
            }),
            Err(err) => fail(
                rep,
                10,
                None,
                "§19.2, §19.3",
                format!(
                    "mix unit of contest {} region {:?}: {err}",
                    unit.contest_index(),
                    unit.region
                ),
            ),
        }
    }
    states
}

/// Share sets whose signature verifies, keyed by the RecordId they name.
pub(crate) type VerifiedSets = BTreeMap<[u8; 32], Vec<Value>>;

/// One thing the trustees open (§20.1).
struct Target {
    label: String,
    digest: [u8; 32],
    items: Vec<Ciphertext>,
}

/// §23 step 11: every `decryption_shares` entry is checked against its target
/// (§20.1). A set that fails its signature, names no target, or fails its proofs
/// is reported with its trustee and discarded. Decryption continues from the
/// valid sets (§20.2, §20.3). Returns the signed sets that verify, for step 13.
pub(crate) fn step11_decryption(
    entries: &[Value],
    homo: &Homo,
    mix: &[MixState],
    manifest: &Manifest,
    context: &Context,
    rep: &mut Report,
) -> VerifiedSets {
    let k = manifest.trustees.k;
    let mut targets: Vec<Target> = Vec::new();
    for (st, _, _) in &homo.sections {
        let items = section_tally_items(st);
        if !items.is_empty() {
            targets.push(Target {
                label: format!("section tally of {}", st.section_id),
                digest: st.record_id(),
                items,
            });
        }
    }
    let pool_items = pool_tally_items(&homo.pool);
    if !pool_items.is_empty() {
        targets.push(Target {
            label: "pool tally".to_owned(),
            digest: record_id(&homo.pool.to_value()),
            items: pool_items,
        });
    }
    for m in mix {
        if let Some(digest) = m.last_digest {
            let items = mix_list_items(&m.final_list);
            if !items.is_empty() {
                targets.push(Target {
                    label: format!(
                        "mix unit of contest {} region {:?}",
                        m.unit.contest_index(),
                        m.unit.region
                    ),
                    digest,
                    items,
                });
            }
        }
    }

    let mut decoded: Vec<(usize, DecryptionShareSet, &Value)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("decryption_shares") {
            continue;
        }
        let entry = Some(i as u64);
        let Some(j) = uint_at(e, 4) else {
            fail(rep, 11, entry, "§20.1", "share set has no trustee index");
            continue;
        };
        let Some(trustee) = manifest.trustees.get(j) else {
            fail(
                rep,
                11,
                entry,
                "§20.1",
                format!("share set of trustee {j}, who is not in the manifest"),
            );
            continue;
        };
        match DecryptionShareSet::from_signed(e, &trustee.sig_key) {
            Ok(set) => decoded.push((i, set, e)),
            Err(err) => fail(
                rep,
                11,
                entry,
                "§20.1, §20.3",
                format!("share set of trustee {j} does not verify and is discarded: {err}"),
            ),
        }
    }

    let mut verified: VerifiedSets = BTreeMap::new();
    for (i, set, e) in &decoded {
        if targets.iter().any(|t| t.digest == set.target) {
            verified.entry(set.target).or_default().push((*e).clone());
        } else {
            fail(
                rep,
                11,
                Some(*i as u64),
                "§20.1",
                format!(
                    "share set of trustee {} names no target on the board",
                    set.trustee
                ),
            );
        }
    }

    for t in &targets {
        let sets: Vec<&(usize, DecryptionShareSet, &Value)> = decoded
            .iter()
            .filter(|(_, s, _)| s.target == t.digest)
            .collect();
        let owned: Vec<DecryptionShareSet> = sets.iter().map(|(_, s, _)| s.clone()).collect();
        match combine(context, k, &t.items, &owned) {
            Err(err) => fail(rep, 11, None, "§20.2", format!("{}: {err}", t.label)),
            Ok(combined) => {
                for (trustee, reason) in combined.rejected {
                    let entry = sets
                        .iter()
                        .find(|(_, s, _)| s.trustee == trustee)
                        .map(|(i, _, _)| *i as u64);
                    fail(
                        rep,
                        11,
                        entry,
                        "§20.3",
                        format!(
                            "{}: share set of trustee {trustee} discarded: {reason}",
                            t.label
                        ),
                    );
                }
            }
        }
    }
    verified
}

/// §23 step 12: every `final_bu` is checked against its section tally and
/// pre-BU (§16.5). Each section with contests to open needs one. Returns the final
/// BUs with their RecordIds.
pub(crate) fn step12_final_bus(
    entries: &[Value],
    homo: &Homo,
    manifest: &Manifest,
    context: &Context,
    rep: &mut Report,
) -> Vec<(FinalBu, [u8; 32])> {
    let k = manifest.trustees.k;
    let mut trustees: Vec<_> = manifest.trustees.trustees.iter().collect();
    trustees.sort_by_key(|t| t.index);
    let keys: Vec<VerifyingKey> = trustees.iter().map(|t| t.sig_key).collect();

    let mut out: Vec<(FinalBu, [u8; 32])> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("final_bu") {
            continue;
        }
        let entry = Some(i as u64);
        let fb = match FinalBu::from_value(e) {
            Ok(fb) => fb,
            Err(err) => {
                fail(
                    rep,
                    12,
                    entry,
                    "§16.5",
                    format!("final BU does not decode: {err}"),
                );
                continue;
            }
        };
        let Some((st, _, _)) = homo
            .sections
            .iter()
            .find(|(s, _, _)| s.record_id() == fb.section_tally_id)
        else {
            fail(
                rep,
                12,
                entry,
                "§16.5",
                "final BU names no section tally of the board",
            );
            continue;
        };
        if let Err(err) = check_final_bu(&fb, st, context, k, &keys) {
            fail(
                rep,
                12,
                entry,
                "§16.5, §20.3",
                format!(
                    "final BU of section {} does not check: {err}",
                    st.section_id
                ),
            );
            continue;
        }
        if out
            .iter()
            .any(|(f, _)| f.section_tally_id == fb.section_tally_id)
        {
            fail(
                rep,
                12,
                entry,
                "§16.5",
                format!("a second final BU for section {}", st.section_id),
            );
            continue;
        }
        let id = record_id(&fb.to_value());
        out.push((fb, id));
    }

    for (st, _, _) in &homo.sections {
        let needs = !section_tally_items(st).is_empty();
        if needs
            && !out
                .iter()
                .any(|(f, _)| f.section_tally_id == st.record_id())
        {
            fail(
                rep,
                12,
                None,
                "§16.5",
                format!(
                    "section {} has contests to open but no final BU",
                    st.section_id
                ),
            );
        }
    }
    out
}
