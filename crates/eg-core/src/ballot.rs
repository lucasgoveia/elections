//! Ballots (SPEC.md §12): encryption, structure, validity and reveal checks.
//!
//! A ballot is encrypted from the voter's choices and a fresh seed ρ. Every
//! encryption nonce is derived from ρ (§12.2), so a spoiled ballot can be
//! re-encrypted from its revealed choices and ρ (§14.2). Proof randomness comes
//! only from the caller's RNG.
//!
//! The encoding of each contest (choices to plaintexts, §12.3 and §12.4) lives
//! in one private function, [`plaintexts`], which both encryption and the reveal
//! check use, so the two cannot disagree.

use curve25519_dalek::traits::IsIdentity;
use rand_core::{CryptoRng, RngCore};

use crate::cbor::{self, Value};
use crate::elgamal::Ciphertext;
use crate::error::Error;
use crate::group::{point_from_value, point_to_value, RistrettoPoint, Scalar};
use crate::hash::{digest, hash_to_scalar};
use crate::manifest::{
    bytes32, decode_list, expect_version, record, schema, Contest, ContestKind, LinkGroup,
    Manifest, Method, OptionKind,
};
use crate::proofs::{prove_sum, verify_sum, CpProof, Disj01Proof, SchnorrProof};

/// Version of the ballot record (§12.5 field 1).
const VERSION: u64 = 1;

/// Identifier of a ballot (`ballot_id`, §12.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BallotId {
    /// Machine identifier (`tstr`).
    pub machine_id: String,
    /// Session identifier on that machine (`tstr`).
    pub session_id: String,
    /// Sequence number, 1-based within the session (`uint`).
    pub seq: u64,
}

impl BallotId {
    /// Encodes as `[tstr, tstr, uint]` (§12.1).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::from(self.machine_id.as_str()),
            Value::from(self.session_id.as_str()),
            Value::Uint(self.seq),
        ])
    }

    /// Strict decode of `[tstr, tstr, uint]` (§12.1).
    pub fn from_value(v: &Value) -> Result<BallotId, Error> {
        match v.as_array()? {
            [m, s, q] => Ok(BallotId {
                machine_id: m.as_text()?.to_owned(),
                session_id: s.as_text()?.to_owned(),
                seq: q.as_uint()?,
            }),
            _ => Err(schema("ballot_id must be [tstr, tstr, uint]")),
        }
    }
}

/// The election parameters a ballot needs: context hash, joint key and manifest.
pub struct Election<'a> {
    pub context_hash: [u8; 32],
    pub k: RistrettoPoint,
    pub manifest: &'a Manifest,
}

/// r(contest_index, position) = HashToScalar("eg/v1/nonce", context_hash, ballot_id, ρ,
/// contest_index, position) (§12.2).
pub fn derive_nonce(
    context_hash: &[u8; 32],
    id: &BallotId,
    rho: &[u8; 32],
    contest: u64,
    position: u64,
) -> Scalar {
    hash_to_scalar(
        "eg/v1/nonce",
        &[
            Value::from(*context_hash),
            id.to_value(),
            Value::from(*rho),
            Value::Uint(contest),
            Value::Uint(position),
        ],
    )
}

/// What the voter chose in one contest: selected option indices, ascending (§14.1 contest_plain).
///
/// - single and proportional: exactly one option (candidate, party, blank or null).
/// - multi: 0..=L candidate options (empty = blank), or exactly `[null]`.
/// - mixnet contests: the same rules, at most L selections (L = slots).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContestPlain {
    pub contest: u64,
    pub selected: Vec<u64>,
}

impl ContestPlain {
    /// Encodes as `[uint, [* uint]]` (§14.1).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.contest),
            Value::Array(self.selected.iter().map(|&o| Value::Uint(o)).collect()),
        ])
    }

    /// Strict decode of `[uint, [* uint]]` (§14.1).
    pub fn from_value(v: &Value) -> Result<ContestPlain, Error> {
        match v.as_array()? {
            [c, sel] => Ok(ContestPlain {
                contest: c.as_uint()?,
                selected: sel
                    .as_array()?
                    .iter()
                    .map(Value::as_uint)
                    .collect::<Result<_, _>>()?,
            }),
            _ => Err(schema("contest_plain must be [uint, [* uint]]")),
        }
    }
}

/// A complete ballot (`ballot`, §12.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ballot {
    /// Field 2: context hash of the election.
    pub context_hash: [u8; 32],
    /// Field 3: ballot identifier.
    pub id: BallotId,
    /// Field 4: one entry per contest offered by the machine, ascending contest index.
    pub contests: Vec<ContestBallot>,
    /// Field 5: one link proof per homomorphic link group whose contests are all offered.
    pub link_proofs: Vec<LinkProof>,
}

/// One contest of a ballot (`contest_ballot`, §12.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContestBallot {
    /// Homomorphic contest: one selection per position, then the sum proof.
    Hom {
        contest: u64,
        selections: Vec<(Ciphertext, Disj01Proof)>,
        sum_proof: CpProof,
    },
    /// Mixnet contest: one slot per slot index.
    Mix {
        contest: u64,
        slots: Vec<(Ciphertext, SchnorrProof)>,
    },
}

impl ContestBallot {
    /// The contest index this entry belongs to.
    pub fn contest(&self) -> u64 {
        match self {
            ContestBallot::Hom { contest, .. } | ContestBallot::Mix { contest, .. } => *contest,
        }
    }

    /// Encodes the contest entry as in §12.5.
    fn to_value(&self) -> Value {
        match self {
            ContestBallot::Hom {
                contest,
                selections,
                sum_proof,
            } => record(vec![
                (0, Value::from("hom")),
                (1, Value::Uint(*contest)),
                (
                    2,
                    Value::Array(
                        selections
                            .iter()
                            .map(|(ct, p)| entry_value(ct, &p.to_value()))
                            .collect(),
                    ),
                ),
                (3, sum_proof.to_value()),
            ]),
            ContestBallot::Mix { contest, slots } => record(vec![
                (0, Value::from("mix")),
                (1, Value::Uint(*contest)),
                (
                    2,
                    Value::Array(
                        slots
                            .iter()
                            .map(|(ct, p)| entry_value(ct, &p.to_value()))
                            .collect(),
                    ),
                ),
            ]),
        }
    }

    /// Strict decode of a contest entry (§12.5).
    fn from_value(v: &Value) -> Result<ContestBallot, Error> {
        let tag = v
            .get(0)?
            .ok_or_else(|| schema("contest ballot has no type tag"))?
            .as_text()?;
        match tag {
            "hom" => {
                let f = cbor::record_fields(v, "hom", 4)?;
                Ok(ContestBallot::Hom {
                    contest: f[1].as_uint()?,
                    selections: decode_list(f[2], 1, "selections", selection_from_value)?,
                    sum_proof: CpProof::from_value(f[3])?,
                })
            }
            "mix" => {
                let f = cbor::record_fields(v, "mix", 3)?;
                Ok(ContestBallot::Mix {
                    contest: f[1].as_uint()?,
                    slots: decode_list(f[2], 1, "slots", slot_from_value)?,
                })
            }
            _ => Err(schema("unknown contest ballot type")),
        }
    }
}

/// A link proof for one homomorphic link group (§12.5 `link_proof`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkProof {
    /// Group index.
    pub group: u64,
    /// One disj01 proof per candidate option, ascending option index.
    pub proofs: Vec<Disj01Proof>,
}

impl LinkProof {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.group),
            Value::Array(self.proofs.iter().map(Disj01Proof::to_value).collect()),
        ])
    }

    fn from_value(v: &Value) -> Result<LinkProof, Error> {
        match v.as_array()? {
            [g, ps] => Ok(LinkProof {
                group: g.as_uint()?,
                proofs: decode_list(ps, 1, "link proof", Disj01Proof::from_value)?,
            }),
            _ => Err(schema("link_proof must be [uint, [+ disj01_proof]]")),
        }
    }
}

/// The result of checking one contest of a ballot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContestStatus {
    Counted,
    /// Excluded from the tally, with the reason.
    Excluded(String),
}

/// The result of [`check_ballot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BallotCheck {
    /// `Err(reason)` if the ballot is not well-formed (§12.6 rules 1 to 4).
    pub well_formed: Result<(), String>,
    /// Status of each contest, in ballot order. Empty if not well-formed.
    pub contests: Vec<(u64, ContestStatus)>,
}

impl Ballot {
    /// Encodes the ballot as the CBOR map of §12.5.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("ballot")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, self.id.to_value()),
            (
                4,
                Value::Array(self.contests.iter().map(ContestBallot::to_value).collect()),
            ),
            (
                5,
                Value::Array(self.link_proofs.iter().map(LinkProof::to_value).collect()),
            ),
        ])
    }

    /// Strict decode of a ballot (§12.5). Structure against the manifest is
    /// checked by [`check_ballot`], not here.
    pub fn from_value(v: &Value) -> Result<Ballot, Error> {
        let f = cbor::record_fields(v, "ballot", 6)?;
        expect_version(f[1])?;
        Ok(Ballot {
            context_hash: bytes32(f[2])?,
            id: BallotId::from_value(f[3])?,
            contests: decode_list(f[4], 1, "contests", ContestBallot::from_value)?,
            link_proofs: decode_list(f[5], 0, "link proofs", LinkProof::from_value)?,
        })
    }

    /// The α values of one contest's entries, in position order. Used for the
    /// α reservation of §12.6, which runs at tally time.
    pub fn alphas(&self, contest: u64) -> Vec<RistrettoPoint> {
        self.contests
            .iter()
            .find(|cb| cb.contest() == contest)
            .map(|cb| entries(cb).into_iter().map(|ct| ct.alpha).collect())
            .unwrap_or_default()
    }

    /// Digest("eg/v1/ballot", ballot) (§13.1), used for tracking codes.
    pub fn digest(&self) -> [u8; 32] {
        digest("eg/v1/ballot", &[self.to_value()])
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers.
// ---------------------------------------------------------------------------

/// Encodes `[point α, point β, proof]` (§12.5 `selection` and `slot`).
fn entry_value(ct: &Ciphertext, proof: &Value) -> Value {
    Value::Array(vec![
        point_to_value(&ct.alpha),
        point_to_value(&ct.beta),
        proof.clone(),
    ])
}

/// Extracts exactly three elements from a CBOR array.
fn triple(v: &Value) -> Result<&[Value; 3], Error> {
    v.as_array()?
        .try_into()
        .map_err(|_| schema("expected a 3-element array"))
}

/// Decodes a `selection`. α may be the identity here, so that such a ballot
/// decodes and is then reported by rule 4 of §12.6.
fn selection_from_value(v: &Value) -> Result<(Ciphertext, Disj01Proof), Error> {
    let [a, b, p] = triple(v)?;
    Ok((
        Ciphertext {
            alpha: point_from_value(a)?,
            beta: point_from_value(b)?,
        },
        Disj01Proof::from_value(p)?,
    ))
}

/// Decodes a `slot`, with the same identity handling as [`selection_from_value`].
fn slot_from_value(v: &Value) -> Result<(Ciphertext, SchnorrProof), Error> {
    let [a, b, p] = triple(v)?;
    Ok((
        Ciphertext {
            alpha: point_from_value(a)?,
            beta: point_from_value(b)?,
        },
        SchnorrProof::from_value(p)?,
    ))
}

/// The ciphertexts of a contest's entries, in position order.
fn entries(cb: &ContestBallot) -> Vec<&Ciphertext> {
    match cb {
        ContestBallot::Hom { selections, .. } => selections.iter().map(|(ct, _)| ct).collect(),
        ContestBallot::Mix { slots, .. } => slots.iter().map(|(ct, _)| ct).collect(),
    }
}

/// The selections of a homomorphic contest (empty for a mixnet contest).
fn hom_selections(cb: &ContestBallot) -> &[(Ciphertext, Disj01Proof)] {
    match cb {
        ContestBallot::Hom { selections, .. } => selections,
        ContestBallot::Mix { .. } => &[],
    }
}

/// Index of the `null` option of a contest, if it has one.
fn null_position(contest: &Contest) -> Option<usize> {
    contest
        .options
        .iter()
        .position(|o| o.kind == OptionKind::Null)
}

/// Weight of each entry of a homomorphic contest in the sum (§12.3), and the
/// sum target L_target. Options come first, then placeholders (multi only).
/// The null option of a multi contest counts L times.
fn hom_layout(contest: &Contest) -> (Vec<u64>, u64) {
    let m = contest.options.len();
    match contest.kind {
        ContestKind::Multi => {
            let l = contest.limit;
            let mut weights: Vec<u64> = vec![1; m + l as usize];
            if let Some(n) = null_position(contest) {
                weights[n] = l;
            }
            (weights, l)
        }
        ContestKind::Single | ContestKind::Proportional => (vec![1; m], 1),
    }
}

fn strictly_ascending(sel: &[u64]) -> bool {
    sel.windows(2).all(|w| w[0] < w[1])
}

/// The plaintext of every entry of one contest, in position order (§12.3, §12.4).
///
/// Homomorphic contests give one bit per option, then one bit per placeholder
/// (multi). Mixnet contests give `option + 1` for each filled slot and 0 for each
/// empty one. This is the only place the encoding is defined. Invalid choices
/// are rejected here.
fn plaintexts(contest: &Contest, choice: &ContestPlain) -> Result<Vec<u32>, Error> {
    let m = contest.options.len();
    let sel = choice.selected.as_slice();
    let fail = |msg: &str| Error::Ballot(format!("contest {}: {msg}", contest.index));
    let check_index = |o: u64| -> Result<usize, Error> {
        usize::try_from(o)
            .ok()
            .filter(|&i| i < m)
            .ok_or_else(|| fail(&format!("option {o} does not exist")))
    };

    if choice.contest != contest.index {
        return Err(fail("choice is for another contest"));
    }
    if !strictly_ascending(sel) {
        return Err(fail("selected options must be strictly ascending"));
    }

    match contest.method {
        Method::Mixnet => {
            let l = contest.limit as usize;
            if sel.len() > l {
                return Err(fail("more selections than slots"));
            }
            // An honest machine only encrypts choices that §19.6 counts as
            // valid: single/proportional fill their one slot, and a multi null
            // stands alone.
            match contest.kind {
                ContestKind::Single | ContestKind::Proportional if sel.len() != 1 => {
                    return Err(fail("exactly one option must be selected"));
                }
                ContestKind::Multi if sel.len() > 1 => {
                    for &o in sel {
                        if contest.options[check_index(o)?].kind != OptionKind::Candidate {
                            return Err(fail("only candidates may be combined in a multi vote"));
                        }
                    }
                }
                _ => {}
            }
            let mut slots = vec![0u32; l];
            for (slot, &o) in slots.iter_mut().zip(sel) {
                check_index(o)?;
                *slot = o as u32 + 1;
            }
            Ok(slots)
        }
        Method::Homomorphic => match contest.kind {
            ContestKind::Single | ContestKind::Proportional => {
                let [o] = sel else {
                    return Err(fail("exactly one option must be selected"));
                };
                let mut bits = vec![0u32; m];
                bits[check_index(*o)?] = 1;
                Ok(bits)
            }
            ContestKind::Multi => {
                let l = contest.limit as usize;
                let null = null_position(contest);
                let mut bits = vec![0u32; m + l];
                if let (&[o], Some(n)) = (sel, null) {
                    if o == n as u64 {
                        bits[n] = 1;
                        return Ok(bits);
                    }
                }
                if sel.len() > l {
                    return Err(fail("more candidates than the selection limit"));
                }
                for &o in sel {
                    let i = check_index(o)?;
                    if contest.options[i].kind != OptionKind::Candidate {
                        return Err(fail("only candidates may be combined in a multi vote"));
                    }
                    bits[i] = 1;
                }
                // L - q placeholders encrypt 1, the lowest-positioned ones.
                let q = sel.len();
                bits[m..m + l - q].fill(1);
                Ok(bits)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Context strings (§11, the `ctx` values of each proof).
// ---------------------------------------------------------------------------

fn sel_ctx(election: &Election, id: &BallotId, contest: u64, position: u64) -> Value {
    Value::Array(vec![
        Value::from("sel"),
        Value::from(election.context_hash),
        id.to_value(),
        Value::Uint(contest),
        Value::Uint(position),
    ])
}

fn sum_ctx(election: &Election, id: &BallotId, contest: u64) -> Value {
    Value::Array(vec![
        Value::from("sum"),
        Value::from(election.context_hash),
        id.to_value(),
        Value::Uint(contest),
    ])
}

fn link_ctx(election: &Election, id: &BallotId, group: u64, candidate: u64) -> Value {
    Value::Array(vec![
        Value::from("link"),
        Value::from(election.context_hash),
        id.to_value(),
        Value::Uint(group),
        Value::Uint(candidate),
    ])
}

fn slot_ctx(
    election: &Election,
    id: &BallotId,
    contest: u64,
    slot: u64,
    beta: &RistrettoPoint,
) -> Value {
    Value::Array(vec![
        Value::from("slot"),
        Value::from(election.context_hash),
        id.to_value(),
        Value::Uint(contest),
        Value::Uint(slot),
        point_to_value(beta),
    ])
}

// ---------------------------------------------------------------------------
// Link groups.
// ---------------------------------------------------------------------------

/// The homomorphic link groups whose contests are all offered, ascending by
/// group index (§12.5 field 5).
fn homomorphic_groups<'a>(manifest: &'a Manifest, offered: &[u64]) -> Vec<&'a LinkGroup> {
    let mut groups: Vec<&LinkGroup> = manifest
        .link_groups
        .iter()
        .filter(|g| {
            g.contests.iter().all(|c| offered.contains(c))
                && g.contests
                    .first()
                    .and_then(|&c| manifest.contest(c))
                    .is_some_and(|c| c.method == Method::Homomorphic)
        })
        .collect();
    groups.sort_by_key(|g| g.index);
    groups
}

/// Candidate option indices of a link group. The manifest gives all contests
/// of a group the same options (§7.5).
fn group_candidates(manifest: &Manifest, group: &LinkGroup) -> Vec<u64> {
    group
        .contests
        .first()
        .and_then(|&c| manifest.contest(c))
        .map(|c| {
            c.options
                .iter()
                .enumerate()
                .filter(|(_, o)| o.kind == OptionKind::Candidate)
                .map(|(i, _)| i as u64)
                .collect()
        })
        .unwrap_or_default()
}

/// Positions in `offered` of the contests of a group.
fn member_positions(group: &LinkGroup, offered: &[u64]) -> Vec<usize> {
    group
        .contests
        .iter()
        .filter_map(|c| offered.iter().position(|o| o == c))
        .collect()
}

/// Proves that (α, β) = Enc(b; r_sum) encrypts 0 or 1 (§12.3a). The returned
/// ciphertext is Enc(b; r_sum), which equals the sum of the selections when the
/// link group is honest.
fn prove_link<R: RngCore + CryptoRng>(
    rng: &mut R,
    election: &Election,
    id: &BallotId,
    group: u64,
    candidate: u64,
    bit: u8,
    r_sum: &Scalar,
) -> Result<(Ciphertext, Disj01Proof), Error> {
    Disj01Proof::prove(
        rng,
        &link_ctx(election, id, group, candidate),
        &election.k,
        bit,
        r_sum,
    )
}

// ---------------------------------------------------------------------------
// Encryption (§12.2 to §12.5).
// ---------------------------------------------------------------------------

/// Checks that `offered` is non-empty, strictly ascending and names known contests.
fn check_offered(election: &Election, offered: &[u64]) -> Result<(), String> {
    if offered.is_empty() || !offered.windows(2).all(|w| w[0] < w[1]) {
        return Err("offered contests must be non-empty and strictly ascending".into());
    }
    match offered
        .iter()
        .find(|&&c| election.manifest.contest(c).is_none())
    {
        Some(c) => Err(format!("unknown contest {c}")),
        None => Ok(()),
    }
}

/// Machine-layer rule (§7.5): a candidate may not be selected in two contests
/// of the same link group.
fn check_link_duplicates(manifest: &Manifest, choices: &[ContestPlain]) -> Result<(), Error> {
    for g in &manifest.link_groups {
        let mut seen: Vec<u64> = Vec::new();
        for choice in choices.iter().filter(|p| g.contests.contains(&p.contest)) {
            let Some(def) = manifest.contest(choice.contest) else {
                continue;
            };
            for &o in &choice.selected {
                let is_candidate = def
                    .options
                    .get(o as usize)
                    .is_some_and(|opt| opt.kind == OptionKind::Candidate);
                if is_candidate {
                    if seen.contains(&o) {
                        return Err(Error::Ballot(format!(
                            "candidate {o} is selected in more than one contest of link group {}",
                            g.index
                        )));
                    }
                    seen.push(o);
                }
            }
        }
    }
    Ok(())
}

/// Encrypts and proves one homomorphic contest from explicit bits and weights
/// (§12.3). Returns the contest entry and the nonces used, which the link
/// proofs need. The bits must be 0 or 1 (a disj01 proof is a programming error
/// otherwise), but they are not otherwise checked.
fn hom_contest<R: RngCore + CryptoRng>(
    rng: &mut R,
    election: &Election,
    id: &BallotId,
    rho: &[u8; 32],
    contest: u64,
    bits: &[u32],
    weights: &[u64],
) -> Result<(ContestBallot, Vec<Scalar>), Error> {
    let mut selections = Vec::with_capacity(bits.len());
    let mut nonces = Vec::with_capacity(bits.len());
    let mut r_sum = Scalar::ZERO;
    for (p, (&bit, &w)) in bits.iter().zip(weights).enumerate() {
        let position = p as u64;
        let r = derive_nonce(&election.context_hash, id, rho, contest, position);
        let (ct, proof) = Disj01Proof::prove(
            rng,
            &sel_ctx(election, id, contest, position),
            &election.k,
            bit as u8,
            &r,
        )?;
        selections.push((ct, proof));
        r_sum += Scalar::from(w) * r;
        nonces.push(r);
    }
    let sum_proof = prove_sum(rng, &sum_ctx(election, id, contest), &election.k, &r_sum);
    Ok((
        ContestBallot::Hom {
            contest,
            selections,
            sum_proof,
        },
        nonces,
    ))
}

/// Encrypts and proves one mixnet contest (§12.4).
fn mix_contest<R: RngCore + CryptoRng>(
    rng: &mut R,
    election: &Election,
    id: &BallotId,
    rho: &[u8; 32],
    contest: u64,
    plain: &[u32],
) -> Result<ContestBallot, Error> {
    let mut slots = Vec::with_capacity(plain.len());
    for (s, &m) in plain.iter().enumerate() {
        let slot = s as u64;
        let r = derive_nonce(&election.context_hash, id, rho, contest, slot);
        let ct = Ciphertext::encrypt(m, &r, &election.k)?;
        let proof = SchnorrProof::prove(rng, &slot_ctx(election, id, contest, slot, &ct.beta), &r);
        slots.push((ct, proof));
    }
    Ok(ContestBallot::Mix { contest, slots })
}

/// Encrypts a ballot (§12.2 to §12.5).
///
/// `offered` are the contests the machine offers (ascending). `choices` must
/// cover exactly those contests, in the same order, and each must be valid for
/// its contest (see [`ContestPlain`]). Otherwise the call returns
/// [`Error::Ballot`]. Every nonce is derived from `rho`. If one is zero, the call
/// returns [`Error::ZeroNonce`] and the caller must draw a new ρ.
pub fn encrypt_ballot<R: RngCore + CryptoRng>(
    rng: &mut R,
    election: &Election,
    offered: &[u64],
    id: &BallotId,
    rho: &[u8; 32],
    choices: &[ContestPlain],
) -> Result<Ballot, Error> {
    check_offered(election, offered).map_err(Error::Ballot)?;
    if choices.len() != offered.len() || choices.iter().zip(offered).any(|(p, &c)| p.contest != c) {
        return Err(Error::Ballot(
            "choices must cover exactly the offered contests, ascending".into(),
        ));
    }
    check_link_duplicates(election.manifest, choices)?;

    let manifest = election.manifest;
    let mut contests = Vec::with_capacity(offered.len());
    // Per offered contest: the plaintext bits and the nonces (homomorphic only).
    let mut bits: Vec<Vec<u32>> = Vec::with_capacity(offered.len());
    let mut nonces: Vec<Vec<Scalar>> = Vec::with_capacity(offered.len());
    for (&c, choice) in offered.iter().zip(choices) {
        let def = manifest
            .contest(c)
            .ok_or_else(|| Error::Ballot(format!("unknown contest {c}")))?;
        let plain = plaintexts(def, choice)?;
        match def.method {
            Method::Homomorphic => {
                let (weights, _) = hom_layout(def);
                let (cb, rs) = hom_contest(rng, election, id, rho, c, &plain, &weights)?;
                contests.push(cb);
                bits.push(plain);
                nonces.push(rs);
            }
            Method::Mixnet => {
                contests.push(mix_contest(rng, election, id, rho, c, &plain)?);
                bits.push(Vec::new());
                nonces.push(Vec::new());
            }
        }
    }

    let mut link_proofs = Vec::new();
    for group in homomorphic_groups(manifest, offered) {
        let members = member_positions(group, offered);
        let mut proofs = Vec::new();
        for x in group_candidates(manifest, group) {
            let xi = x as usize;
            let mut sum = Ciphertext::zero();
            let mut bit = 0u32;
            let mut r_sum = Scalar::ZERO;
            for &mi in &members {
                sum += hom_selections(&contests[mi])[xi].0;
                bit += bits[mi][xi];
                r_sum += nonces[mi][xi];
            }
            debug_assert!(
                bit <= 1,
                "link group sums are 0 or 1 after the duplicate check"
            );
            let (link_ct, proof) =
                prove_link(rng, election, id, group.index, x, bit as u8, &r_sum)?;
            debug_assert_eq!(link_ct, sum);
            proofs.push(proof);
        }
        link_proofs.push(LinkProof {
            group: group.index,
            proofs,
        });
    }

    Ok(Ballot {
        context_hash: election.context_hash,
        id: id.clone(),
        contests,
        link_proofs,
    })
}

// ---------------------------------------------------------------------------
// Validity (§12.6).
// ---------------------------------------------------------------------------

/// Checks well-formedness rules 1 to 4 of §12.6.
fn well_formed(election: &Election, offered: &[u64], ballot: &Ballot) -> Result<(), String> {
    let manifest = election.manifest;
    // Rule 1.
    if ballot.context_hash != election.context_hash {
        return Err("context hash does not match the election".into());
    }
    check_offered(election, offered)?;
    // Rule 2: contest indices and structure.
    if ballot.contests.len() != offered.len() {
        return Err(format!(
            "expected {} contests, found {}",
            offered.len(),
            ballot.contests.len()
        ));
    }
    for (cb, &c) in ballot.contests.iter().zip(offered) {
        if cb.contest() != c {
            return Err(format!("contest {} where {c} was expected", cb.contest()));
        }
        let def = manifest
            .contest(c)
            .ok_or_else(|| format!("unknown contest {c}"))?;
        match (def.method, cb) {
            (Method::Homomorphic, ContestBallot::Hom { selections, .. }) => {
                let want = hom_layout(def).0.len();
                if selections.len() != want {
                    return Err(format!(
                        "contest {c}: expected {want} selections, found {}",
                        selections.len()
                    ));
                }
            }
            (Method::Mixnet, ContestBallot::Mix { slots, .. }) => {
                if slots.len() as u64 != def.limit {
                    return Err(format!(
                        "contest {c}: expected {} slots, found {}",
                        def.limit,
                        slots.len()
                    ));
                }
            }
            _ => return Err(format!("contest {c}: entry does not match its method")),
        }
        // Rule 4: no identity α.
        if let Some(p) = entries(cb).iter().position(|ct| ct.alpha.is_identity()) {
            return Err(format!("contest {c}, position {p}: alpha is the identity"));
        }
    }
    // Rule 3: one link proof per homomorphic group, with one proof per candidate.
    let groups = homomorphic_groups(manifest, offered);
    if ballot.link_proofs.len() != groups.len() {
        return Err(format!(
            "expected {} link proofs, found {}",
            groups.len(),
            ballot.link_proofs.len()
        ));
    }
    for (lp, group) in ballot.link_proofs.iter().zip(&groups) {
        if lp.group != group.index {
            return Err(format!(
                "link proof for group {} where {} was expected",
                lp.group, group.index
            ));
        }
        let want = group_candidates(manifest, group).len();
        if lp.proofs.len() != want {
            return Err(format!(
                "link group {}: expected {want} proofs, found {}",
                group.index,
                lp.proofs.len()
            ));
        }
    }
    Ok(())
}

/// Verifies the selection proofs and sum proof of one homomorphic contest, or
/// the slot proofs of one mixnet contest.
fn verify_contest(election: &Election, ballot: &Ballot, cb: &ContestBallot) -> Result<(), String> {
    let c = cb.contest();
    let def = election
        .manifest
        .contest(c)
        .ok_or_else(|| format!("unknown contest {c}"))?;
    match cb {
        ContestBallot::Hom {
            selections,
            sum_proof,
            ..
        } => {
            let (weights, target) = hom_layout(def);
            let mut sum = Ciphertext::zero();
            for (p, ((ct, proof), w)) in selections.iter().zip(&weights).enumerate() {
                if !proof.verify(&sel_ctx(election, &ballot.id, c, p as u64), &election.k, ct) {
                    return Err(format!("contest {c}, position {p}: selection proof fails"));
                }
                sum += ct.scale(&Scalar::from(*w));
            }
            if !verify_sum(
                sum_proof,
                &sum_ctx(election, &ballot.id, c),
                &election.k,
                &sum,
                target,
            ) {
                return Err(format!("contest {c}: sum proof fails"));
            }
            Ok(())
        }
        ContestBallot::Mix { slots, .. } => {
            for (s, (ct, proof)) in slots.iter().enumerate() {
                let ctx = slot_ctx(election, &ballot.id, c, s as u64, &ct.beta);
                if !proof.verify(&ctx, &ct.alpha) {
                    return Err(format!("contest {c}, slot {s}: slot proof fails"));
                }
            }
            Ok(())
        }
    }
}

/// Judges each contest of a well-formed ballot.
fn judge(election: &Election, offered: &[u64], ballot: &Ballot) -> Vec<(u64, ContestStatus)> {
    let manifest = election.manifest;
    let mut failure: Vec<Option<String>> = ballot
        .contests
        .iter()
        .map(|cb| verify_contest(election, ballot, cb).err())
        .collect();

    for (gi, group) in homomorphic_groups(manifest, offered)
        .into_iter()
        .enumerate()
    {
        let members = member_positions(group, offered);
        let lp = &ballot.link_proofs[gi];
        let mut link_failure = None;
        for (j, x) in group_candidates(manifest, group).into_iter().enumerate() {
            let mut sum = Ciphertext::zero();
            for &mi in &members {
                sum += hom_selections(&ballot.contests[mi])[x as usize].0;
            }
            let ctx = link_ctx(election, &ballot.id, group.index, x);
            if !lp.proofs[j].verify(&ctx, &election.k, &sum) {
                link_failure = Some(format!("link proof for candidate {x} fails"));
                break;
            }
        }
        // If any contest of the group or its link proof fails, the whole group is out.
        let reason = link_failure.or_else(|| members.iter().find_map(|&mi| failure[mi].clone()));
        if let Some(reason) = reason {
            for &mi in &members {
                failure[mi].get_or_insert_with(|| format!("link group {}: {reason}", group.index));
            }
        }
    }

    ballot
        .contests
        .iter()
        .zip(failure)
        .map(|(cb, f)| {
            let status = match f {
                None => ContestStatus::Counted,
                Some(reason) => ContestStatus::Excluded(reason),
            };
            (cb.contest(), status)
        })
        .collect()
}

/// Checks a ballot against the election and the contests its machine offers
/// (§12.6). Returns whether it is well-formed, and for each contest whether it
/// is counted or excluded (with the reason).
///
/// α reservation is not applied here. It spans ballots and is done at tally
/// time, using [`Ballot::alphas`].
pub fn check_ballot(election: &Election, offered: &[u64], ballot: &Ballot) -> BallotCheck {
    match well_formed(election, offered, ballot) {
        Ok(()) => BallotCheck {
            well_formed: Ok(()),
            contests: judge(election, offered, ballot),
        },
        Err(reason) => BallotCheck {
            well_formed: Err(reason),
            contests: Vec::new(),
        },
    }
}

/// Re-encrypts the claimed selections from ρ and compares every (α, β) byte
/// for byte with the ballot (§14.2 steps 2 to 4). Returns `Err` naming the
/// first mismatch.
pub fn check_reveal(
    election: &Election,
    ballot: &Ballot,
    rho: &[u8; 32],
    claimed: &[ContestPlain],
) -> Result<(), String> {
    if claimed.len() != ballot.contests.len() {
        return Err(format!(
            "reveal has {} contests, ballot has {}",
            claimed.len(),
            ballot.contests.len()
        ));
    }
    for (cb, claim) in ballot.contests.iter().zip(claimed) {
        let c = cb.contest();
        if claim.contest != c {
            return Err(format!(
                "reveal is for contest {} where {c} was expected",
                claim.contest
            ));
        }
        let def = election
            .manifest
            .contest(c)
            .ok_or_else(|| format!("unknown contest {c}"))?;
        let plain = plaintexts(def, claim).map_err(|e| e.to_string())?;
        let entries = entries(cb);
        if entries.len() != plain.len() {
            return Err(format!(
                "contest {c}: expected {} entries, found {}",
                plain.len(),
                entries.len()
            ));
        }
        for (p, (&m, ct)) in plain.iter().zip(entries).enumerate() {
            let r = derive_nonce(&election.context_hash, &ballot.id, rho, c, p as u64);
            let expected = Ciphertext::encrypt(m, &r, &election.k).map_err(|e| e.to_string())?;
            let same = expected.alpha.compress().to_bytes() == ct.alpha.compress().to_bytes()
                && expected.beta.compress().to_bytes() == ct.beta.compress().to_bytes();
            if !same {
                return Err(format!(
                    "contest {c}, position {p}: ciphertext does not match the reveal"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::elgamal::dlog_bounded;
    use crate::fixtures::{sample_manifest, sample_registry};
    use crate::group::{random_scalar, B};
    use curve25519_dalek::traits::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    const CTX: [u8; 32] = [9; 32];

    struct Setup {
        manifest: Manifest,
        offered: Vec<u64>,
        s: Scalar,
        k: RistrettoPoint,
    }

    fn setup() -> Setup {
        let (manifest, keys) = sample_manifest(1);
        let registry = sample_registry(&manifest, &keys);
        let offered = registry
            .machine("M-S1-01")
            .expect("machine")
            .contests
            .clone();
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let s = random_scalar(&mut rng);
        Setup {
            manifest,
            offered,
            s,
            k: s * B,
        }
    }

    fn election(st: &Setup) -> Election<'_> {
        Election {
            context_hash: CTX,
            k: st.k,
            manifest: &st.manifest,
        }
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([5; 32])
    }

    fn rho_of(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        r
    }

    fn bid(seq: u64) -> BallotId {
        BallotId {
            machine_id: "M-S1-01".into(),
            session_id: "S-1".into(),
            seq,
        }
    }

    fn decrypt(st: &Setup, ct: &Ciphertext) -> u64 {
        dlog_bounded(&ct.decrypt_to_point(&st.s), 100).expect("small plaintext")
    }

    fn decrypted(st: &Setup, cb: &ContestBallot) -> Vec<u64> {
        entries(cb).into_iter().map(|ct| decrypt(st, ct)).collect()
    }

    fn contest_of(b: &Ballot, c: u64) -> &ContestBallot {
        b.contests
            .iter()
            .find(|cb| cb.contest() == c)
            .expect("contest")
    }

    /// Contests 0..=5 of the sample manifest, with valid choices.
    /// 0 single hom, 1 multi hom (L = 2), 2 proportional, 3 single mixnet,
    /// 4 and 5 linked senators.
    fn valid_choices() -> Vec<ContestPlain> {
        let cp = |contest, selected: Vec<u64>| ContestPlain { contest, selected };
        vec![
            cp(0, vec![1]),
            cp(1, vec![1]),
            cp(2, vec![4]),
            cp(3, vec![1]),
            cp(4, vec![0]),
            cp(5, vec![2]),
        ]
    }

    /// Honest encryption of one homomorphic contest, bypassing ballot-level checks.
    fn honest_hom(
        rng: &mut ChaCha20Rng,
        e: &Election,
        id: &BallotId,
        rho: &[u8; 32],
        c: u64,
        selected: Vec<u64>,
    ) -> (ContestBallot, Vec<Scalar>) {
        let def = e.manifest.contest(c).expect("contest");
        let bits = plaintexts(
            def,
            &ContestPlain {
                contest: c,
                selected,
            },
        )
        .expect("valid");
        let (weights, _) = hom_layout(def);
        hom_contest(rng, e, id, rho, c, &bits, &weights).expect("honest contest")
    }

    fn assemble(
        e: &Election,
        id: &BallotId,
        contests: Vec<ContestBallot>,
        link_proofs: Vec<LinkProof>,
    ) -> Ballot {
        Ballot {
            context_hash: e.context_hash,
            id: id.clone(),
            contests,
            link_proofs,
        }
    }

    fn all_counted(check: &BallotCheck) -> bool {
        check.well_formed == Ok(())
            && check
                .contests
                .iter()
                .all(|(_, s)| *s == ContestStatus::Counted)
    }

    #[test]
    fn valid_ballot_is_counted_and_decrypts_to_intended_bits() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &valid_choices())
            .expect("encrypt");

        let check = check_ballot(&e, &st.offered, &b);
        assert!(all_counted(&check), "{check:?}");
        assert_eq!(b.link_proofs.len(), 1);
        assert_eq!(b.link_proofs[0].proofs.len(), 3);

        let expected: [(u64, Vec<u64>); 6] = [
            (0, vec![0, 1, 0, 0, 0]),
            // Candidate Iara, and the lowest placeholder set (L - q = 1).
            (1, vec![0, 1, 0, 0, 0, 1, 0]),
            (2, vec![0, 0, 0, 0, 1, 0, 0, 0]),
            // Option Iara is index 1, so the slot holds 2.
            (3, vec![2]),
            (4, vec![1, 0, 0, 0, 0]),
            (5, vec![0, 0, 1, 0, 0]),
        ];
        for (c, bits) in expected {
            assert_eq!(decrypted(&st, contest_of(&b, c)), bits, "contest {c}");
        }
    }

    #[test]
    fn multi_null_blank_and_full_selections() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let cases: [(Vec<u64>, Vec<u64>); 4] = [
            // Null: null = 1, every candidate and placeholder 0.
            (vec![4], vec![0, 0, 0, 0, 1, 0, 0]),
            // Blank: all placeholders 1.
            (vec![], vec![0, 0, 0, 0, 0, 1, 1]),
            // Two candidates: no placeholders.
            (vec![0, 3], vec![1, 0, 0, 1, 0, 0, 0]),
            // One candidate: one placeholder.
            (vec![2], vec![0, 0, 1, 0, 0, 1, 0]),
        ];
        for (selected, bits) in cases {
            let mut ch = valid_choices();
            ch[1].selected = selected.clone();
            let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &ch).expect("encrypt");
            assert!(
                all_counted(&check_ballot(&e, &st.offered, &b)),
                "{selected:?}"
            );
            assert_eq!(decrypted(&st, contest_of(&b, 1)), bits, "{selected:?}");
        }
    }

    #[test]
    fn mixnet_single_requires_one_selection() {
        // §19.6 counts an all-empty single row as invalid, so an honest machine
        // never encrypts one.
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let mut ch = valid_choices();
        ch[3].selected = vec![];
        assert!(encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &ch).is_err());
    }

    #[test]
    fn value_round_trip_is_canonical() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(7), &rho, &valid_choices())
            .expect("encrypt");

        let bytes = cbor::encode(&b.to_value());
        let decoded = cbor::decode(&bytes).expect("cbor");
        assert_eq!(cbor::encode(&decoded), bytes);
        assert_eq!(Ballot::from_value(&decoded), Ok(b.clone()));
        assert_eq!(
            b.digest(),
            Ballot::from_value(&decoded).expect("decode").digest()
        );

        for p in valid_choices() {
            assert_eq!(ContestPlain::from_value(&p.to_value()), Ok(p));
        }
        assert_eq!(BallotId::from_value(&bid(7).to_value()), Ok(bid(7)));
    }

    #[test]
    fn decoder_rejects_malformed_ballot() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &valid_choices())
            .expect("encrypt");
        let mut v = b.to_value();
        if let Value::Map(entries) = &mut v {
            entries.retain(|(k, _)| *k != Value::Uint(5));
        }
        assert!(Ballot::from_value(&v).is_err());
        assert!(Ballot::from_value(&Value::Uint(0)).is_err());
    }

    #[test]
    fn invalid_choices_are_rejected_by_encrypt() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let mut cases: Vec<(&str, Vec<ContestPlain>)> = Vec::new();

        let mut ch = valid_choices();
        ch[0].selected = vec![0, 1];
        cases.push(("two options in single", ch));

        let mut ch = valid_choices();
        ch[1].selected = vec![0, 1, 2];
        cases.push(("L+1 in multi", ch));

        let mut ch = valid_choices();
        ch[1].selected = vec![0, 4];
        cases.push(("null with candidate", ch));

        let mut ch = valid_choices();
        ch[3].selected = vec![5];
        cases.push(("out of range", ch));

        let mut ch = valid_choices();
        ch.pop();
        cases.push(("missing contest", ch));

        let mut ch = valid_choices();
        ch[4].selected = vec![0];
        ch[5].selected = vec![0];
        cases.push(("repeated candidate across link group", ch));

        for (name, ch) in cases {
            let r = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &ch);
            assert!(matches!(r, Err(Error::Ballot(_))), "{name}");
        }
    }

    #[test]
    fn cheat_two_ones_in_single_is_excluded() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let id = bid(1);
        // Honest proofs for each bit, but the sum is 2.
        let (cb, _) =
            hom_contest(&mut rng, &e, &id, &rho, 0, &[1, 1, 0, 0, 0], &[1; 5]).expect("contest");
        let b = assemble(&e, &id, vec![cb], vec![]);
        let check = check_ballot(&e, &[0], &b);
        assert_eq!(check.well_formed, Ok(()));
        assert!(matches!(check.contests[0].1, ContestStatus::Excluded(_)));
    }

    #[test]
    fn cheat_selection_encrypting_two_is_excluded() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let id = bid(1);
        let mut ch = valid_choices();
        ch.truncate(1);
        let mut b = encrypt_ballot(&mut rng, &e, &[0], &id, &rho, &ch).expect("encrypt");
        // Replace selection 0 with Enc(2; r), keeping its proof.
        let r0 = derive_nonce(&CTX, &id, &rho, 0, 0);
        let forged = Ciphertext::encrypt(2, &r0, &e.k).expect("nonzero");
        if let ContestBallot::Hom { selections, .. } = &mut b.contests[0] {
            selections[0].0 = forged;
        }
        let check = check_ballot(&e, &[0], &b);
        assert_eq!(check.well_formed, Ok(()));
        assert!(matches!(check.contests[0].1, ContestStatus::Excluded(_)));
    }

    #[test]
    fn cheat_same_candidate_in_linked_contests_excludes_both() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let id = bid(1);
        let (c0, _) = honest_hom(&mut rng, &e, &id, &rho, 0, vec![1]);
        // Both senators vote candidate 0. Each contest is honest on its own.
        let (c4, n4) = honest_hom(&mut rng, &e, &id, &rho, 4, vec![0]);
        let (c5, n5) = honest_hom(&mut rng, &e, &id, &rho, 5, vec![0]);
        let mut proofs = Vec::new();
        for x in 0..3usize {
            let r_sum = n4[x] + n5[x];
            // Candidate 0 is claimed with bit 1 over a sum that is really 2.
            // Candidates 1 and 2 are honest with bit 0.
            let bit = u8::from(x == 0);
            let (_, proof) =
                prove_link(&mut rng, &e, &id, 0, x as u64, bit, &r_sum).expect("prove");
            proofs.push(proof);
        }
        let link = LinkProof { group: 0, proofs };
        let b = assemble(&e, &id, vec![c0, c4, c5], vec![link]);
        let offered = [0, 4, 5];
        let check = check_ballot(&e, &offered, &b);
        assert_eq!(check.well_formed, Ok(()));
        assert_eq!(check.contests[0].1, ContestStatus::Counted);
        assert!(matches!(check.contests[1].1, ContestStatus::Excluded(_)));
        assert!(matches!(check.contests[2].1, ContestStatus::Excluded(_)));
    }

    #[test]
    fn swapped_selection_proofs_are_excluded() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let id = bid(1);
        let mut ch = valid_choices();
        ch.truncate(1);
        let mut b = encrypt_ballot(&mut rng, &e, &[0], &id, &rho, &ch).expect("encrypt");
        if let ContestBallot::Hom { selections, .. } = &mut b.contests[0] {
            let p0 = selections[0].1;
            selections[0].1 = selections[1].1;
            selections[1].1 = p0;
        }
        let check = check_ballot(&e, &[0], &b);
        assert_eq!(check.well_formed, Ok(()));
        assert!(matches!(check.contests[0].1, ContestStatus::Excluded(_)));
    }

    #[test]
    fn proof_copied_from_another_ballot_is_excluded() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let mut ch = valid_choices();
        ch.truncate(1);
        let a = encrypt_ballot(&mut rng, &e, &[0], &bid(1), &rho, &ch).expect("encrypt");
        let mut b = encrypt_ballot(&mut rng, &e, &[0], &bid(2), &rho, &ch).expect("encrypt");
        let copied = match &a.contests[0] {
            ContestBallot::Hom { selections, .. } => selections[0],
            ContestBallot::Mix { .. } => unreachable!(),
        };
        if let ContestBallot::Hom { selections, .. } = &mut b.contests[0] {
            selections[0] = copied;
        }
        let check = check_ballot(&e, &[0], &b);
        assert_eq!(check.well_formed, Ok(()));
        assert!(matches!(check.contests[0].1, ContestStatus::Excluded(_)));
    }

    #[test]
    fn identity_alpha_is_not_well_formed() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let mut ch = valid_choices();
        ch.truncate(1);
        let mut b = encrypt_ballot(&mut rng, &e, &[0], &bid(1), &rho, &ch).expect("encrypt");
        if let ContestBallot::Hom { selections, .. } = &mut b.contests[0] {
            selections[0].0.alpha = RistrettoPoint::identity();
        }
        let check = check_ballot(&e, &[0], &b);
        assert!(check.well_formed.is_err());
        assert!(check.contests.is_empty());
    }

    #[test]
    fn structural_failures_are_not_well_formed() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &valid_choices())
            .expect("encrypt");
        assert_eq!(check_ballot(&e, &st.offered, &b).well_formed, Ok(()));

        // Wrong context hash.
        let mut wrong_ctx = b.clone();
        wrong_ctx.context_hash = [1; 32];
        assert!(check_ballot(&e, &st.offered, &wrong_ctx)
            .well_formed
            .is_err());

        // Missing contest: the machine offers one more contest than the ballot has.
        let mut missing = b.clone();
        missing.contests.remove(2);
        assert!(check_ballot(&e, &st.offered, &missing).well_formed.is_err());

        // Wrong link proof count, both for a missing group and a missing candidate proof.
        let mut no_links = b.clone();
        no_links.link_proofs.clear();
        assert!(check_ballot(&e, &st.offered, &no_links)
            .well_formed
            .is_err());
        let mut short_link = b.clone();
        short_link.link_proofs[0].proofs.pop();
        assert!(check_ballot(&e, &st.offered, &short_link)
            .well_formed
            .is_err());
    }

    #[test]
    fn check_reveal_accepts_true_claims_and_rejects_others() {
        let st = setup();
        let e = election(&st);
        let mut rng = rng();
        let rho = rho_of(&mut rng);
        let b = encrypt_ballot(&mut rng, &e, &st.offered, &bid(1), &rho, &valid_choices())
            .expect("encrypt");

        assert_eq!(check_reveal(&e, &b, &rho, &valid_choices()), Ok(()));

        let mut altered = valid_choices();
        altered[1].selected = vec![2];
        assert!(check_reveal(&e, &b, &rho, &altered).is_err());

        let mut wrong_rho = rho;
        wrong_rho[0] ^= 1;
        assert!(check_reveal(&e, &b, &wrong_rho, &valid_choices()).is_err());
    }

    #[test]
    fn derive_nonce_is_deterministic_and_position_sensitive() {
        let rho = [4u8; 32];
        let id = bid(1);
        let r = derive_nonce(&CTX, &id, &rho, 0, 0);
        assert_eq!(r, derive_nonce(&CTX, &id, &rho, 0, 0));
        assert_ne!(r, derive_nonce(&CTX, &id, &rho, 0, 1));
        assert_ne!(r, derive_nonce(&CTX, &id, &rho, 1, 0));
        assert_ne!(r, derive_nonce(&CTX, &bid(2), &rho, 0, 0));
        assert_ne!(r, derive_nonce(&CTX, &id, &[5u8; 32], 0, 0));
        assert_ne!(r, derive_nonce(&[8u8; 32], &id, &rho, 0, 0));
    }
}
