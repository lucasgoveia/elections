//! Threshold decryption, mix-row counting, final BUs and results
//! (SPEC.md §16.5, §19.4 to §19.6, §20, §21).
//!
//! Decryption shares are per trustee and per ciphertext: trustee j publishes
//! M_j = z_j·α with a Chaum-Pedersen proof against its verification key Z_j.
//! Verifiers discard failing share sets, combine any k valid ones by Lagrange
//! interpolation, and recover each plaintext point m·B by a bounded discrete log.
//!
//! All records here are strictly decoded and carry version 1. The final BU is
//! unsigned; the share sets it carries are signed by their trustees, and the
//! result record is signed by the EA.

use std::collections::BTreeMap;

use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};

use crate::apportionment::SeatAllocation;
use crate::cbor::{record_fields, record_fields_opt, Value};
use crate::ceremony::Context;
use crate::elgamal::{dlog_bounded, Ciphertext};
use crate::error::Error;
use crate::group::{lagrange, point_from_value, point_to_value, RistrettoPoint, Scalar};
use crate::manifest::{
    bytes32, decode_list, expect_version, record, schema, uint_item, Contest, ContestKind,
    Manifest, OptionKind,
};
use crate::proofs::{prove_decryption_share, verify_decryption_share, CpProof};
use crate::shuffle::Row;
use crate::sign::{sign_record, verify_record, SigningKey, VerifyingKey};
use crate::tally::{ContestSum, PoolTally, SectionTally};

/// Version of every record in this module (§6.3).
const VERSION: u64 = 1;

const SHARES_TAG: &str = "decryption_shares";
const SHARES_SIG_TAG: &str = "eg/v1/sig/shares";
const SHARES_FIELDS: usize = 7;
const SHARES_SIG_KEY: u64 = 6;

const FINAL_BU_TAG: &str = "final_bu";
const FINAL_BU_FIELDS: usize = 7;

const CONTEST_RESULT_TAG: &str = "contest_result";
const SECTION_RESULT_TAG: &str = "section_result";
const SECTION_RESULT_FIELDS: usize = 7;

const RESULT_TAG: &str = "result";
const RESULT_SIG_TAG: &str = "eg/v1/sig/result";
const RESULT_FIELDS: usize = 8;
const RESULT_SIG_KEY: u64 = 7;

fn decryption(msg: impl Into<String>) -> Error {
    Error::Decryption(msg.into())
}

/// `ctx = ["dec", context_hash, target_digest, item_index]` (§20.1).
pub fn dec_ctx(context_hash: &[u8; 32], target: &[u8; 32], item: u64) -> Value {
    Value::Array(vec![
        Value::from("dec"),
        Value::from(*context_hash),
        Value::from(*target),
        Value::Uint(item),
    ])
}

// ---------------------------------------------------------------------------
// Canonical item lists (§20.1).
// ---------------------------------------------------------------------------

/// Ciphertexts of a section tally: contests in field-6 order, options ascending.
pub fn section_tally_items(t: &SectionTally) -> Vec<Ciphertext> {
    t.contests
        .iter()
        .flat_map(|s| s.sums.iter().copied())
        .collect()
}

/// Ciphertexts of a pool tally: contests ascending, options ascending, skipping
/// contests with no counted ballots.
pub fn pool_tally_items(t: &PoolTally) -> Vec<Ciphertext> {
    t.contests
        .iter()
        .filter(|s| s.counted > 0)
        .flat_map(|s| s.sums.iter().copied())
        .collect()
}

/// Ciphertexts of a mix list: rows ascending, slots ascending.
pub fn mix_list_items(list: &[Row]) -> Vec<Ciphertext> {
    list.iter().flat_map(|row| row.iter().copied()).collect()
}

// ---------------------------------------------------------------------------
// Decryption share sets (§20.1).
// ---------------------------------------------------------------------------

/// `decryption_share_set` (§20.1): one `(M_j, proof)` per ciphertext of a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionShareSet {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: RecordId of the target (section tally, pool tally or mix output).
    pub target: [u8; 32],
    /// Field 4: trustee index j (1-based).
    pub trustee: u64,
    /// Field 5: `(M_j, proof)` per ciphertext, in canonical order.
    pub shares: Vec<(RistrettoPoint, CpProof)>,
}

impl DecryptionShareSet {
    /// Trustee `trustee` computes `M_j = z_j·α` and a proof for every item (§20.1).
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        context_hash: &[u8; 32],
        target: &[u8; 32],
        trustee: u64,
        z_j: &Scalar,
        items: &[Ciphertext],
    ) -> DecryptionShareSet {
        let mut shares = Vec::with_capacity(items.len());
        for (i, ct) in items.iter().enumerate() {
            let m = z_j * ct.alpha;
            let ctx = dec_ctx(context_hash, target, i as u64);
            let proof = prove_decryption_share(rng, &ctx, z_j, &ct.alpha);
            shares.push((m, proof));
        }
        DecryptionShareSet {
            context_hash: *context_hash,
            target: *target,
            trustee,
            shares,
        }
    }

    /// Signs the set with the trustee's key (tag `eg/v1/sig/shares`, field 6).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let fields = vec![
            (0, Value::from(SHARES_TAG)),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.target)),
            (4, Value::Uint(self.trustee)),
            (
                5,
                Value::Array(
                    self.shares
                        .iter()
                        .map(|(m, p)| Value::Array(vec![point_to_value(m), p.to_value()]))
                        .collect(),
                ),
            ),
        ];
        sign_record(sk, SHARES_SIG_TAG, to_pairs(fields), SHARES_SIG_KEY)
    }

    /// Decodes and verifies a signed share set with the trustee's public key.
    pub fn from_signed(v: &Value, trustee_pk: &VerifyingKey) -> Result<DecryptionShareSet, Error> {
        let f = record_fields(v, SHARES_TAG, SHARES_FIELDS)?;
        verify_record(trustee_pk, SHARES_SIG_TAG, v, SHARES_SIG_KEY)?;
        expect_version(f[1])?;
        Ok(DecryptionShareSet {
            context_hash: bytes32(f[2])?,
            target: bytes32(f[3])?,
            trustee: f[4].as_uint()?,
            shares: decode_list(f[5], 1, "shares", share_from_value)?,
        })
    }

    /// True iff the set is for this context, has one share per item, and every
    /// proof verifies against Z_j = `context.z[trustee - 1]` and the item's α.
    pub fn verify(&self, context: &Context, items: &[Ciphertext]) -> bool {
        if self.context_hash != context.hash() || self.shares.len() != items.len() {
            return false;
        }
        let Some(z_big_j) = self
            .trustee
            .checked_sub(1)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| context.z.get(i))
        else {
            return false;
        };
        items
            .iter()
            .zip(&self.shares)
            .enumerate()
            .all(|(i, (ct, (m, p)))| {
                let ctx = dec_ctx(&self.context_hash, &self.target, i as u64);
                verify_decryption_share(p, &ctx, z_big_j, &ct.alpha, m)
            })
    }
}

fn share_from_value(v: &Value) -> Result<(RistrettoPoint, CpProof), Error> {
    match v.as_array()? {
        [m, p] => Ok((point_from_value(m)?, CpProof::from_value(p)?)),
        _ => Err(schema("share must be [point, cp_proof]")),
    }
}

fn to_pairs(fields: Vec<(u64, Value)>) -> Vec<(Value, Value)> {
    fields
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect()
}

// ---------------------------------------------------------------------------
// Combination (§20.2, §20.3).
// ---------------------------------------------------------------------------

/// Result of [`combine`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Combined {
    /// `T = β − Σ λ_j·M_j` per item, i.e. `m·B` in canonical order.
    pub plaintext_points: Vec<RistrettoPoint>,
    /// Trustee indices used, ascending (the k lowest valid ones).
    pub used: Vec<u64>,
    /// Sets discarded, as `(trustee, reason)`, in input order.
    pub rejected: Vec<(u64, String)>,
}

/// Verifies every share set, discards failures, and combines the k lowest valid
/// trustee indices (§20.2, §20.3). A set that fails verification, is for another
/// context, or repeats an already accepted trustee index is rejected. Returns
/// [`Error::Decryption`] if fewer than `k` sets are valid.
pub fn combine(
    context: &Context,
    k: u64,
    items: &[Ciphertext],
    sets: &[DecryptionShareSet],
) -> Result<Combined, Error> {
    if k == 0 {
        return Err(decryption("threshold must be at least 1"));
    }
    let context_hash = context.hash();
    let mut rejected = Vec::new();
    let mut valid: Vec<&DecryptionShareSet> = Vec::new();
    for set in sets {
        if set.context_hash != context_hash {
            rejected.push((set.trustee, "share set is for another context".to_owned()));
        } else if !set.verify(context, items) {
            rejected.push((set.trustee, "share proofs do not verify".to_owned()));
        } else if valid.iter().any(|s| s.trustee == set.trustee) {
            rejected.push((set.trustee, "duplicate trustee index".to_owned()));
        } else {
            valid.push(set);
        }
    }

    if (valid.len() as u64) < k {
        return Err(decryption(format!(
            "only {} valid share sets, need {k}",
            valid.len()
        )));
    }
    valid.sort_by_key(|s| s.trustee);
    let chosen = &valid[..usize::try_from(k).unwrap_or(usize::MAX)];
    let used: Vec<u64> = chosen.iter().map(|s| s.trustee).collect();

    let mut m_total = vec![RistrettoPoint::identity(); items.len()];
    for set in chosen {
        let lambda = lagrange(&used, set.trustee)?;
        for (acc, (m, _)) in m_total.iter_mut().zip(&set.shares) {
            *acc += lambda * *m;
        }
    }
    let plaintext_points = items
        .iter()
        .zip(&m_total)
        .map(|(ct, m)| ct.beta - m)
        .collect();

    Ok(Combined {
        plaintext_points,
        used,
        rejected,
    })
}

// ---------------------------------------------------------------------------
// Decoding (§20.4, §19.5).
// ---------------------------------------------------------------------------

/// Recovers, per homomorphic sum, the number of ballots and the votes per option
/// (§20.4). `points` are the decrypted values in canonical order of `sums`: one
/// per option of each sum, in sum order. For a pool tally, pass only the sums
/// with `counted > 0`, as [`pool_tally_items`] does. Each value must be
/// `m·B` with `m ≤ counted`, else [`Error::Decryption`].
pub fn decode_sums(
    sums: &[ContestSum],
    points: &[RistrettoPoint],
) -> Result<Vec<(u64, u64, Vec<u64>)>, Error> {
    let total: usize = sums.iter().map(|s| s.sums.len()).sum();
    if total != points.len() {
        return Err(decryption(format!(
            "expected {total} decrypted values, got {}",
            points.len()
        )));
    }
    let mut out = Vec::with_capacity(sums.len());
    let mut rest = points;
    for s in sums {
        let (mine, tail) = rest.split_at(s.sums.len());
        rest = tail;
        let votes = mine
            .iter()
            .enumerate()
            .map(|(o, p)| {
                dlog_bounded(p, s.counted).ok_or_else(|| {
                    decryption(format!(
                        "contest {} option {o}: no m <= {} matches",
                        s.contest, s.counted
                    ))
                })
            })
            .collect::<Result<Vec<u64>, Error>>()?;
        out.push((s.contest, s.counted, votes));
    }
    Ok(out)
}

/// Lookup table of §19.5: the m in `0..=options` with `point == m·B`, or `None`
/// if the value is not a valid slot.
pub fn decode_slot(point: &RistrettoPoint, options: usize) -> Option<u64> {
    dlog_bounded(point, u64::try_from(options).ok()?)
}

// ---------------------------------------------------------------------------
// Counting decrypted mix rows (§19.6).
// ---------------------------------------------------------------------------

/// Counts for one mix unit and one contest (§19.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixCount {
    /// Contest index.
    pub contest: u64,
    /// Votes per option (index = option index; blank and null included).
    pub votes: Vec<u64>,
    /// Rows counted for this contest (valid, including blank and null votes).
    pub counted: u64,
    /// Rows invalid for this contest.
    pub invalid: u64,
}

/// Verdict on one contest's slice of a row.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slice {
    /// Multi contest, all slots empty.
    Blank,
    /// Option indices selected (nonempty slots), in slot order.
    Votes(Vec<usize>),
}

/// Applies the single-contest rules of §19.6 to one contest's slots. `None` means
/// the row is invalid for this contest.
fn judge_slice(c: &Contest, slots: &[Option<u64>]) -> Option<Slice> {
    let options = c.options.len() as u64;
    let mut picks: Vec<usize> = Vec::new();
    for slot in slots {
        match *slot {
            None => return None,
            Some(0) => {}
            Some(m) if m > options => return None,
            Some(m) => picks.push((m - 1) as usize),
        }
    }
    let mut sorted = picks.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    if picks.is_empty() {
        // A machine always fills single and proportional slots.
        return (c.kind == ContestKind::Multi).then_some(Slice::Blank);
    }
    if c.kind == ContestKind::Multi {
        let null = c.options.iter().position(|o| o.kind == OptionKind::Null);
        if picks.len() > 1 && picks.iter().any(|p| Some(*p) == null) {
            return None;
        }
    }
    Some(Slice::Votes(picks))
}

/// Splits a row into one slice per contest, in contest order.
fn split_row<'a>(contests: &[&Contest], row: &'a [Option<u64>]) -> Vec<&'a [Option<u64>]> {
    let mut offset = 0;
    contests
        .iter()
        .map(|c| {
            let l = c.limit as usize;
            let slice = &row[offset..offset + l];
            offset += l;
            slice
        })
        .collect()
}

/// True if a candidate option index is selected in two different contests of the row.
fn repeats_candidate(contests: &[&Contest], slices: &[&[Option<u64>]]) -> bool {
    let mut seen: BTreeMap<usize, usize> = BTreeMap::new();
    for (p, (c, slice)) in contests.iter().zip(slices).enumerate() {
        for m in slice.iter().flatten().copied() {
            if m == 0 {
                continue;
            }
            let Ok(o) = usize::try_from(m - 1) else {
                continue;
            };
            let is_candidate = c
                .options
                .get(o)
                .is_some_and(|opt| opt.kind == OptionKind::Candidate);
            if !is_candidate {
                continue;
            }
            match seen.get(&o) {
                Some(&q) if q != p => return true,
                Some(_) => {}
                None => {
                    seen.insert(o, p);
                }
            }
        }
    }
    false
}

/// Counts decrypted mix rows for one mix unit (§19.6). `contests` lists the unit's
/// contests in ascending index (one for a plain mixnet contest, several for a link
/// group). `rows` hold the decoded slots `m` per row (`None` = invalid slot), laid
/// out as the contests' slots in order. A row whose width does not match the
/// unit is invalid for every contest.
pub fn count_mix_rows(contests: &[&Contest], rows: &[Vec<Option<u64>>]) -> Vec<MixCount> {
    let width: usize = contests.iter().map(|c| c.limit as usize).sum();
    let mut out: Vec<MixCount> = contests
        .iter()
        .map(|c| MixCount {
            contest: c.index,
            votes: vec![0; c.options.len()],
            counted: 0,
            invalid: 0,
        })
        .collect();

    for row in rows {
        let verdicts: Vec<Option<Slice>> = if row.len() != width {
            vec![None; contests.len()]
        } else {
            let slices = split_row(contests, row);
            if repeats_candidate(contests, &slices) {
                vec![None; contests.len()]
            } else {
                contests
                    .iter()
                    .zip(&slices)
                    .map(|(c, slice)| judge_slice(c, slice))
                    .collect()
            }
        };
        for (m, verdict) in out.iter_mut().zip(verdicts) {
            match verdict {
                None => m.invalid += 1,
                Some(Slice::Blank) => m.counted += 1,
                Some(Slice::Votes(picks)) => {
                    m.counted += 1;
                    for o in picks {
                        m.votes[o] += 1;
                    }
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Final BU (§16.5).
// ---------------------------------------------------------------------------

/// `final_bu` (§16.5). Unsigned: its authority is the share sets it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalBu {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: RecordId of the pre-BU.
    pub pre_bu_id: [u8; 32],
    /// Field 4: RecordId of the section tally.
    pub section_tally_id: [u8; 32],
    /// Field 5: per contest not pooled: index, ballots counted, votes per option.
    pub results: Vec<(u64, u64, Vec<u64>)>,
    /// Field 6: signed `decryption_share_set` values (kept as published).
    pub share_sets: Vec<Value>,
}

impl FinalBu {
    /// Encodes the record of §16.5.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from(FINAL_BU_TAG)),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.pre_bu_id)),
            (4, Value::from(self.section_tally_id)),
            (5, results_to_value(&self.results)),
            (6, Value::Array(self.share_sets.clone())),
        ])
    }

    /// Strict decode. Share sets are checked for shape only; their signatures are
    /// checked by [`check_final_bu`].
    pub fn from_value(v: &Value) -> Result<FinalBu, Error> {
        let f = record_fields(v, FINAL_BU_TAG, FINAL_BU_FIELDS)?;
        expect_version(f[1])?;
        Ok(FinalBu {
            context_hash: bytes32(f[2])?,
            pre_bu_id: bytes32(f[3])?,
            section_tally_id: bytes32(f[4])?,
            results: results_from_value(f[5])?,
            share_sets: decode_list(f[6], 1, "share sets", share_set_shape)?,
        })
    }
}

fn share_set_shape(v: &Value) -> Result<Value, Error> {
    record_fields(v, SHARES_TAG, SHARES_FIELDS)?;
    Ok(v.clone())
}

fn trustee_of(v: &Value) -> Option<u64> {
    record_fields(v, SHARES_TAG, SHARES_FIELDS)
        .ok()
        .and_then(|f| f[4].as_uint().ok())
}

/// Checks a final BU against the section tally whose fingerprint the caller has
/// already matched to the pre-BU (§16.5, steps 3 and 4). Share sets that fail to
/// decode, are signed by an unknown trustee, or are for another target are
/// discarded, as §20.3 requires. `trustee_keys[j-1]` is trustee j's key.
pub fn check_final_bu(
    fb: &FinalBu,
    tally: &SectionTally,
    context: &Context,
    k: u64,
    trustee_keys: &[VerifyingKey],
) -> Result<(), Error> {
    let context_hash = context.hash();
    if fb.context_hash != context_hash || tally.context_hash != context_hash {
        return Err(decryption("final BU is for another election context"));
    }
    if fb.pre_bu_id != tally.pre_bu_id {
        return Err(decryption(
            "final BU pre-BU id does not match the section tally",
        ));
    }
    let target = tally.record_id();
    if fb.section_tally_id != target {
        return Err(decryption(
            "final BU section tally id does not match the section tally",
        ));
    }

    let mut sets = Vec::new();
    for v in &fb.share_sets {
        let Some(key) = trustee_of(v)
            .and_then(|j| j.checked_sub(1))
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| trustee_keys.get(i))
        else {
            continue;
        };
        let Ok(set) = DecryptionShareSet::from_signed(v, key) else {
            continue;
        };
        if set.target == target {
            sets.push(set);
        }
    }

    let items = section_tally_items(tally);
    let combined = combine(context, k, &items, &sets)?;
    let decoded = decode_sums(&tally.contests, &combined.plaintext_points)?;
    if decoded != fb.results {
        return Err(decryption(
            "decrypted results differ from the final BU's field 5",
        ));
    }
    Ok(())
}

fn results_to_value(rs: &[(u64, u64, Vec<u64>)]) -> Value {
    Value::Array(
        rs.iter()
            .map(|(c, n, votes)| {
                Value::Array(vec![
                    Value::Uint(*c),
                    Value::Uint(*n),
                    Value::Array(votes.iter().map(|&v| Value::Uint(v)).collect()),
                ])
            })
            .collect(),
    )
}

fn result_item(v: &Value) -> Result<(u64, u64, Vec<u64>), Error> {
    match v.as_array()? {
        [c, n, votes] => Ok((
            c.as_uint()?,
            n.as_uint()?,
            decode_list(votes, 1, "votes", uint_item)?,
        )),
        _ => Err(schema("result must be [uint, uint, [+ uint]]")),
    }
}

fn results_from_value(v: &Value) -> Result<Vec<(u64, u64, Vec<u64>)>, Error> {
    decode_list(v, 0, "results", result_item)
}

// ---------------------------------------------------------------------------
// Results (§21).
// ---------------------------------------------------------------------------

/// `contest_result` (§21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContestResult {
    /// Field 1: contest index.
    pub contest: u64,
    /// Field 2: votes per option.
    pub votes: Vec<u64>,
    /// Field 3: ballots counted.
    pub counted: u64,
    /// Field 4: invalid ballots (mixnet only, else 0).
    pub invalid: u64,
    /// Field 5: ballots excluded under §12.6.
    pub excluded: u64,
    /// Field 6 (proportional): `(party index, party total)`.
    pub party_totals: Option<Vec<(u64, u64)>>,
    /// Field 7 (proportional): seat allocation.
    pub seats: Option<SeatAllocation>,
}

impl ContestResult {
    /// Encodes the record of §21.
    pub fn to_value(&self) -> Value {
        let mut fields = vec![
            (0, Value::from(CONTEST_RESULT_TAG)),
            (1, Value::Uint(self.contest)),
            (
                2,
                Value::Array(self.votes.iter().map(|&v| Value::Uint(v)).collect()),
            ),
            (3, Value::Uint(self.counted)),
            (4, Value::Uint(self.invalid)),
            (5, Value::Uint(self.excluded)),
        ];
        if let Some(totals) = &self.party_totals {
            fields.push((6, pairs_to_value(totals)));
        }
        if let Some(seats) = &self.seats {
            fields.push((7, seats.to_value()));
        }
        record(fields)
    }

    /// Strict decode. `seats` is the contest's seat count from the manifest and is
    /// needed only when field 7 is present.
    pub fn from_value(v: &Value, seats: Option<u64>) -> Result<ContestResult, Error> {
        let f = record_fields_opt(v, CONTEST_RESULT_TAG, 6, &[6, 7])?;
        let need = |i: usize| f[i].ok_or_else(|| schema("missing record key"));
        let party_totals = f[6]
            .map(|t| decode_list(t, 1, "party totals", uint_pair))
            .transpose()?;
        let seat_alloc = match f[7] {
            Some(s) => {
                let seats =
                    seats.ok_or_else(|| schema("seat allocation for a contest without seats"))?;
                Some(SeatAllocation::from_value(s, seats)?)
            }
            None => None,
        };
        Ok(ContestResult {
            contest: need(1)?.as_uint()?,
            votes: decode_list(need(2)?, 1, "votes", uint_item)?,
            counted: need(3)?.as_uint()?,
            invalid: need(4)?.as_uint()?,
            excluded: need(5)?.as_uint()?,
            party_totals,
            seats: seat_alloc,
        })
    }
}

/// `section_result` (§21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionResult {
    /// Field 1: section identifier.
    pub section_id: String,
    /// Field 2: RecordId of the pre-BU.
    pub pre_bu_id: [u8; 32],
    /// Field 3: RecordId of the final BU.
    pub final_bu_id: [u8; 32],
    /// Field 4: homomorphic contests not pooled: index, counted, votes per option.
    pub contests: Vec<(u64, u64, Vec<u64>)>,
    /// Field 5: every offered contest: index, ballots excluded under §12.6.
    pub excluded: Vec<(u64, u64)>,
    /// Field 6: whether the pre-BU fingerprint matches the recomputed section tally.
    pub matches: bool,
}

impl SectionResult {
    /// Encodes the record of §21.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from(SECTION_RESULT_TAG)),
            (1, Value::from(self.section_id.as_str())),
            (2, Value::from(self.pre_bu_id)),
            (3, Value::from(self.final_bu_id)),
            (4, results_to_value(&self.contests)),
            (5, pairs_to_value(&self.excluded)),
            (
                6,
                Value::from(if self.matches { "match" } else { "mismatch" }),
            ),
        ])
    }

    /// Strict decode of `section_result`.
    pub fn from_value(v: &Value) -> Result<SectionResult, Error> {
        let f = record_fields(v, SECTION_RESULT_TAG, SECTION_RESULT_FIELDS)?;
        let matches = match f[6].as_text()? {
            "match" => true,
            "mismatch" => false,
            _ => return Err(schema("section match must be \"match\" or \"mismatch\"")),
        };
        Ok(SectionResult {
            section_id: f[1].as_text()?.to_owned(),
            pre_bu_id: bytes32(f[2])?,
            final_bu_id: bytes32(f[3])?,
            contests: results_from_value(f[4])?,
            excluded: decode_list(f[5], 0, "excluded", uint_pair)?,
            matches,
        })
    }
}

fn uint_pair(v: &Value) -> Result<(u64, u64), Error> {
    match v.as_array()? {
        [a, b] => Ok((a.as_uint()?, b.as_uint()?)),
        _ => Err(schema("expected [uint, uint]")),
    }
}

fn pairs_to_value(pairs: &[(u64, u64)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|&(a, b)| Value::Array(vec![Value::Uint(a), Value::Uint(b)]))
            .collect(),
    )
}

/// The signed election result (§21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionResult {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: tree size the tally covers (`tally_cutoff`).
    pub tree_size: u64,
    /// Field 4: one entry per contest.
    pub contests: Vec<ContestResult>,
    /// Field 5: one entry per pre-BU in accepted packages, board order.
    pub sections: Vec<SectionResult>,
    /// Field 6: pool, per homomorphic contest: index, counted, votes per option.
    pub pool: Vec<(u64, u64, Vec<u64>)>,
}

impl ElectionResult {
    fn fields(&self) -> Vec<(u64, Value)> {
        vec![
            (0, Value::from(RESULT_TAG)),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::Uint(self.tree_size)),
            (
                4,
                Value::Array(self.contests.iter().map(ContestResult::to_value).collect()),
            ),
            (
                5,
                Value::Array(self.sections.iter().map(SectionResult::to_value).collect()),
            ),
            (6, results_to_value(&self.pool)),
        ]
    }

    /// Signs the result with the EA key (tag `eg/v1/sig/result`, field 7).
    pub fn sign(&self, ea_sk: &SigningKey) -> Value {
        sign_record(
            ea_sk,
            RESULT_SIG_TAG,
            to_pairs(self.fields()),
            RESULT_SIG_KEY,
        )
    }

    /// Decodes and verifies a signed result. `manifest` supplies each contest's seat
    /// count for field 4 entries; a result for a contest the manifest lacks is rejected.
    pub fn from_signed(
        v: &Value,
        ea_pk: &VerifyingKey,
        manifest: &Manifest,
    ) -> Result<ElectionResult, Error> {
        let f = record_fields(v, RESULT_TAG, RESULT_FIELDS)?;
        verify_record(ea_pk, RESULT_SIG_TAG, v, RESULT_SIG_KEY)?;
        expect_version(f[1])?;
        let contests = decode_list(f[4], 1, "contest results", |c| {
            let index = record_fields_opt(c, CONTEST_RESULT_TAG, 6, &[6, 7])?[1]
                .ok_or_else(|| schema("missing contest index"))?
                .as_uint()?;
            let def = manifest
                .contest(index)
                .ok_or_else(|| decryption(format!("result for unknown contest {index}")))?;
            ContestResult::from_value(c, def.seats)
        })?;
        Ok(ElectionResult {
            context_hash: bytes32(f[2])?,
            tree_size: f[3].as_uint()?,
            contests,
            sections: decode_list(f[5], 0, "section results", SectionResult::from_value)?,
            pool: results_from_value(f[6])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{
        encrypt_ballot, Ballot, BallotId, ContestBallot, ContestPlain, ContestStatus, Election,
    };
    use crate::dkg::{joint_public_key, verification_key, Polynomial};
    use crate::fixtures::{sample_manifest, sample_registry};
    use crate::group::{random_scalar, B};
    use crate::manifest::{BallotOption, Method};
    use crate::shuffle::shuffle;
    use crate::tally::{judge_cast, sum_ballots, JudgedBallot, Reservations};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    /// Context for n trustees with threshold k, built from random polynomials.
    /// Returns the context and every trustee's secret z_j (index j-1).
    fn make_context(rng: &mut ChaCha20Rng, n: u64, k: usize) -> (Context, Vec<Scalar>) {
        let polys: Vec<Polynomial> = (0..n).map(|_| Polynomial::random(rng, k)).collect();
        let all: Vec<Vec<RistrettoPoint>> = polys.iter().map(Polynomial::commitments).collect();
        let key = joint_public_key(&all).expect("K");
        let mut zs = Vec::new();
        let mut zbig = Vec::new();
        for j in 1..=n {
            zs.push(polys.iter().fold(Scalar::ZERO, |acc, p| acc + p.eval(j)));
            zbig.push(verification_key(&all, j));
        }
        let ctx = Context {
            manifest_hash: [1; 32],
            transcript_hash: [2; 32],
            k: key,
            z: zbig,
        };
        (ctx, zs)
    }

    fn nonzero(rng: &mut ChaCha20Rng) -> Scalar {
        loop {
            let r = random_scalar(rng);
            if r != Scalar::ZERO {
                return r;
            }
        }
    }

    fn encrypt_items(rng: &mut ChaCha20Rng, k: &RistrettoPoint, ms: &[u32]) -> Vec<Ciphertext> {
        ms.iter()
            .map(|&m| Ciphertext::encrypt(m, &nonzero(rng), k).unwrap())
            .collect()
    }

    const TARGET: [u8; 32] = [7; 32];

    /// Signed share sets from every trustee, round-tripped through their signed form.
    fn signed_sets(
        rng: &mut ChaCha20Rng,
        ctx: &Context,
        zs: &[Scalar],
        keys: &[SigningKey],
        items: &[Ciphertext],
    ) -> Vec<DecryptionShareSet> {
        let hash = ctx.hash();
        (0..zs.len())
            .map(|j| {
                let set =
                    DecryptionShareSet::create(rng, &hash, &TARGET, j as u64 + 1, &zs[j], items);
                let signed = set.sign(&keys[j]);
                let back = DecryptionShareSet::from_signed(&signed, &keys[j].verifying_key())
                    .expect("from_signed");
                assert_eq!(back, set);
                back
            })
            .collect()
    }

    fn trustee_keys(rng: &mut ChaCha20Rng, n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(rng)).collect()
    }

    fn tampered(set: &DecryptionShareSet) -> DecryptionShareSet {
        let mut bad = set.clone();
        bad.shares[0].0 += B;
        bad
    }

    #[test]
    fn share_set_round_trip_and_verify() {
        let mut rng = rng(1);
        let (ctx, zs) = make_context(&mut rng, 3, 2);
        let keys = trustee_keys(&mut rng, 3);
        let items = encrypt_items(&mut rng, &ctx.k, &[1, 2, 3]);
        let set = DecryptionShareSet::create(&mut rng, &ctx.hash(), &TARGET, 2, &zs[1], &items);
        assert!(set.verify(&ctx, &items));

        let signed = set.sign(&keys[1]);
        let back = DecryptionShareSet::from_signed(&signed, &keys[1].verifying_key()).unwrap();
        assert_eq!(back, set);
        assert!(back.verify(&ctx, &items));

        assert!(DecryptionShareSet::from_signed(&signed, &keys[0].verifying_key()).is_err());
        assert!(!tampered(&set).verify(&ctx, &items));
        // Wrong target: the proofs bind the target, so a changed field fails.
        let mut other_target = set.clone();
        other_target.target = [8; 32];
        assert!(!other_target.verify(&ctx, &items));
        // Shares for other items do not verify.
        let other_items = encrypt_items(&mut rng, &ctx.k, &[1, 2, 4]);
        assert!(!set.verify(&ctx, &other_items));
    }

    #[test]
    fn combine_is_independent_of_the_subset() {
        let mut rng = rng(2);
        let (ctx, zs) = make_context(&mut rng, 3, 2);
        let keys = trustee_keys(&mut rng, 3);
        let ms = [0u32, 3, 9];
        let items = encrypt_items(&mut rng, &ctx.k, &ms);
        let sets = signed_sets(&mut rng, &ctx, &zs, &keys, &items);
        let expected: Vec<RistrettoPoint> = ms.iter().map(|&m| Scalar::from(m) * B).collect();

        let all = combine(&ctx, 2, &items, &sets).unwrap();
        assert_eq!(all.used, vec![1, 2]);
        assert!(all.rejected.is_empty());
        assert_eq!(all.plaintext_points, expected);

        let high = combine(&ctx, 2, &items, &sets[1..]).unwrap();
        assert_eq!(high.used, vec![2, 3]);
        assert_eq!(high.plaintext_points, expected);
    }

    #[test]
    fn combine_discards_bad_sets_and_reports_them() {
        let mut rng = rng(3);
        let (ctx, zs) = make_context(&mut rng, 3, 2);
        let keys = trustee_keys(&mut rng, 3);
        let ms = [4u32, 1];
        let items = encrypt_items(&mut rng, &ctx.k, &ms);
        let sets = signed_sets(&mut rng, &ctx, &zs, &keys, &items);
        let expected: Vec<RistrettoPoint> = ms.iter().map(|&m| Scalar::from(m) * B).collect();

        let bad = vec![tampered(&sets[0]), sets[1].clone(), sets[2].clone()];
        let c = combine(&ctx, 2, &items, &bad).unwrap();
        assert_eq!(c.used, vec![2, 3]);
        assert_eq!(c.rejected.len(), 1);
        assert_eq!(c.rejected[0].0, 1);
        assert_eq!(c.plaintext_points, expected);

        let dup = vec![sets[0].clone(), sets[0].clone(), sets[1].clone()];
        let c = combine(&ctx, 2, &items, &dup).unwrap();
        assert_eq!(c.used, vec![1, 2]);
        assert_eq!(c.rejected, vec![(1, "duplicate trustee index".to_owned())]);

        let only_one = vec![sets[0].clone(), tampered(&sets[1]), tampered(&sets[2])];
        assert!(matches!(
            combine(&ctx, 2, &items, &only_one),
            Err(Error::Decryption(_))
        ));
    }

    #[test]
    fn decode_sums_recovers_counts_and_rejects_overflow() {
        let sum = ContestSum {
            contest: 0,
            counted: 3,
            sums: vec![Ciphertext::zero(), Ciphertext::zero()],
        };
        let points = [RistrettoPoint::identity(), Scalar::from(3u64) * B];
        assert_eq!(
            decode_sums(std::slice::from_ref(&sum), &points).unwrap(),
            vec![(0, 3, vec![0, 3])]
        );
        let over = [Scalar::from(1u64) * B, Scalar::from(4u64) * B];
        assert!(matches!(
            decode_sums(std::slice::from_ref(&sum), &over),
            Err(Error::Decryption(_))
        ));
        assert!(decode_sums(std::slice::from_ref(&sum), &points[..1]).is_err());
    }

    fn option(index: u64, kind: OptionKind) -> BallotOption {
        BallotOption {
            index,
            name: format!("o{index}"),
            kind,
            number: None,
            party_index: None,
            tiebreak_rank: None,
        }
    }

    fn contest(index: u64, kind: ContestKind, limit: u64) -> Contest {
        Contest {
            index,
            name: format!("c{index}"),
            kind,
            method: Method::Mixnet,
            limit,
            options: vec![
                option(0, OptionKind::Candidate),
                option(1, OptionKind::Candidate),
                option(2, OptionKind::Blank),
                option(3, OptionKind::Null),
            ],
            apportionment: None,
            seats: None,
            regional_mix: false,
        }
    }

    fn some(v: &[u64]) -> Vec<Option<u64>> {
        v.iter().map(|&m| Some(m)).collect()
    }

    #[test]
    fn count_single_rows() {
        let c = contest(0, ContestKind::Single, 1);
        let rows = vec![
            some(&[1]), // candidate 0
            some(&[3]), // blank
            some(&[0]), // empty: invalid for single
            some(&[9]), // out of range: invalid
            vec![None], // invalid slot
            some(&[4]), // null
        ];
        let out = count_mix_rows(&[&c], &rows);
        assert_eq!(
            out,
            vec![MixCount {
                contest: 0,
                votes: vec![1, 0, 1, 1],
                counted: 3,
                invalid: 3,
            }]
        );
    }

    #[test]
    fn count_multi_rows() {
        let c = contest(1, ContestKind::Multi, 2);
        let rows = vec![
            some(&[1, 2]),       // candidates 0 and 1
            some(&[0, 0]),       // blank
            some(&[4, 0]),       // null alone
            some(&[4, 1]),       // null with candidate: invalid
            some(&[1, 1]),       // duplicate: invalid
            some(&[0, 2]),       // candidate 1 alone
            vec![Some(2), None], // invalid slot
        ];
        let out = count_mix_rows(&[&c], &rows);
        assert_eq!(
            out,
            vec![MixCount {
                contest: 1,
                votes: vec![1, 2, 0, 1],
                counted: 4,
                invalid: 3,
            }]
        );
    }

    #[test]
    fn link_group_repeated_candidate_invalidates_both_contests() {
        let a = contest(4, ContestKind::Single, 1);
        let b = contest(5, ContestKind::Single, 1);
        let rows = vec![
            some(&[1, 2]),       // candidate 0 in A, candidate 1 in B: both valid
            some(&[1, 1]),       // candidate 0 in both: both invalid
            some(&[1, 3]),       // candidate 0 in A, blank in B: both valid
            some(&[3, 3]),       // blank in both: valid, not a candidate
            vec![None, Some(2)], // invalid slot in A; B (candidate 1) still valid
        ];
        let out = count_mix_rows(&[&a, &b], &rows);
        assert_eq!(out[0].contest, 4);
        assert_eq!(out[0].votes, vec![2, 0, 1, 0]);
        assert_eq!(out[0].counted, 3);
        assert_eq!(out[0].invalid, 2);
        assert_eq!(out[1].contest, 5);
        assert_eq!(out[1].votes, vec![0, 2, 2, 0]);
        assert_eq!(out[1].counted, 4);
        assert_eq!(out[1].invalid, 1);
    }

    /// Choices for contests 0..=5 of the sample manifest for voter `i` (0..5).
    fn picks(i: usize) -> Vec<ContestPlain> {
        let rows: [[Vec<u64>; 6]; 5] = [
            [vec![1], vec![1], vec![4], vec![1], vec![0], vec![2]],
            [vec![1], vec![0, 3], vec![4], vec![1], vec![0], vec![1]],
            [vec![0], vec![], vec![0], vec![1], vec![1], vec![2]],
            [vec![3], vec![4], vec![7], vec![1], vec![4], vec![2]],
            [vec![1], vec![2], vec![4], vec![1], vec![0], vec![4]],
        ];
        rows[i]
            .iter()
            .enumerate()
            .map(|(c, sel)| ContestPlain {
                contest: c as u64,
                selected: sel.clone(),
            })
            .collect()
    }

    #[test]
    fn homomorphic_election_end_to_end() {
        let mut rng = rng(4);
        let (ctx, zs) = make_context(&mut rng, 3, 2);
        let keys = trustee_keys(&mut rng, 3);
        let (manifest, keys_ea) = sample_manifest(1);
        let registry = sample_registry(&manifest, &keys_ea);
        let offered = registry
            .machine("M-S1-01")
            .expect("machine")
            .contests
            .clone();
        let hash = ctx.hash();
        let election = Election {
            context_hash: hash,
            k: ctx.k,
            manifest: &manifest,
        };

        let ballots: Vec<Ballot> = (0..5)
            .map(|i| {
                let mut rho = [0u8; 32];
                rho[0] = i as u8 + 1;
                let id = BallotId {
                    machine_id: "M-S1-01".into(),
                    session_id: "S-1".into(),
                    seq: i as u64 + 1,
                };
                encrypt_ballot(&mut rng, &election, &offered, &id, &rho, &picks(i))
                    .expect("encrypt")
            })
            .collect();
        let mut reservations = Reservations::new();
        let judged: Vec<JudgedBallot> = ballots
            .iter()
            .map(|b| judge_cast(&election, &offered, b, &mut reservations))
            .collect();
        assert!(judged.iter().all(|j| j.well_formed == Ok(())
            && j.contests.iter().all(|(_, s)| *s == ContestStatus::Counted)));

        let pairs: Vec<(&Ballot, &JudgedBallot)> = ballots.iter().zip(&judged).collect();
        let sums = sum_ballots(&election, &pairs);
        assert!(!sums.is_empty());

        let tally = SectionTally {
            context_hash: hash,
            pre_bu_id: [3; 32],
            section_id: "S1".into(),
            packages: vec![[4; 32]],
            contests: sums.clone(),
            pooled: vec![],
        };
        let target = tally.record_id();
        let items = section_tally_items(&tally);
        let sets = signed_sets(&mut rng, &ctx, &zs, &keys, &items);
        let combined = combine(&ctx, 2, &items, &sets[..2]).unwrap();
        let decoded = decode_sums(&tally.contests, &combined.plaintext_points).unwrap();
        assert_eq!(decoded.len(), sums.len());
        for (s, (idx, counted, votes)) in sums.iter().zip(&decoded) {
            assert_eq!(*idx, s.contest);
            assert_eq!(*counted, 5);
            let mut expected = vec![0u64; votes.len()];
            for i in 0..5 {
                for choice in picks(i).iter().filter(|p| p.contest == s.contest) {
                    for &o in &choice.selected {
                        expected[o as usize] += 1;
                    }
                }
            }
            assert_eq!(votes, &expected, "contest {}", s.contest);
        }

        let vks: Vec<VerifyingKey> = keys.iter().map(SigningKey::verifying_key).collect();
        let signed: Vec<Value> = (0..3)
            .map(|j| {
                DecryptionShareSet::create(&mut rng, &hash, &target, j as u64 + 1, &zs[j], &items)
                    .sign(&keys[j])
            })
            .collect();
        let fb = FinalBu {
            context_hash: hash,
            pre_bu_id: tally.pre_bu_id,
            section_tally_id: target,
            results: decoded.clone(),
            share_sets: signed,
        };
        assert_eq!(FinalBu::from_value(&fb.to_value()).unwrap(), fb);
        assert!(check_final_bu(&fb, &tally, &ctx, 2, &vks).is_ok());

        let mut altered = fb.clone();
        altered.results[0].2[0] += 1;
        assert!(check_final_bu(&altered, &tally, &ctx, 2, &vks).is_err());

        let mut wrong_tally = tally.clone();
        wrong_tally.pre_bu_id = [5; 32];
        assert!(check_final_bu(&fb, &wrong_tally, &ctx, 2, &vks).is_err());

        // Fewer than k valid share sets: decryption incomplete.
        let mut short = fb.clone();
        short.share_sets.truncate(1);
        assert!(check_final_bu(&short, &tally, &ctx, 2, &vks).is_err());
    }

    #[test]
    fn pool_and_mix_items_have_canonical_order() {
        let ct = |n: u32| Ciphertext::encrypt(n, &Scalar::from(u64::from(n) + 1), &B).unwrap();
        let pool = PoolTally {
            context_hash: [0; 32],
            tree_size: 1,
            contests: vec![
                ContestSum {
                    contest: 0,
                    counted: 0,
                    sums: vec![ct(1)],
                },
                ContestSum {
                    contest: 1,
                    counted: 2,
                    sums: vec![ct(2), ct(3)],
                },
            ],
        };
        assert_eq!(pool_tally_items(&pool), vec![ct(2), ct(3)]);
        let list: Vec<Row> = vec![vec![ct(1), ct(2)], vec![ct(3), ct(4)]];
        assert_eq!(mix_list_items(&list), vec![ct(1), ct(2), ct(3), ct(4)]);
    }

    fn mix_row(ballot: &Ballot, contest: u64) -> Row {
        ballot
            .contests
            .iter()
            .find_map(|cb| match cb {
                ContestBallot::Mix { contest: c, slots } if *c == contest => {
                    Some(slots.iter().map(|(ct, _)| *ct).collect())
                }
                _ => None,
            })
            .expect("mix contest present")
    }

    #[test]
    fn mix_unit_end_to_end() {
        let mut rng = rng(5);
        let (ctx, zs) = make_context(&mut rng, 3, 2);
        let (manifest, keys_ea) = sample_manifest(1);
        let registry = sample_registry(&manifest, &keys_ea);
        let offered = registry
            .machine("M-S1-01")
            .expect("machine")
            .contests
            .clone();
        let election = Election {
            context_hash: ctx.hash(),
            k: ctx.k,
            manifest: &manifest,
        };
        let mix_contest = manifest.contest(3).expect("contest 3");
        let blank = (mix_contest.options.len() - 2) as u64;
        let null = blank + 1;
        let chosen = [0u64, 2, blank, null];

        let rows: Vec<Row> = chosen
            .iter()
            .enumerate()
            .map(|(i, &sel)| {
                let mut choices = picks(0);
                choices[3].selected = vec![sel];
                let mut rho = [0u8; 32];
                rho[0] = i as u8 + 1;
                let id = BallotId {
                    machine_id: "M-S1-01".into(),
                    session_id: "S-1".into(),
                    seq: i as u64 + 1,
                };
                let ballot = encrypt_ballot(&mut rng, &election, &offered, &id, &rho, &choices)
                    .expect("encrypt");
                mix_row(&ballot, 3)
            })
            .collect();

        let (out, _witness) = shuffle(&mut rng, &ctx.k, &rows);
        let target = [6u8; 32];
        let items = mix_list_items(&out);
        let sets: Vec<DecryptionShareSet> = (0..3)
            .map(|j| {
                DecryptionShareSet::create(
                    &mut rng,
                    &ctx.hash(),
                    &target,
                    j as u64 + 1,
                    &zs[j],
                    &items,
                )
            })
            .collect();
        let combined = combine(&ctx, 2, &items, &sets).unwrap();

        let width = out[0].len();
        let decoded: Vec<Vec<Option<u64>>> = combined
            .plaintext_points
            .chunks(width)
            .map(|row| {
                row.iter()
                    .map(|p| decode_slot(p, mix_contest.options.len()))
                    .collect()
            })
            .collect();
        let counts = count_mix_rows(&[mix_contest], &decoded);
        assert_eq!(counts.len(), 1);
        let mut votes = vec![0u64; mix_contest.options.len()];
        votes[0] = 1;
        votes[2] = 1;
        votes[blank as usize] = 1;
        votes[null as usize] = 1;
        assert_eq!(
            counts[0],
            MixCount {
                contest: 3,
                votes,
                counted: 4,
                invalid: 0,
            }
        );
    }

    fn replace(v: &Value, key: u64, new: Value) -> Value {
        match v {
            Value::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|(k, x)| {
                        if *k == Value::Uint(key) {
                            (k.clone(), new.clone())
                        } else {
                            (k.clone(), x.clone())
                        }
                    })
                    .collect(),
            ),
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn election_result_sign_and_open() {
        let (manifest, keys) = sample_manifest(1);
        let seat = SeatAllocation {
            rule: "dhondt".into(),
            seats_per_list: vec![(0, 2), (1, 1)],
            elected: vec![0, 1, 4],
            qe: None,
            unfilled: 0,
        };
        let result = ElectionResult {
            context_hash: [9; 32],
            tree_size: 5,
            contests: vec![
                ContestResult {
                    contest: 0,
                    votes: vec![2, 1, 0, 0],
                    counted: 3,
                    invalid: 0,
                    excluded: 1,
                    party_totals: None,
                    seats: None,
                },
                ContestResult {
                    contest: 2,
                    votes: vec![3, 2],
                    counted: 5,
                    invalid: 0,
                    excluded: 0,
                    party_totals: Some(vec![(0, 3), (1, 2)]),
                    seats: Some(seat),
                },
            ],
            sections: vec![SectionResult {
                section_id: "S1".into(),
                pre_bu_id: [1; 32],
                final_bu_id: [2; 32],
                contests: vec![(0, 3, vec![2, 1, 0, 0])],
                excluded: vec![(0, 1)],
                matches: true,
            }],
            pool: vec![(4, 2, vec![1, 1])],
        };
        let signed = result.sign(&keys.ea);
        let back = ElectionResult::from_signed(&signed, &manifest.ea_key, &manifest).unwrap();
        assert_eq!(back, result);

        let other = keys.board.verifying_key();
        assert!(ElectionResult::from_signed(&signed, &other, &manifest).is_err());
        let tampered = replace(&signed, 3, Value::Uint(6));
        assert!(ElectionResult::from_signed(&tampered, &manifest.ea_key, &manifest).is_err());
    }

    #[test]
    fn section_result_strict_decode() {
        let s = SectionResult {
            section_id: "S1".into(),
            pre_bu_id: [1; 32],
            final_bu_id: [2; 32],
            contests: vec![],
            excluded: vec![],
            matches: false,
        };
        let v = s.to_value();
        assert_eq!(SectionResult::from_value(&v).unwrap(), s);
        let bad = replace(&v, 6, Value::from("maybe"));
        assert!(SectionResult::from_value(&bad).is_err());
    }

    #[test]
    fn final_bu_round_trip_rejects_wrong_tag() {
        let mut rng = rng(6);
        let key = SigningKey::generate(&mut rng);
        let set = DecryptionShareSet {
            context_hash: [1; 32],
            target: [3; 32],
            trustee: 1,
            shares: vec![(
                B,
                CpProof {
                    c: Scalar::ZERO,
                    v: Scalar::ZERO,
                },
            )],
        };
        let fb = FinalBu {
            context_hash: [1; 32],
            pre_bu_id: [2; 32],
            section_tally_id: [3; 32],
            results: vec![(0, 2, vec![1, 1])],
            share_sets: vec![set.sign(&key)],
        };
        assert_eq!(FinalBu::from_value(&fb.to_value()).unwrap(), fb);
        let mut no_sets = fb.clone();
        no_sets.share_sets.clear();
        assert!(FinalBu::from_value(&no_sets.to_value()).is_err());
        assert!(FinalBu::from_value(
            &SectionResult {
                section_id: String::new(),
                pre_bu_id: [0; 32],
                final_bu_id: [0; 32],
                contests: vec![],
                excluded: vec![],
                matches: true,
            }
            .to_value()
        )
        .is_err());
    }
}
