//! Homomorphic tally (SPEC.md §12.6 α reservation, §18).
//!
//! Three steps, in order:
//!
//! 1. [`judge_cast`] judges each cast ballot with the proof checks of §12.6 and
//!    the α reservation across ballots (board order, then package order).
//! 2. [`sum_ballots`] adds the ciphertexts of the counted contests per option,
//!    giving the section tally of §18.1 (split by [`split_pooled`]).
//! 3. [`SectionTally`], [`PoolTally`] and [`EncryptedTally`] are the published
//!    records of §18.1 to §18.3. [`fingerprint`] is the subtotal fingerprint of
//!    §18.1 that goes on the pre-BU.
//!
//! All records here are unsigned, strictly decoded, and carry version 1.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};

use crate::ballot::{Ballot, ContestBallot, ContestStatus, Election};
use crate::cbor::{record_fields, Value};
use crate::elgamal::Ciphertext;
use crate::error::Error;
use crate::group::RistrettoPoint;
use crate::hash::digest;
use crate::manifest::{bytes32, decode_list, expect_version, record, schema, uint_item, Method};

/// Version of every tally record (§6.3).
const VERSION: u64 = 1;

/// α reservation across ballots (§12.6). Holds the compressed α values already
/// reserved by counted contests. Ballots must be judged in board order, then
/// package order, with the same `Reservations`.
#[derive(Clone, Debug, Default)]
pub struct Reservations {
    /// Compressed α bytes.
    seen: HashSet<[u8; 32]>,
}

impl Reservations {
    /// An empty reservation set.
    pub fn new() -> Reservations {
        Reservations::default()
    }

    /// For a contest whose proofs passed: if any α is already reserved, or two
    /// α inside this contest are equal, returns `false` and reserves nothing.
    /// Otherwise reserves all of them and returns `true`.
    pub fn try_reserve(&mut self, alphas: &[RistrettoPoint]) -> bool {
        let keys: Vec<[u8; 32]> = alphas.iter().map(|a| a.compress().to_bytes()).collect();
        let mut local = HashSet::with_capacity(keys.len());
        let clash = keys
            .iter()
            .any(|k| self.seen.contains(k) || !local.insert(*k));
        if clash {
            return false;
        }
        self.seen.extend(keys);
        true
    }
}

/// Outcome of judging one cast ballot with reservations applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JudgedBallot {
    /// `Err(reason)` if the ballot is not well-formed (§12.6 rules 1 to 4).
    pub well_formed: Result<(), String>,
    /// Status of each offered contest, ascending. Empty if not well-formed.
    pub contests: Vec<(u64, ContestStatus)>,
}

/// Judges one cast ballot (§12.6): [`crate::ballot::check_ballot`], then α
/// reservation, then the link group rule.
///
/// Reservation runs per contest in ascending order. A contest whose proofs pass
/// reserves its α values. If one of them is already reserved, the contest is
/// excluded with "α already reserved".
///
/// Link groups: if any contest of a group is excluded, every counted contest of
/// that group on the ballot is excluded too. A contest that passed its proofs
/// and reserved its α keeps that reservation even when its group-mates are
/// then excluded. This is deliberately conservative: those α are still burned
/// for later ballots, since the spec reserves on proof success, not on counting.
pub fn judge_cast(
    election: &Election,
    offered: &[u64],
    ballot: &Ballot,
    reservations: &mut Reservations,
) -> JudgedBallot {
    let check = crate::ballot::check_ballot(election, offered, ballot);
    if let Err(reason) = check.well_formed {
        return JudgedBallot {
            well_formed: Err(reason),
            contests: Vec::new(),
        };
    }
    let mut contests = check.contests;

    for (c, status) in contests.iter_mut() {
        if *status != ContestStatus::Counted {
            continue;
        }
        if !reservations.try_reserve(&ballot.alphas(*c)) {
            *status = ContestStatus::Excluded("α already reserved".into());
        }
    }

    for group in &election.manifest.link_groups {
        let members: Vec<usize> = contests
            .iter()
            .enumerate()
            .filter(|(_, (c, _))| group.contests.contains(c))
            .map(|(i, _)| i)
            .collect();
        let reason = members.iter().find_map(|&i| match &contests[i].1 {
            ContestStatus::Excluded(r) => Some(r.clone()),
            ContestStatus::Counted => None,
        });
        if let Some(reason) = reason {
            for &i in &members {
                if contests[i].1 == ContestStatus::Counted {
                    contests[i].1 =
                        ContestStatus::Excluded(format!("link group {}: {reason}", group.index));
                }
            }
        }
    }

    JudgedBallot {
        well_formed: Ok(()),
        contests,
    }
}

/// Encrypted per-option sums for one homomorphic contest (§18.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContestSum {
    /// Contest index.
    pub contest: u64,
    /// Number of ballots whose contest is counted.
    pub counted: u64,
    /// One ciphertext per option (placeholders excluded).
    pub sums: Vec<Ciphertext>,
}

impl ContestSum {
    /// Encodes as `[uint, uint, [+ [point, point]]]` (§18.1).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.contest),
            Value::Uint(self.counted),
            Value::Array(self.sums.iter().map(Ciphertext::to_value).collect()),
        ])
    }

    /// Strict decode of `[uint, uint, [+ [point, point]]]`.
    pub fn from_value(v: &Value) -> Result<ContestSum, Error> {
        match v.as_array()? {
            [c, n, sums] => Ok(ContestSum {
                contest: c.as_uint()?,
                counted: n.as_uint()?,
                sums: decode_list(sums, 1, "contest sums", Ciphertext::from_value)?,
            }),
            _ => Err(schema(
                "contest sum must be [uint, uint, [+ [point, point]]]",
            )),
        }
    }
}

/// Sums the homomorphic contests over the given judged cast ballots (§18.1).
///
/// Each pair must be a ballot with its own [`judge_cast`] result. A contest
/// contributes only for ballots where it is counted. The output covers every
/// homomorphic contest that appears in any judged list, even with `counted = 0`.
/// It is in ascending contest index, and each sum has one ciphertext per option
/// (the first `m` selections of the contest; placeholders are excluded).
pub fn sum_ballots(election: &Election, ballots: &[(&Ballot, &JudgedBallot)]) -> Vec<ContestSum> {
    let mut contests: Vec<u64> = ballots
        .iter()
        .flat_map(|(_, judged)| judged.contests.iter().map(|(c, _)| *c))
        .collect();
    contests.sort_unstable();
    contests.dedup();

    contests
        .into_iter()
        .filter_map(|c| {
            let def = election.manifest.contest(c)?;
            if def.method != Method::Homomorphic {
                return None;
            }
            let mut sum = ContestSum {
                contest: c,
                counted: 0,
                sums: vec![Ciphertext::zero(); def.options.len()],
            };
            for (ballot, judged) in ballots {
                let counted = matches!(
                    judged.contests.iter().find(|(x, _)| *x == c),
                    Some((_, ContestStatus::Counted))
                );
                if !counted {
                    continue;
                }
                let Some(ContestBallot::Hom { selections, .. }) =
                    ballot.contests.iter().find(|cb| cb.contest() == c)
                else {
                    continue;
                };
                for (acc, (ct, _)) in sum.sums.iter_mut().zip(selections) {
                    *acc += *ct;
                }
                sum.counted += 1;
            }
            Some(sum)
        })
        .collect()
}

/// Splits sums by `min_section_ballots` (§18.1). Returns the kept sums and the
/// pooled sums, both ascending. A contest with fewer than `min_section_ballots`
/// counted ballots is pooled: it leaves the section tally (whose field 7 lists
/// [`indices`] of the pooled sums) and is added to the pool (§18.2) with
/// [`merge_sums`].
pub fn split_pooled(
    sums: Vec<ContestSum>,
    min_section_ballots: u64,
) -> (Vec<ContestSum>, Vec<ContestSum>) {
    let mut sums = sums;
    sums.sort_by_key(|s| s.contest);
    sums.into_iter()
        .partition(|s| s.counted >= min_section_ballots)
}

/// Contest indices of a list of sums, in order.
pub fn indices(sums: &[ContestSum]) -> Vec<u64> {
    sums.iter().map(|s| s.contest).collect()
}

/// Adds sums contest-wise (§18.2). Output is ascending and includes every
/// contest of either input.
///
/// # Panics
///
/// If the same contest has a different number of options in the two inputs.
/// Both come from the same manifest, so this is a programming error.
pub fn merge_sums(a: &[ContestSum], b: &[ContestSum]) -> Vec<ContestSum> {
    let mut out: BTreeMap<u64, ContestSum> = BTreeMap::new();
    for s in a.iter().chain(b) {
        match out.entry(s.contest) {
            Entry::Vacant(e) => {
                e.insert(s.clone());
            }
            Entry::Occupied(mut e) => {
                let acc = e.get_mut();
                assert_eq!(
                    acc.sums.len(),
                    s.sums.len(),
                    "contest {} has different option counts",
                    s.contest
                );
                acc.counted += s.counted;
                for (x, y) in acc.sums.iter_mut().zip(&s.sums) {
                    *x += *y;
                }
            }
        }
    }
    out.into_values().collect()
}

/// A recovered package imported into a session (`imported`, §16.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// RecordId of the recovered package.
    pub package_id: [u8; 32],
    /// Its cast count.
    pub cast: u64,
    /// Its last chain head.
    pub last_head: [u8; 32],
}

impl Imported {
    /// Encodes as `[digest, uint, digest]` (§16.2).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::from(self.package_id),
            Value::Uint(self.cast),
            Value::from(self.last_head),
        ])
    }

    /// Strict decode of `[digest, uint, digest]` (§16.2).
    pub fn from_value(v: &Value) -> Result<Imported, Error> {
        match v.as_array()? {
            [p, c, h] => Ok(Imported {
                package_id: bytes32(p)?,
                cast: c.as_uint()?,
                last_head: bytes32(h)?,
            }),
            _ => Err(schema("imported must be [digest, uint, digest]")),
        }
    }
}

/// Subtotal fingerprint (§18.1):
/// `Digest("eg/v1/subtotal", context_hash, machine_id, session_id,
/// pre_bu field 6, section_tally field 6, section_tally field 7)`.
///
/// `imported` is pre-BU field 6, `kept` is section tally field 6 and `pooled`
/// is section tally field 7.
pub fn fingerprint(
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    imported: &[Imported],
    kept: &[ContestSum],
    pooled: &[u64],
) -> [u8; 32] {
    digest(
        "eg/v1/subtotal",
        &[
            Value::from(*context_hash),
            Value::from(machine_id),
            Value::from(session_id),
            Value::Array(imported.iter().map(Imported::to_value).collect()),
            Value::Array(kept.iter().map(ContestSum::to_value).collect()),
            Value::Array(pooled.iter().map(|&c| Value::Uint(c)).collect()),
        ],
    )
}

/// Section tally (`section_tally`, §18.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionTally {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: RecordId of the pre-BU.
    pub pre_bu_id: [u8; 32],
    /// Field 4: section identifier.
    pub section_id: String,
    /// Field 5: RecordId of the pre-BU's package, then of each imported package.
    pub packages: Vec<[u8; 32]>,
    /// Field 6: contests not pooled, ascending.
    pub contests: Vec<ContestSum>,
    /// Field 7: pooled contest indices, ascending.
    pub pooled: Vec<u64>,
}

impl SectionTally {
    /// Encodes the record as in §18.1.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("section_tally")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.pre_bu_id)),
            (4, Value::from(self.section_id.as_str())),
            (
                5,
                Value::Array(self.packages.iter().map(|d| Value::from(*d)).collect()),
            ),
            (
                6,
                Value::Array(self.contests.iter().map(ContestSum::to_value).collect()),
            ),
            (
                7,
                Value::Array(self.pooled.iter().map(|&c| Value::Uint(c)).collect()),
            ),
        ])
    }

    /// Strict decode (§18.1). Requires `packages` to be non-empty and both
    /// index lists to be strictly ascending.
    pub fn from_value(v: &Value) -> Result<SectionTally, Error> {
        let f = record_fields(v, "section_tally", 8)?;
        expect_version(f[1])?;
        let packages = decode_list(f[5], 1, "packages", bytes32)?;
        let contests = decode_list(f[6], 0, "contests", ContestSum::from_value)?;
        check_ascending(contests.iter().map(|s| s.contest), "section tally contests")?;
        let pooled = decode_list(f[7], 0, "pooled", uint_item)?;
        check_ascending(pooled.iter().copied(), "section tally pooled")?;
        Ok(SectionTally {
            context_hash: bytes32(f[2])?,
            pre_bu_id: bytes32(f[3])?,
            section_id: f[4].as_text()?.to_owned(),
            packages,
            contests,
            pooled,
        })
    }

    /// RecordId of this section tally (§15.5).
    pub fn record_id(&self) -> [u8; 32] {
        crate::board::record_id(&self.to_value())
    }
}

/// Pool tally (`pool_tally`, §18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolTally {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: tree size at `tally_cutoff`.
    pub tree_size: u64,
    /// Field 4: per homomorphic contest, ascending.
    pub contests: Vec<ContestSum>,
}

impl PoolTally {
    /// Encodes the record as in §18.2.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("pool_tally")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::Uint(self.tree_size)),
            (
                4,
                Value::Array(self.contests.iter().map(ContestSum::to_value).collect()),
            ),
        ])
    }

    /// Strict decode (§18.2). Contest indices must be strictly ascending.
    pub fn from_value(v: &Value) -> Result<PoolTally, Error> {
        let f = record_fields(v, "pool_tally", 5)?;
        expect_version(f[1])?;
        let contests = decode_list(f[4], 0, "pool contests", ContestSum::from_value)?;
        check_ascending(contests.iter().map(|s| s.contest), "pool contests")?;
        Ok(PoolTally {
            context_hash: bytes32(f[2])?,
            tree_size: f[3].as_uint()?,
            contests,
        })
    }
}

/// Encrypted tally index (`encrypted_tally`, §18.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTally {
    /// Field 2: context hash.
    pub context_hash: [u8; 32],
    /// Field 3: STH root at `tally_cutoff`.
    pub sth_root: [u8; 32],
    /// Field 4: tree size at `tally_cutoff`.
    pub tree_size: u64,
    /// Field 5: RecordId of every section tally, board order.
    pub section_tallies: Vec<[u8; 32]>,
    /// Field 6: RecordId of the pool tally.
    pub pool: [u8; 32],
}

impl EncryptedTally {
    /// Encodes the record as in §18.3.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("encrypted_tally")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.sth_root)),
            (4, Value::Uint(self.tree_size)),
            (
                5,
                Value::Array(
                    self.section_tallies
                        .iter()
                        .map(|d| Value::from(*d))
                        .collect(),
                ),
            ),
            (6, Value::from(self.pool)),
        ])
    }

    /// Strict decode (§18.3).
    pub fn from_value(v: &Value) -> Result<EncryptedTally, Error> {
        let f = record_fields(v, "encrypted_tally", 7)?;
        expect_version(f[1])?;
        Ok(EncryptedTally {
            context_hash: bytes32(f[2])?,
            sth_root: bytes32(f[3])?,
            tree_size: f[4].as_uint()?,
            section_tallies: decode_list(f[5], 0, "section tallies", bytes32)?,
            pool: bytes32(f[6])?,
        })
    }
}

/// Checks that indices are strictly ascending (canonical order).
fn check_ascending(indices: impl Iterator<Item = u64>, what: &str) -> Result<(), Error> {
    let v: Vec<u64> = indices.collect();
    if v.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(schema(format!("{what} must be strictly ascending")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{encrypt_ballot, BallotId, ContestPlain};
    use crate::cbor;
    use crate::elgamal::dlog_bounded;
    use crate::fixtures::{sample_manifest, sample_registry};
    use crate::group::{random_scalar, Scalar, B};
    use crate::manifest::Manifest;
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

    /// Choices for contests 0..=5 of the sample manifest, for voter `i` (0..5).
    /// Contests 4 and 5 are one link group, so they never pick the same candidate.
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

    fn cast(st: &Setup, rng: &mut ChaCha20Rng, seq: u64, choices: &[ContestPlain]) -> Ballot {
        let e = election(st);
        let rho = rho_of(rng);
        encrypt_ballot(rng, &e, &st.offered, &bid(seq), &rho, choices).expect("encrypt")
    }

    fn open(st: &Setup, cs: &ContestSum) -> Vec<u64> {
        cs.sums
            .iter()
            .map(|ct| dlog_bounded(&ct.decrypt_to_point(&st.s), 100).expect("small"))
            .collect()
    }

    fn judge_all(st: &Setup, ballots: &[Ballot]) -> Vec<JudgedBallot> {
        let e = election(st);
        let mut r = Reservations::new();
        ballots
            .iter()
            .map(|b| judge_cast(&e, &st.offered, b, &mut r))
            .collect()
    }

    fn all_counted(j: &JudgedBallot) -> bool {
        j.well_formed == Ok(()) && j.contests.iter().all(|(_, s)| *s == ContestStatus::Counted)
    }

    fn ct(n: u64) -> Ciphertext {
        Ciphertext {
            alpha: Scalar::from(n) * B,
            beta: Scalar::from(n + 1) * B,
        }
    }

    fn sample_sum(contest: u64, counted: u64, options: usize) -> ContestSum {
        ContestSum {
            contest,
            counted,
            sums: (0..options as u64).map(|i| ct(i + contest)).collect(),
        }
    }

    /// Re-encodes through canonical CBOR and checks the bytes are stable.
    fn canonical(v: &Value) -> Value {
        let bytes = cbor::encode(v);
        let back = cbor::decode(&bytes).expect("decodes");
        assert_eq!(cbor::encode(&back), bytes, "canonical");
        back
    }

    #[test]
    fn sums_decrypt_to_counts_and_exclude_placeholders() {
        let st = setup();
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        let ballots: Vec<Ballot> = (0..5)
            .map(|i| cast(&st, &mut rng, i as u64 + 1, &picks(i)))
            .collect();
        let judged = judge_all(&st, &ballots);
        assert!(judged.iter().all(all_counted));

        let pairs: Vec<(&Ballot, &JudgedBallot)> = ballots.iter().zip(&judged).collect();
        let sums = sum_ballots(&election(&st), &pairs);
        let ids: Vec<u64> = sums.iter().map(|s| s.contest).collect();
        assert_eq!(ids, vec![0, 1, 2, 4, 5], "homomorphic contests only");
        assert!(sums.iter().all(|s| s.counted == 5));

        let by = |c: u64| sums.iter().find(|s| s.contest == c).expect("contest");
        assert_eq!(open(&st, by(0)), vec![1, 3, 0, 1, 0]);
        // Multi: five options, two placeholders excluded from the sum.
        assert_eq!(by(1).sums.len(), 5);
        assert_eq!(open(&st, by(1)), vec![1, 1, 1, 1, 1]);
        // Proportional: eight options.
        assert_eq!(by(2).sums.len(), 8);
        assert_eq!(open(&st, by(2)), vec![1, 0, 0, 0, 3, 0, 0, 1]);
        assert_eq!(open(&st, by(4)), vec![3, 1, 0, 0, 1]);
        assert_eq!(open(&st, by(5)), vec![0, 1, 3, 0, 1]);
    }

    #[test]
    fn excluded_contest_does_not_count_but_others_do() {
        let st = setup();
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        let honest: Vec<Ballot> = (0..5)
            .map(|i| cast(&st, &mut rng, i as u64 + 1, &picks(i)))
            .collect();
        let donor = cast(&st, &mut rng, 90, &picks(2));
        let mut bad = cast(&st, &mut rng, 91, &picks(0));
        // Replace contest 0's sum proof with one from another ballot, so it fails.
        let ContestBallot::Hom {
            sum_proof: donor_sum,
            ..
        } = donor.contests[0].clone()
        else {
            panic!("contest 0 is homomorphic")
        };
        if let ContestBallot::Hom { sum_proof, .. } = &mut bad.contests[0] {
            *sum_proof = donor_sum;
        }
        let bad = Ballot::from_value(&bad.to_value()).expect("decodes");

        let mut all = honest.clone();
        all.push(bad);
        let judged = judge_all(&st, &all);
        let status0 = &judged[5].contests[0];
        assert_eq!(status0.0, 0);
        assert!(matches!(status0.1, ContestStatus::Excluded(_)));
        assert!(judged[5].contests[1..]
            .iter()
            .all(|(_, s)| *s == ContestStatus::Counted));

        let pairs: Vec<(&Ballot, &JudgedBallot)> = all.iter().zip(&judged).collect();
        let sums = sum_ballots(&election(&st), &pairs);
        let by = |c: u64| sums.iter().find(|s| s.contest == c).expect("contest");
        // Contest 0: the bad ballot is out, so five counted, as for honest voters only.
        assert_eq!(by(0).counted, 5);
        assert_eq!(open(&st, by(0)), vec![1, 3, 0, 1, 0]);
        // Contest 1: all six ballots count.
        assert_eq!(by(1).counted, 6);
    }

    #[test]
    fn same_ballot_cast_twice_is_excluded_by_reservation() {
        let st = setup();
        let e = election(&st);
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let b = cast(&st, &mut rng, 1, &picks(0));
        let mut r = Reservations::new();
        assert!(all_counted(&judge_cast(&e, &st.offered, &b, &mut r)));
        let second = judge_cast(&e, &st.offered, &b, &mut r);
        assert_eq!(second.well_formed, Ok(()));
        assert_eq!(second.contests.len(), st.offered.len());
        assert!(second
            .contests
            .iter()
            .all(|(_, s)| *s == ContestStatus::Excluded("α already reserved".into())));
    }

    #[test]
    fn ballot_with_failing_proofs_reserves_nothing() {
        let st = setup();
        let e = election(&st);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let honest = cast(&st, &mut rng, 1, &picks(0));
        let donor = cast(&st, &mut rng, 2, &picks(3));

        // Same ciphertexts as the honest ballot, but every contest's proof is wrong.
        let mut bad = honest.clone();
        for (cb, d) in bad.contests.iter_mut().zip(&donor.contests) {
            match (cb, d) {
                (
                    ContestBallot::Hom { sum_proof, .. },
                    ContestBallot::Hom {
                        sum_proof: donor_sum,
                        ..
                    },
                ) => *sum_proof = *donor_sum,
                (
                    ContestBallot::Mix { slots, .. },
                    ContestBallot::Mix {
                        slots: donor_slots, ..
                    },
                ) => slots[0].1 = donor_slots[0].1,
                _ => panic!("same manifest"),
            }
        }
        let bad = Ballot::from_value(&bad.to_value()).expect("decodes");

        let mut r = Reservations::new();
        let judged_bad = judge_cast(&e, &st.offered, &bad, &mut r);
        assert!(judged_bad
            .contests
            .iter()
            .all(|(_, s)| matches!(s, ContestStatus::Excluded(_))));

        let judged_honest = judge_cast(&e, &st.offered, &honest, &mut r);
        assert!(all_counted(&judged_honest), "{judged_honest:?}");
    }

    #[test]
    fn reservation_is_all_or_nothing_within_a_contest() {
        let mut r = Reservations::new();
        let a = ct(1).alpha;
        let b = ct(2).alpha;
        // Two equal α inside one contest: nothing reserved.
        assert!(!r.try_reserve(&[a, a]));
        assert!(r.try_reserve(&[a, b]));
        // Shares α with the first: refused, and nothing new reserved.
        let c = ct(3).alpha;
        assert!(!r.try_reserve(&[c, b]));
        assert!(r.try_reserve(&[c]));
    }

    #[test]
    fn split_pooled_threshold() {
        let sums = vec![
            sample_sum(4, 5, 2),
            sample_sum(0, 2, 3),
            sample_sum(2, 3, 1),
        ];
        let (kept, pooled) = split_pooled(sums.clone(), 3);
        assert_eq!(
            kept.iter().map(|s| s.contest).collect::<Vec<_>>(),
            vec![2, 4]
        );
        assert_eq!(indices(&pooled), vec![0]);
        assert_eq!(pooled[0], sums[1]);
        assert_eq!(kept[0], sums[2]);

        let (kept, pooled) = split_pooled(sums.clone(), 0);
        assert_eq!(kept.len(), 3);
        assert!(pooled.is_empty());

        let (kept, pooled) = split_pooled(sums, 6);
        assert!(kept.is_empty());
        assert_eq!(indices(&pooled), vec![0, 2, 4]);
    }

    #[test]
    fn merge_sums_adds_contest_wise() {
        let a = vec![sample_sum(0, 2, 2), sample_sum(3, 1, 1)];
        let b = vec![sample_sum(0, 1, 2), sample_sum(5, 4, 3)];
        let m = merge_sums(&a, &b);
        assert_eq!(
            m.iter().map(|s| s.contest).collect::<Vec<_>>(),
            vec![0, 3, 5]
        );
        assert_eq!(m[0].counted, 3);
        assert_eq!(m[0].sums[0], ct(0) + ct(0));
        assert_eq!(m[0].sums[1], ct(1) + ct(1));
        assert_eq!(m[1], a[1]);
        assert_eq!(m[2], b[1]);
        assert!(merge_sums(&[], &[]).is_empty());
    }

    #[test]
    fn fingerprint_binds_every_input() {
        let imp = vec![Imported {
            package_id: [7; 32],
            cast: 2,
            last_head: [8; 32],
        }];
        let kept = vec![sample_sum(0, 2, 2)];
        let pooled = vec![3u64];
        let base = fingerprint(&CTX, "M-1", "S-1", &imp, &kept, &pooled);

        let expected = digest(
            "eg/v1/subtotal",
            &[
                Value::from(CTX),
                Value::from("M-1"),
                Value::from("S-1"),
                Value::Array(vec![imp[0].to_value()]),
                Value::Array(vec![kept[0].to_value()]),
                Value::Array(vec![Value::Uint(3)]),
            ],
        );
        assert_eq!(base, expected);

        let mut other_imp = imp.clone();
        other_imp[0].cast = 3;
        let mut other_kept = kept.clone();
        other_kept[0].counted = 1;
        let variants = [
            fingerprint(&[1; 32], "M-1", "S-1", &imp, &kept, &pooled),
            fingerprint(&CTX, "M-2", "S-1", &imp, &kept, &pooled),
            fingerprint(&CTX, "M-1", "S-2", &imp, &kept, &pooled),
            fingerprint(&CTX, "M-1", "S-1", &other_imp, &kept, &pooled),
            fingerprint(&CTX, "M-1", "S-1", &imp, &other_kept, &pooled),
            fingerprint(&CTX, "M-1", "S-1", &imp, &kept, &[4]),
            fingerprint(&CTX, "M-1", "S-1", &imp, &kept, &[]),
        ];
        for v in variants {
            assert_ne!(v, base);
        }
    }

    #[test]
    fn imported_round_trip_and_strictness() {
        let i = Imported {
            package_id: [1; 32],
            cast: 42,
            last_head: [2; 32],
        };
        let back = Imported::from_value(&canonical(&i.to_value())).expect("decodes");
        assert_eq!(back, i);
        let bad = Value::Array(vec![Value::from(i.package_id), Value::Uint(1)]);
        assert!(Imported::from_value(&bad).is_err());
    }

    #[test]
    fn section_tally_round_trip_and_strictness() {
        let t = SectionTally {
            context_hash: CTX,
            pre_bu_id: [2; 32],
            section_id: "S-1".into(),
            packages: vec![[3; 32], [4; 32]],
            contests: vec![
                ContestSum {
                    contest: 0,
                    counted: 2,
                    sums: vec![ct(1), Ciphertext::zero()],
                },
                sample_sum(2, 0, 3),
            ],
            pooled: vec![1, 4],
        };
        let v = canonical(&t.to_value());
        assert_eq!(SectionTally::from_value(&v).expect("decodes"), t);
        assert_eq!(t.record_id(), crate::board::record_id(&t.to_value()));

        // Wrong version.
        let mut f = record_fields(&t.to_value(), "section_tally", 8)
            .expect("fields")
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        f[1] = Value::Uint(2);
        let wrong_version = record(
            f.into_iter()
                .enumerate()
                .map(|(i, v)| (i as u64, v))
                .collect(),
        );
        assert!(SectionTally::from_value(&wrong_version).is_err());

        // Pooled indices out of order.
        let mut unsorted = t.clone();
        unsorted.pooled = vec![4, 1];
        assert!(SectionTally::from_value(&unsorted.to_value()).is_err());

        // Empty packages.
        let mut no_pkg = t.clone();
        no_pkg.packages = vec![];
        assert!(SectionTally::from_value(&no_pkg.to_value()).is_err());
    }

    #[test]
    fn pool_and_encrypted_tally_round_trip() {
        let p = PoolTally {
            context_hash: CTX,
            tree_size: 17,
            contests: vec![sample_sum(1, 0, 2), sample_sum(3, 4, 5)],
        };
        let back = PoolTally::from_value(&canonical(&p.to_value())).expect("decodes");
        assert_eq!(back, p);

        let mut unsorted = p.clone();
        unsorted.contests.reverse();
        assert!(PoolTally::from_value(&unsorted.to_value()).is_err());

        let e = EncryptedTally {
            context_hash: CTX,
            sth_root: [5; 32],
            tree_size: 17,
            section_tallies: vec![[6; 32], [7; 32]],
            pool: [8; 32],
        };
        let back = EncryptedTally::from_value(&canonical(&e.to_value())).expect("decodes");
        assert_eq!(back, e);

        let empty = EncryptedTally {
            section_tallies: vec![],
            ..e
        };
        assert_eq!(
            EncryptedTally::from_value(&canonical(&empty.to_value())).expect("decodes"),
            empty
        );
    }
}
