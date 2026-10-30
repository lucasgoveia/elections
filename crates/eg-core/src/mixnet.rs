//! Mixnet orchestration (SPEC.md §19.1 mix units, region merging and input
//! lists; §19.2 mixer chain rules; §23 step 10 checks).
//!
//! The shuffle primitive and its proof live in [`crate::shuffle`]. This module
//! decides which rows each mix unit mixes, runs or checks the chain of mixers,
//! and hands the final list to the decryption stage (§19.4).

use std::collections::BTreeSet;

use rand_core::{CryptoRng, RngCore};

use crate::ballot::{Ballot, ContestBallot, ContestStatus};
use crate::cbor::Value;
use crate::ceremony::Context;
use crate::error::Error;
use crate::manifest::{Manifest, Method};
use crate::registry::Registry;
use crate::shuffle::{
    list_digest, prove_shuffle, shuffle, verify_shuffle, MixOutput, Row, ShuffleStatement,
};
use crate::sign::SigningKey;
use crate::tally::JudgedBallot;

fn tally(msg: impl Into<String>) -> Error {
    Error::Tally(msg.into())
}

/// A mix unit (§19.1): a mixnet contest outside any link group, or a mixnet link
/// group, plus a region ("" if not regional).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixUnit {
    /// Contest indices of the unit, ascending.
    pub contests: Vec<u64>,
    /// Region of the unit, possibly merged ("A+B"), or "" if not regional.
    pub region: String,
    /// The registry regions the unit covers (sorted by name).
    pub regions: Vec<String>,
}

impl MixUnit {
    /// The lowest contest index of the unit. With `region`, this identifies the
    /// unit (§19.2, §19.3).
    pub fn contest_index(&self) -> u64 {
        self.contests.first().copied().unwrap_or(0)
    }

    /// Width `w` = Σ L over the unit's contests (§19.1).
    pub fn width(&self, m: &Manifest) -> usize {
        self.contests
            .iter()
            .filter_map(|&c| m.contest(c))
            .map(|c| c.limit as usize)
            .sum()
    }
}

/// A cast ballot as seen by the mixnet: which section region it belongs to and
/// its judged status.
pub struct CastBallot<'a> {
    pub region: &'a str,
    pub ballot: &'a Ballot,
    pub judged: &'a JudgedBallot,
}

/// Sorted, distinct section regions of the registry.
fn registry_regions(registry: &Registry) -> Vec<String> {
    let set: BTreeSet<&str> = registry
        .sections
        .iter()
        .map(|s| s.region.as_str())
        .collect();
    set.into_iter().map(str::to_owned).collect()
}

/// True if the unit's contests use regional mixing (field 9). Link group members
/// agree on it (manifest rule 9).
fn is_regional(manifest: &Manifest, unit: &MixUnit) -> bool {
    unit.contests
        .first()
        .and_then(|&c| manifest.contest(c))
        .is_some_and(|c| c.regional_mix)
}

/// Mix units before merging: one per (unit contests, region) for regional units
/// (every region of the registry, sorted by name), or one with region "" covering
/// all regions. Units are ordered by contest index.
pub fn mix_units(manifest: &Manifest, registry: &Registry) -> Vec<MixUnit> {
    let regions = registry_regions(registry);
    let in_group: BTreeSet<u64> = manifest
        .link_groups
        .iter()
        .flat_map(|g| g.contests.iter().copied())
        .collect();

    // (contests, regional) for each mixnet contest outside a group and each
    // mixnet link group.
    let mut sets: Vec<(Vec<u64>, bool)> = Vec::new();
    for c in &manifest.contests {
        if c.method == Method::Mixnet && !in_group.contains(&c.index) {
            sets.push((vec![c.index], c.regional_mix));
        }
    }
    for g in &manifest.link_groups {
        let first = g.contests.first().and_then(|&ci| manifest.contest(ci));
        if let Some(c) = first.filter(|c| c.method == Method::Mixnet) {
            sets.push((g.contests.clone(), c.regional_mix));
        }
    }

    let mut units = Vec::new();
    for (contests, regional) in sets {
        if regional {
            for r in &regions {
                units.push(MixUnit {
                    contests: contests.clone(),
                    region: r.clone(),
                    regions: vec![r.clone()],
                });
            }
        } else {
            units.push(MixUnit {
                contests,
                region: String::new(),
                regions: regions.clone(),
            });
        }
    }
    units.sort_by(|a, b| {
        a.contest_index()
            .cmp(&b.contest_index())
            .then_with(|| a.region.cmp(&b.region))
    });
    units
}

/// Builds E^(0) for one unmerged unit set (§19.1). Rows follow the order of
/// `ballots` (the caller passes board-entry, then package, order). Only ballots
/// whose region is in `unit.regions` and whose unit contests are all counted are
/// included. Each row holds the slots of the unit's contests, contests ascending
/// and slots ascending.
pub fn input_rows(manifest: &Manifest, unit: &MixUnit, ballots: &[CastBallot]) -> Vec<Row> {
    let width = unit.width(manifest);
    let mut rows = Vec::new();
    'ballots: for cb in ballots {
        if !unit.regions.iter().any(|r| r == cb.region) {
            continue;
        }
        let mut row: Row = Vec::with_capacity(width);
        for &c in &unit.contests {
            let counted = cb
                .judged
                .contests
                .iter()
                .any(|(i, s)| *i == c && *s == ContestStatus::Counted);
            if !counted {
                continue 'ballots;
            }
            let Some(ContestBallot::Mix { slots, .. }) =
                cb.ballot.contests.iter().find(|x| x.contest() == c)
            else {
                continue 'ballots;
            };
            row.extend(slots.iter().map(|(ct, _)| *ct));
        }
        debug_assert_eq!(row.len(), width, "ballot slots do not match the unit width");
        rows.push(row);
    }
    rows
}

/// Region merging (§19.1 "Small regions") for the regional units of one contest
/// set. `counts` lists (region name, row count) sorted by name. While some group
/// has fewer than `min_region_rows` rows and more than one group remains, the
/// smallest such group (ties to the earlier name) is merged into its next
/// neighbour in sorted order, wrapping from last to first. Returns the final
/// groups, each a sorted list of original region names, ordered by first name.
pub fn merge_regions(counts: &[(String, u64)], min_region_rows: u64) -> Vec<Vec<String>> {
    fn by_first_name(a: &(Vec<String>, u64), b: &(Vec<String>, u64)) -> std::cmp::Ordering {
        a.0[0].cmp(&b.0[0])
    }

    let mut groups: Vec<(Vec<String>, u64)> = counts
        .iter()
        .map(|(name, rows)| (vec![name.clone()], *rows))
        .collect();
    groups.sort_by(by_first_name);

    while groups.len() > 1 {
        let small = (0..groups.len())
            .filter(|&i| groups[i].1 < min_region_rows)
            .min_by(|&a, &b| {
                groups[a]
                    .1
                    .cmp(&groups[b].1)
                    .then_with(|| groups[a].0[0].cmp(&groups[b].0[0]))
            });
        let Some(idx) = small else {
            break;
        };
        let len = groups.len();
        let neighbour = (idx + 1) % len;
        let (names, rows) = groups.remove(idx);
        // Removing `idx` shifts later groups down by one.
        let target = if neighbour > idx {
            neighbour - 1
        } else {
            neighbour
        };
        groups[target].0.extend(names);
        groups[target].0.sort();
        groups[target].1 += rows;
        groups.sort_by(by_first_name);
    }

    groups.into_iter().map(|(names, _)| names).collect()
}

/// Full plan for a tally: units after region merging, each with its input list
/// E^(0). Units with zero rows are included with an empty list (they are not
/// mixed, and their counts are 0). Sorted by contest index, then region.
pub fn plan(
    manifest: &Manifest,
    registry: &Registry,
    ballots: &[CastBallot],
) -> Vec<(MixUnit, Vec<Row>)> {
    let units = mix_units(manifest, registry);
    let min_rows = manifest.mix_policy.min_region_rows;
    let mut planned: Vec<(MixUnit, Vec<Row>)> = Vec::new();

    // Regional units of one contest set are merged together.
    let mut sets: Vec<Vec<u64>> = Vec::new();
    for u in units.iter().filter(|u| is_regional(manifest, u)) {
        if !sets.contains(&u.contests) {
            sets.push(u.contests.clone());
        }
    }
    for set in sets {
        let members: Vec<&MixUnit> = units
            .iter()
            .filter(|u| u.contests == set && is_regional(manifest, u))
            .collect();
        let counts: Vec<(String, u64)> = members
            .iter()
            .map(|u| {
                (
                    u.region.clone(),
                    input_rows(manifest, u, ballots).len() as u64,
                )
            })
            .collect();
        for names in merge_regions(&counts, min_rows) {
            let region = names.join("+");
            let unit = MixUnit {
                contests: set.clone(),
                region,
                regions: names,
            };
            let rows = input_rows(manifest, &unit, ballots);
            planned.push((unit, rows));
        }
    }

    for u in units.iter().filter(|u| !is_regional(manifest, u)) {
        let rows = input_rows(manifest, u, ballots);
        planned.push((u.clone(), rows));
    }

    planned.sort_by(|a, b| {
        a.0.contest_index()
            .cmp(&b.0.contest_index())
            .then_with(|| a.0.region.cmp(&b.0.region))
    });
    planned
}

/// Checks a unit's mix chain (§19.2, §23 step 10) and returns the final list.
///
/// The caller must already have verified each [`MixOutput`]'s signature (with
/// [`MixOutput::from_signed`]). This function checks:
///
/// - steps are numbered 1.. in order, with the unit's context, contest index and
///   region;
/// - each step's `input_digest` is `list_digest` of the previous list (the first
///   step's input is `input`);
/// - each mixer is a trustee, and mixers are in strictly ascending trustee index
///   order (which also makes them distinct);
/// - each shuffle proof verifies against the step's statement;
/// - at least `mix_policy.min_mixers` mixers took part.
///
/// A unit with no rows is not mixed: empty `input` with no outputs returns an
/// empty list.
pub fn check_mix_chain(
    context: &Context,
    manifest: &Manifest,
    unit: &MixUnit,
    input: &[Row],
    outputs: &[MixOutput],
) -> Result<Vec<Row>, Error> {
    if input.is_empty() {
        return if outputs.is_empty() {
            Ok(Vec::new())
        } else {
            Err(tally(format!(
                "unit {}/{:?} has no rows but has mix steps",
                unit.contest_index(),
                unit.region
            )))
        };
    }
    if outputs.is_empty() {
        return Err(tally(format!(
            "unit {}/{:?} has no mix steps",
            unit.contest_index(),
            unit.region
        )));
    }
    let min = manifest.mix_policy.min_mixers;
    if (outputs.len() as u64) < min {
        return Err(tally(format!(
            "unit {}/{:?}: {} mix steps, at least {min} required",
            unit.contest_index(),
            unit.region,
            outputs.len()
        )));
    }

    let context_hash = context.hash();
    let contest_index = unit.contest_index();
    let mut prev: &[Row] = input;
    let mut last_mixer: Option<u64> = None;
    for (i, out) in outputs.iter().enumerate() {
        let step = i as u64 + 1;
        let fail = |msg: &str| {
            tally(format!(
                "unit {contest_index}/{:?} step {step}: {msg}",
                unit.region
            ))
        };
        if out.step != step {
            return Err(fail("step number out of order"));
        }
        if out.context_hash != context_hash {
            return Err(fail("context hash does not match"));
        }
        if out.contest_index != contest_index || out.region != unit.region {
            return Err(fail("contest index or region does not match the unit"));
        }
        if out.input_digest != list_digest(prev) {
            return Err(fail("input digest does not match the previous list"));
        }
        if manifest.trustees.get(out.mixer).is_none() {
            return Err(fail("mixer is not a trustee"));
        }
        if last_mixer.is_some_and(|m| out.mixer <= m) {
            return Err(fail(
                "mixers must be distinct and in ascending trustee order",
            ));
        }
        last_mixer = Some(out.mixer);
        let st = ShuffleStatement {
            context_hash,
            contest_index,
            region: &unit.region,
            step,
            k: context.k,
            input: prev,
            output: &out.output,
        };
        if !verify_shuffle(&st, &out.proof) {
            return Err(fail("shuffle proof does not verify"));
        }
        prev = &out.output;
    }
    Ok(prev.to_vec())
}

/// Test and demo helper: runs the mix chain for `unit` over `input` with the
/// given mixers (trustee index, signing key), in the order given. Returns each
/// step's signed `mix_output` value with its parsed [`MixOutput`].
///
/// `input` must not be empty (a unit with no rows is not mixed).
pub fn run_mix_chain<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &Context,
    unit: &MixUnit,
    input: &[Row],
    mixers: &[(u64, &SigningKey)],
) -> Vec<(Value, MixOutput)> {
    let context_hash = context.hash();
    let contest_index = unit.contest_index();
    let mut current: Vec<Row> = input.to_vec();
    let mut chain = Vec::with_capacity(mixers.len());
    for (i, &(mixer, sk)) in mixers.iter().enumerate() {
        let step = i as u64 + 1;
        let input_digest = list_digest(&current);
        let (output, witness) = shuffle(rng, &context.k, &current);
        let proof = {
            let st = ShuffleStatement {
                context_hash,
                contest_index,
                region: &unit.region,
                step,
                k: context.k,
                input: &current,
                output: &output,
            };
            prove_shuffle(rng, &st, &witness)
        };
        let mo = MixOutput {
            context_hash,
            contest_index,
            mixer,
            step,
            input_digest,
            output: output.clone(),
            proof,
            region: unit.region.clone(),
        };
        let signed = mo.sign(sk);
        current = output;
        chain.push((signed, mo));
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{encrypt_ballot, BallotId, ContestPlain, Election};
    use crate::decrypt::{count_mix_rows, decode_slot};
    use crate::elgamal::Ciphertext;
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::group::{random_scalar, Scalar, B};
    use crate::tally::{judge_cast, Reservations};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn rho_of(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        r
    }

    fn unit(contests: Vec<u64>, region: &str, regions: &[&str]) -> MixUnit {
        MixUnit {
            contests,
            region: region.to_owned(),
            regions: regions.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn counts(v: &[(&str, u64)]) -> Vec<(String, u64)> {
        v.iter().map(|(n, r)| ((*n).to_owned(), *r)).collect()
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Choices for all six offered contests; `sel3` is the option for contest 3.
    fn choices(sel3: u64) -> Vec<ContestPlain> {
        let cp = |contest, selected: Vec<u64>| ContestPlain { contest, selected };
        vec![
            cp(0, vec![1]),
            cp(1, vec![1]),
            cp(2, vec![4]),
            cp(3, vec![sel3]),
            cp(4, vec![0]),
            cp(5, vec![1]),
        ]
    }

    fn region_of(registry: &Registry, machine: &str) -> String {
        let m = registry.machine(machine).expect("machine");
        registry
            .section(&m.section_id)
            .expect("section")
            .region
            .clone()
    }

    /// Encrypts and judges one ballot from `machine` choosing `sel3` in contest 3.
    fn cast(
        election: &Election,
        registry: &Registry,
        machine: &str,
        seq: u64,
        sel3: u64,
        reservations: &mut Reservations,
        rng: &mut ChaCha20Rng,
    ) -> (Ballot, JudgedBallot) {
        let offered = registry.machine(machine).expect("machine").contests.clone();
        let id = BallotId {
            machine_id: machine.into(),
            session_id: "S-1".into(),
            seq,
        };
        let rho = rho_of(rng);
        let ballot =
            encrypt_ballot(rng, election, &offered, &id, &rho, &choices(sel3)).expect("encrypt");
        let judged = judge_cast(election, &offered, &ballot, reservations);
        (ballot, judged)
    }

    fn regional_manifest() -> (Manifest, Keys) {
        sample_manifest(1)
    }

    fn non_regional_manifest() -> (Manifest, Keys) {
        let (mut m, keys) = sample_manifest(1);
        m.contests[3].regional_mix = false;
        (m, keys)
    }

    #[test]
    fn mix_units_regional_fixture_one_per_region() {
        let (manifest, keys) = regional_manifest();
        let registry = sample_registry(&manifest, &keys);
        let units = mix_units(&manifest, &registry);
        assert_eq!(
            units,
            vec![unit(vec![3], "RJ", &["RJ"]), unit(vec![3], "SP", &["SP"]),]
        );
    }

    #[test]
    fn mix_units_non_regional_single_unit() {
        let (manifest, keys) = non_regional_manifest();
        let registry = sample_registry(&manifest, &keys);
        let units = mix_units(&manifest, &registry);
        assert_eq!(units, vec![unit(vec![3], "", &["RJ", "SP"])]);
        assert_eq!(units[0].contest_index(), 3);
        assert_eq!(units[0].width(&manifest), 1);
    }

    #[test]
    fn mix_units_link_group_of_mixnet_contests() {
        let (mut manifest, keys) = non_regional_manifest();
        manifest.contests[4].method = Method::Mixnet;
        manifest.contests[5].method = Method::Mixnet;
        let registry = sample_registry(&manifest, &keys);
        let units = mix_units(&manifest, &registry);
        assert_eq!(
            units,
            vec![
                unit(vec![3], "", &["RJ", "SP"]),
                unit(vec![4, 5], "", &["RJ", "SP"]),
            ]
        );
        assert_eq!(units[1].width(&manifest), 2);
    }

    #[test]
    fn merge_small_region_into_next() {
        let c = counts(&[("A", 1), ("B", 10), ("C", 10)]);
        assert_eq!(
            merge_regions(&c, 5),
            vec![names(&["A", "B"]), names(&["C"])]
        );
    }

    #[test]
    fn merge_wraps_from_last_to_first() {
        let c = counts(&[("A", 10), ("B", 10), ("C", 1)]);
        assert_eq!(
            merge_regions(&c, 5),
            vec![names(&["A", "C"]), names(&["B"])]
        );
    }

    #[test]
    fn merge_ties_go_to_earlier_name() {
        let c = counts(&[("A", 1), ("B", 1), ("C", 10)]);
        // A and B tie; A is merged into B, then the pair (2 rows) into C.
        assert_eq!(merge_regions(&c, 5), vec![names(&["A", "B", "C"])]);
        let c = counts(&[("A", 10), ("B", 2), ("C", 2), ("D", 10)]);
        // B and C tie; B merges into C (BC, 4 rows, still small), which then
        // merges into its next neighbour D.
        assert_eq!(
            merge_regions(&c, 5),
            vec![names(&["A"]), names(&["B", "C", "D"])]
        );
    }

    #[test]
    fn merge_single_region_stays_even_if_small() {
        let c = counts(&[("A", 0)]);
        assert_eq!(merge_regions(&c, 5), vec![names(&["A"])]);
    }

    #[test]
    fn merge_unchanged_when_all_big() {
        let c = counts(&[("A", 5), ("B", 7), ("C", 100)]);
        assert_eq!(
            merge_regions(&c, 5),
            vec![names(&["A"]), names(&["B"]), names(&["C"])]
        );
    }

    #[test]
    fn merge_cascades() {
        // A (1) into B -> AB (3) still small -> into C -> ABC (13).
        let c = counts(&[("A", 1), ("B", 2), ("C", 10)]);
        assert_eq!(merge_regions(&c, 5), vec![names(&["A", "B", "C"])]);
        // A (1) merges into B (AB, 10, now big); C (1) wraps into AB.
        let c = counts(&[("A", 1), ("B", 9), ("C", 1)]);
        assert_eq!(merge_regions(&c, 5), vec![names(&["A", "B", "C"])]);
    }

    #[test]
    fn input_rows_skips_excluded_and_keeps_order() {
        let (manifest, keys) = regional_manifest();
        let registry = sample_registry(&manifest, &keys);
        let mut r = rng(4);
        let s = random_scalar(&mut r);
        let election = Election {
            context_hash: [9; 32],
            k: s * B,
            manifest: &manifest,
        };
        let mut res = Reservations::new();
        let (a1, ja1) = cast(&election, &registry, "M-S1-01", 1, 0, &mut res, &mut r);
        let (b, mut jb) = cast(&election, &registry, "M-S1-01", 2, 1, &mut res, &mut r);
        let (a2, ja2) = cast(&election, &registry, "M-S1-01", 3, 2, &mut res, &mut r);
        let (c, jc) = cast(&election, &registry, "M-S2-01", 1, 1, &mut res, &mut r);
        jb.contests = vec![(3, ContestStatus::Excluded("test".into()))];
        let cast_ballots = [
            CastBallot {
                region: "SP",
                ballot: &a1,
                judged: &ja1,
            },
            CastBallot {
                region: "SP",
                ballot: &b,
                judged: &jb,
            },
            CastBallot {
                region: "SP",
                ballot: &a2,
                judged: &ja2,
            },
            CastBallot {
                region: "RJ",
                ballot: &c,
                judged: &jc,
            },
        ];
        let u = unit(vec![3], "SP", &["SP"]);
        let rows = input_rows(&manifest, &u, &cast_ballots);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.len() == 1));
        let slot = |b: &Ballot| match &b.contests[3] {
            ContestBallot::Mix { slots, .. } => slots[0].0,
            _ => panic!("mix contest"),
        };
        assert_eq!(rows[0], vec![slot(&a1)]);
        assert_eq!(rows[1], vec![slot(&a2)]);
    }

    #[test]
    fn plan_merges_small_regions() {
        let (mut manifest, keys) = regional_manifest();
        manifest.mix_policy.min_region_rows = 2;
        let registry = sample_registry(&manifest, &keys);
        let mut r = rng(5);
        let s = random_scalar(&mut r);
        let election = Election {
            context_hash: [9; 32],
            k: s * B,
            manifest: &manifest,
        };
        let mut res = Reservations::new();
        let mut owned = Vec::new();
        for (machine, seq) in [("M-S1-01", 1), ("M-S2-01", 1), ("M-S2-01", 2)] {
            owned.push(cast(
                &election, &registry, machine, seq, 1, &mut res, &mut r,
            ));
        }
        let regions = [
            region_of(&registry, "M-S1-01"),
            region_of(&registry, "M-S2-01"),
            region_of(&registry, "M-S2-01"),
        ];
        let cast_ballots: Vec<CastBallot> = owned
            .iter()
            .zip(&regions)
            .map(|((ballot, judged), region)| CastBallot {
                region,
                ballot,
                judged,
            })
            .collect();
        let planned = plan(&manifest, &registry, &cast_ballots);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].0.region, "RJ+SP");
        assert_eq!(planned[0].0.regions, names(&["RJ", "SP"]));
        assert_eq!(planned[0].1.len(), 3);
    }

    /// A mixed unit: six ballots in the non-regional unit of contest 3, the
    /// trustees 1 and 2 having mixed them.
    struct World {
        manifest: Manifest,
        keys: Keys,
        context: Context,
        secret: Scalar,
        unit: MixUnit,
        rows: Vec<Row>,
    }

    const SEL3: [u64; 6] = [0, 1, 2, 1, 1, 0];

    fn world() -> World {
        let (manifest, keys) = non_regional_manifest();
        let registry = sample_registry(&manifest, &keys);
        let mut r = rng(7);
        let secret = random_scalar(&mut r);
        let context = Context {
            manifest_hash: manifest.hash(),
            transcript_hash: [2; 32],
            k: secret * B,
            z: Vec::new(),
        };
        let election = Election {
            context_hash: context.hash(),
            k: context.k,
            manifest: &manifest,
        };
        let mut res = Reservations::new();
        let mut owned = Vec::new();
        for (seq, &sel) in SEL3.iter().enumerate() {
            let machine = if seq % 2 == 0 { "M-S1-01" } else { "M-S2-01" };
            owned.push((
                region_of(&registry, machine),
                cast(
                    &election, &registry, machine, seq as u64, sel, &mut res, &mut r,
                ),
            ));
        }
        let cast_ballots: Vec<CastBallot> = owned
            .iter()
            .map(|(region, (ballot, judged))| CastBallot {
                region,
                ballot,
                judged,
            })
            .collect();
        let mut planned = plan(&manifest, &registry, &cast_ballots);
        assert_eq!(planned.len(), 1);
        let (unit, rows) = planned.remove(0);
        World {
            manifest,
            keys,
            context,
            secret,
            unit,
            rows,
        }
    }

    fn mixers<'a>(w: &'a World, ids: &[u64]) -> Vec<(u64, &'a SigningKey)> {
        ids.iter()
            .map(|&i| (i, &w.keys.trustee_sig[(i - 1) as usize]))
            .collect()
    }

    fn outputs_of(chain: &[(Value, MixOutput)]) -> Vec<MixOutput> {
        chain.iter().map(|(_, m)| m.clone()).collect()
    }

    #[test]
    fn mix_chain_end_to_end_counts_choices() {
        let w = world();
        assert_eq!(w.unit.region, "");
        assert_eq!(w.rows.len(), 6);
        let mut r = rng(8);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[1, 2]));
        assert_eq!(chain.len(), 2);

        // Each signed step verifies with its trustee's key.
        for (i, (value, mo)) in chain.iter().enumerate() {
            let pk = w.manifest.trustees.trustees[i].sig_key;
            let parsed = MixOutput::from_signed(value, &pk).expect("signed mix output");
            assert_eq!(&parsed, mo);
        }

        let outputs = outputs_of(&chain);
        let final_list =
            check_mix_chain(&w.context, &w.manifest, &w.unit, &w.rows, &outputs).expect("chain ok");
        assert_eq!(final_list, outputs[1].output);

        let contest = w.manifest.contest(3).expect("contest 3");
        let decoded: Vec<Vec<Option<u64>>> = final_list
            .iter()
            .map(|row| {
                row.iter()
                    .map(|ct| decode_slot(&ct.decrypt_to_point(&w.secret), contest.options.len()))
                    .collect()
            })
            .collect();
        let counts = count_mix_rows(&[contest], &decoded);
        assert_eq!(counts[0].counted, 6);
        assert_eq!(counts[0].invalid, 0);
        // Options: 0 -> Hugo, 1 -> Iara, 2 -> Joana, then blank and null (no
        // votes). Choices: 0,1,2,1,1,0.
        assert_eq!(counts[0].votes, vec![2, 3, 1, 0, 0]);
    }

    #[test]
    fn mix_chain_empty_unit_is_not_mixed() {
        let w = world();
        let empty = unit(vec![3], "", &["RJ", "SP"]);
        let res = check_mix_chain(&w.context, &w.manifest, &empty, &[], &[]).expect("empty ok");
        assert!(res.is_empty());
    }

    #[test]
    fn check_fails_with_one_mixer() {
        let w = world();
        let mut r = rng(9);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[1]));
        let err = check_mix_chain(
            &w.context,
            &w.manifest,
            &w.unit,
            &w.rows,
            &outputs_of(&chain),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Tally(m) if m.contains("at least 2")),
            "{err:?}"
        );
    }

    #[test]
    fn check_fails_with_same_trustee_twice() {
        let w = world();
        let mut r = rng(10);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[1, 1]));
        let err = check_mix_chain(
            &w.context,
            &w.manifest,
            &w.unit,
            &w.rows,
            &outputs_of(&chain),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Tally(m) if m.contains("ascending")),
            "{err:?}"
        );
    }

    #[test]
    fn check_fails_with_descending_mixers() {
        let w = world();
        let mut r = rng(11);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[2, 1]));
        let err = check_mix_chain(
            &w.context,
            &w.manifest,
            &w.unit,
            &w.rows,
            &outputs_of(&chain),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Tally(m) if m.contains("ascending")),
            "{err:?}"
        );
    }

    #[test]
    fn check_fails_on_broken_input_digest_link() {
        let w = world();
        let mut r = rng(12);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[1, 2]));
        let mut outs = outputs_of(&chain);
        outs[1].input_digest[0] ^= 1;
        let err = check_mix_chain(&w.context, &w.manifest, &w.unit, &w.rows, &outs).unwrap_err();
        assert!(
            matches!(&err, Error::Tally(m) if m.contains("input digest")),
            "{err:?}"
        );
    }

    #[test]
    fn check_fails_on_tampered_output_row() {
        let w = world();
        let mut r = rng(13);
        let chain = run_mix_chain(&mut r, &w.context, &w.unit, &w.rows, &mixers(&w, &[1, 2]));
        let mut outs = outputs_of(&chain);
        outs[0].output[0][0] = Ciphertext::zero();
        let err = check_mix_chain(&w.context, &w.manifest, &w.unit, &w.rows, &outs).unwrap_err();
        assert!(
            matches!(&err, Error::Tally(m) if m.contains("proof")),
            "{err:?}"
        );
    }
}
