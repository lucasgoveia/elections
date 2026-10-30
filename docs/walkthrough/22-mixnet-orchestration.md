# 22 · Mixnet orchestration: which rows are mixed, in which regions, and how the chain is checked

**Code:** `crates/eg-core/src/mixnet.rs`. **Spec:** §19.1 (mix units, regional mixing, small regions, the input list), §19.2 (the mixer chain and `min_mixers`), §23 step 10 (what the verifier checks), and the manifest rules that bound them (§7.2 rules 8 and 9).

**Scope of this file.** `mixnet.rs` decides the mix units, builds each unit's input list, merges small regions, and checks (or runs) the chain of mixers. The shuffle itself, and its zero-knowledge proof, are in `shuffle.rs` (file 16). Decrypting the final list and counting its rows are in file 20.

## The problem

Some contests cannot be counted by adding locked boxes. A count may depend on each ballot's whole row: for example, a multi-choice contest with blanks and nulls, or a link group where a repeated candidate across contests must be spotted in one ballot (file 20, §19.6). For those, the tally has to decrypt each ballot's row. But then the row would be linked to the voter, unless the rows are **shuffled** first, so that no one can tell which output row came from which input row.

That gives three problems for this module:

1. **Which rows get shuffled together.** A shuffle hides a row among the others in the same unit. So the unit decides the anonymity set: the rows any one voter can hide among.
2. **How small a unit may be.** A unit with three rows gives a voter a hiding set of three. Small regions must be merged.
3. **How a chain of shuffles is checked.** Every mixer's output must follow from the previous list, every step must be proved, and enough different trustees must take part that at least one of them is honest.

## Mix units (§19.1, `mix_units`)

A **mix unit** is a mixnet contest outside any link group, or a mixnet link group, together with a **region**. There are two kinds:

- **Regional.** If the contest has field 9 (regional mixing), there is one unit per region of the registry (§7.7), each covering only that region's sections.
- **Non-regional.** Otherwise there is one unit with the region `""`, covering all sections.

A link group is one unit as a whole, since its contests share the row (§19.1). `mix_units` takes the group's method and regional flag from its first contest. Manifest rule 9 fixes the regional flag to be the same for every member, so the group is consistent.

A unit is identified by its lowest contest index and its region. That pair is what `contest_index` and `region` mean in §19.2 and §19.3.

**Why regional mixing.** A national shuffle of 150 million rows would make every shuffle proof about 19 GB, according to §19.1. Regional units keep each proof manageable. The price is the anonymity set, discussed below.

## The anonymity set trade-off

The region is **published**. So for a regional unit, an observer knows that every row in it came from that region's ballots. The voter's hiding set is therefore the rows of the unit, which is the region's ballots, and no more.

| choice | anonymity set | proof size | cost |
|---|---|---|---|
| one national unit | every ballot in the election | very large (about 19 GB at 150 million rows, §19.1) | one long chain |
| one unit per region | the ballots of one region | proportional to the region | many shorter chains |
| a region merged with a neighbour | the merged region's ballots | bigger than before | fewer units, and one more chain |

The region merge below is the tool for keeping the set from getting too small. It is a floor, not a target: the EA should still name regions so that sorted neighbours are geographically close (§19.1), because a merged region is only as private as its members.

## Small regions: merging (`merge_regions`, §19.1)

**The rule.** Regions are sorted by name. Each has a row count. While some region has fewer rows than `min_region_rows` and more than one region remains:

1. take the smallest such region (ties go to the earlier name);
2. merge it into its **next neighbour** in sorted order, wrapping from the last region to the first;
3. the merged group keeps its member names sorted, and it is named by joining them with `+`.

If only one group is left, it stays, even if it is small. A deterministic rule means every verifier gets the same merges.

### Worked examples

These are the cases the tests check, with `min_region_rows = 5`.

**Simple merge.** Regions A (1 row), B (10), C (10):

```
A is smallest and below 5. Its next neighbour is B.   A merges into B: "A+B" (11 rows).
C has 10 rows, so it stays.
Result:  [A+B (11)], [C (10)]
```

**Wrap-around.** Regions A (10), B (10), C (1):

```
C is smallest. Its next neighbour wraps to A.        C merges into A: "A+C" (11 rows).
Result:  [A+C (11)], [B (10)]          names are sorted: "A+C", not "C+A"
```

**Cascade.** Regions A (1), B (2), C (10):

```
A is smallest. Merge into B: "A+B" (3 rows), still below 5.
"A+B" is now smallest. Its next neighbour is C.      merge into C: "A+B+C" (13 rows).
Result:  [A+B+C (13)]
```

**Tie.** Regions A (10), B (2), C (2), D (10):

```
B and C both have 2 rows. The earlier name, B, goes first. Its neighbour is C.
B merges into C: "B+C" (4 rows), still below 5.
"B+C" is smallest. Its neighbour is D.                merge into D: "B+C+D" (14 rows).
Result:  [A (10)], [B+C+D (14)]
```

**One region only.** A single region with 0 rows stays as it is (`merge_single_region_stays_even_if_small`). There is no neighbour to merge into.

The code joins the names of a merged group in sorted order. The spec does not say in which order, so this is recorded as spec issue 13.

## The input list (`input_rows`, §19.1)

For each mix unit, the input list E(0) holds **one row per cast ballot** in the unit's region, from packages accepted before the cutoff. A row is built from the ballot's slots for every contest of the unit: contests in ascending order, and each contest's slots in order. The row width is `w`, the sum of the contests' limits (`MixUnit::width`).

`input_rows` applies three rules:

1. **Region.** The ballot's region must be one of the unit's regions. For a merged unit, that is any of the merged names.
2. **Counted.** Every contest of the unit must be **counted** on the ballot (file 18, §12.6). A ballot with one contest of a link group excluded is left out of the row for the whole group. This is spec issue 14: the code counts a ballot toward a region only if every contest of the unit is counted on it.
3. **Order.** Rows keep the order of the input slice. The caller passes ballots in board order, then package order (§19.1). So every verifier builds the same list.

All of a ballot's slots move together through every shuffle. That is what lets a duplicate inside the row, within one contest or across a link group, be detected after decryption (§19.6, file 20).

A unit with zero rows is not mixed. Its counts are zero by definition.

### Example: the row for a link group

A link group of two contests, 4 and 5, each with 1 slot, so `w = 2`. Ballots 1 and 2 are cast, and ballot 3 has contest 5 excluded:

```
ballot 1: contest 4 slot [a1], contest 5 slot [b1]    -> row [a1, b1]
ballot 2: contest 4 slot [a2], contest 5 slot [b2]    -> row [a2, b2]
ballot 3: contest 4 counted, contest 5 excluded       -> no row (it is left out of the unit)
```

Ballot 3 would have contributed a row to contest 4 alone, but the unit is the group. So it is left out, and so are its contest 4 votes.

## The plan (`plan`, §19.1)

`plan` puts the pieces together, in order:

1. `mix_units` lists the units before merging.
2. For each contest set that has regional units, `merge_regions` decides the groups, using the input row count of each region as its size. Then each merged group becomes a unit with its own input list.
3. Non-regional units keep their own input lists.
4. The result is sorted by contest index, then region.

Units with zero rows stay in the plan, with empty lists, so every verifier can see that they exist and have zero rows.

`plan` is what each verifier runs to know the first input list. The mixer's first output must have the digest of that list (`check_mix_chain` step 1).

## The mixer chain (`check_mix_chain`, §19.2 and §23 step 10)

The mixers are trustees, acting in **ascending trustee index order**. Each takes the previous output as its input, shuffles it with a fresh random permutation and fresh randomness, and publishes a signed `mix_output` (file 16). `check_mix_chain` checks the whole chain. The caller must first check each output's signature (`MixOutput::from_signed`).

For a unit with rows, the checks are, in order:

| check | error when it fails |
|---|---|
| at least one output | "has no mix steps" |
| at least `min_mixers` outputs | "at least *m* required" |
| step numbers are 1, 2, 3, … | "step number out of order" |
| the context hash matches | "context hash does not match" |
| the contest index and region match the unit | "contest index or region does not match the unit" |
| `input_digest` equals the digest of the previous list (the first step's previous list is the input) | "input digest does not match the previous list" |
| the mixer is a trustee of the manifest | "mixer is not a trustee" |
| mixers are strictly ascending in trustee index | "mixers must be distinct and in ascending trustee order" |
| the shuffle proof verifies against (context, contest, region, step, *k*, input, output) | "shuffle proof does not verify" |

It returns the last output, which is the final list handed to decryption (file 20, §19.4).

A unit with **no rows** must have **no outputs**. The function returns an empty list. If a unit with no rows has outputs, or a unit with rows has none, that is an error.

`run_mix_chain` is the reverse: a helper for tests and demos that runs the chain with given mixers and returns each step's signed output and parsed form. The real mixers run their own copy of the same step.

### Why at least one shuffle is honest

This is the argument the spec relies on (§7.2 rule 8). The chain is accepted only with at least `min_mixers` mixers. Those mixers are **distinct** (ascending order makes that automatic), and the manifest requires `min_mixers ≥ k`. The threshold assumption is that fewer than *k* trustees are corrupt. So among any `min_mixers ≥ k` distinct trustees, at least one is honest.

An honest mixer draws its permutation and its randomness at random, in secret, and does not reuse them. Its output is then unlinkable to its input for anyone who does not know that permutation. The chain composes its permutations, so the final list is unlinkable from the first list as long as any one of the permutations is secret. The corrupt mixers cannot break this, because they do not know the honest mixer's permutation.

So the check is not about trusting any one mixer. It is about the count: enough different trustees took part that one of them had to be honest.

### Why the mixers are in ascending order

Two reasons, both from the code's checks:

- **Distinctness is a single comparison.** If the indices strictly increase, no trustee can appear twice. A trustee mixing twice in a row would hold two shuffles in a row, which would not make the count larger.
- **Every verifier sees the same order.** The chain is a fixed sequence, not a set, so the list of outputs can be checked the same way by anyone.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `MixUnit::contest_index` | the lowest contest index of the unit | identifies the unit with its region (§19.2) |
| `MixUnit::width` | Σ L over the unit's contests | the row width *w* (§19.1) |
| `CastBallot` | a cast ballot with its region and judged status | the input to row building |
| `registry_regions` | the sorted, distinct regions of the registry | the regions a regional unit is split into |
| `is_regional` | whether a unit's first contest has field 9 | decides between regional and national treatment |
| `mix_units` | the units before merging, sorted | §19.1 |
| `input_rows` | the rows of one unit, from ballots in order, with the region and counted rules | §19.1 |
| `merge_regions` | the small-region merge over (name, rows) pairs | §19.1 small regions |
| `plan` | units after merging, each with its input list | the verifier's first list |
| `check_mix_chain` | checks steps, digests, trustees, order and proofs; returns the final list | §19.2 and §23 step 10 |
| `run_mix_chain` | runs the chain with given mixers (test and demo helper) | builds valid chains for the tests |
| `tally` (private) | builds an `Error::Tally` | every failure names its unit |

## Design choices

- **The unit list and the first input list are fixed by the manifest, the registry and the board.** Nothing is chosen by the EA or by a mixer. Every verifier builds the same list, and the first mixer's `input_digest` must match it.
- **Regions are published and merged by a fixed rule.** An EA who wants a small region cannot hide it, since the merge is deterministic and the result is public.
- **A whole row moves together.** Splitting a ballot's slots would break the duplicate check of §19.6.
- **Zero-row units are not mixed.** A proof of shuffling nothing would be meaningless, and the count is 0 by definition.
- **The minimum is on distinct trustees.** It is counted, not assumed, so the honesty argument rests on a number the verifier can check.
- **The chain check does not check signatures.** The caller checks each output's signature first, so this function is about the chain alone.
- **The rows are not decrypted here.** Decryption and counting belong to file 20, so this module never sees a plaintext row.

## Attacks each check stops

| attack | what stops it |
|---|---|
| the EA merges or splits regions to get a favourable set of voters | the merge rule is fixed and deterministic (`merge_small_region_into_next`, `merge_wraps_from_last_to_first`, `merge_ties_go_to_earlier_name`, `merge_cascades`), and the regions are published |
| the first mixer shuffles a different list from the one the board implies | step 1's `input_digest` must match the list the verifier builds (`check_fails_on_broken_input_digest_link`) |
| a mixer drops, duplicates or alters a row | its shuffle proof fails (`check_fails_on_tampered_output_row`, and file 16) |
| one trustee mixes twice to stand in for two honest shuffles | distinct and ascending (`check_fails_with_same_trustee_twice`, `check_fails_with_descending_mixers`) |
| a single mixer does all the shuffling | `min_mixers` (`check_fails_with_one_mixer`) |
| someone who is not a trustee mixes | "mixer is not a trustee" |
| a ballot with an excluded contest is mixed into a link group | `input_rows` leaves it out (`input_rows_skips_excluded_and_keeps_order`) |
| a step from another unit, region or election is spliced in | the context, contest index and region checks |
| a unit with rows but no mixing, or with mixing but no rows | the "no mix steps" and "no rows but has mix steps" checks (`mix_chain_empty_unit_is_not_mixed`) |
| a small region whose rows could be traced | the merge floor `min_region_rows` (`plan_merges_small_regions`) |

## Tests (18)

- **Units:** a regional fixture gives one unit per region; a non-regional contest gives one unit; a link group of mixnet contests is one unit (`mix_units_regional_fixture_one_per_region`, `mix_units_non_regional_single_unit`, `mix_units_link_group_of_mixnet_contests`).
- **Merging:** the simple merge, the wrap-around, the tie, the single region, unchanged big regions, and the cascade (`merge_small_region_into_next`, `merge_wraps_from_last_to_first`, `merge_ties_go_to_earlier_name`, `merge_single_region_stays_even_if_small`, `merge_unchanged_when_all_big`, `merge_cascades`).
- **Input rows:** excluded ballots are left out and the order is kept (`input_rows_skips_excluded_and_keeps_order`).
- **Plan:** small regions are merged in the full plan (`plan_merges_small_regions`).
- **Chain:** a full chain with a counted result (`mix_chain_end_to_end_counts_choices`), an empty unit is not mixed (`mix_chain_empty_unit_is_not_mixed`), and the failure cases: one mixer, the same trustee twice, a descending order, a broken input digest link, and a tampered output row (`check_fails_with_one_mixer`, `check_fails_with_same_trustee_twice`, `check_fails_with_descending_mixers`, `check_fails_on_broken_input_digest_link`, `check_fails_on_tampered_output_row`).

## Spec gaps and issues relevant here

- **Spec issue 13 (merged region names).** The order of names in a merged region is not specified. The code sorts them.
- **Spec issue 14 (row counts for merging).** A ballot counts toward a region only if all contests of the unit are counted on it. The spec does not say so.
- **Spec issues 1 and 2 (shuffle labels and the vector `c`).** These are about the shuffle proof, in `shuffle.rs`. They are listed in file 16, not here.
- **§23 step 10, "the first input list is built per §19.1".** `plan` builds it, but the comparison of the first mixer's digest with `plan`'s list is done by the caller. No function here compares a published list against the board.
- **Method and regional flag inside a link group.** `mix_units` takes both from the group's first contest. The manifest's rules keep the regional flag equal for members (rule 9), and the method is the manifest's to check. A reader should not assume `mix_units` checks each member.
- **Anonymity-set floor.** `min_region_rows` sets a floor on the rows of a unit, not on the number of distinct voters. The spec does not say how large the floor should be. That is an election decision.
