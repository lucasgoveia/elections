# 18 · The homomorphic tally: adding locked boxes, and why no one holds the count

**Code:** `crates/eg-core/src/tally.rs`. **Spec:** §12.6 (ballot validity and α reservation), §18 (section tally, pool, encrypted tally index), §16.2 (the pre-BU that carries the subtotal fingerprint).

**Scope of this file.** `tally.rs` has the pieces: judging a cast ballot, adding its boxes per contest, splitting small contests off, the subtotal fingerprint, and the three published records. It does not decide which packages go into which tally, and it does not decrypt anything. Those are the caller's job (the board service and the verifier), and decryption is file 20. The end-to-end test in `decrypt.rs` shows the pieces wired together.

## The problem

Once the ballots are cast, the election has to add them up. Four things must hold at the same time:

1. **No machine holds the count.** A voting machine that knows how many votes each candidate has is a single point of attack. It can also be compared with other numbers taken at other times, to learn how people voted. So the machine only adds **locked boxes** (file 04), which needs no key, and never sees a plaintext total (§16.2).
2. **Each ballot counts once.** A cast ballot copied into a second package must not be added a second time.
3. **Each ballot is judged contest by contest.** A broken proof in one contest should not throw away the voter's other votes (§12.6).
4. **Small groups stay private.** A published total for a section with three voters reveals those three votes.

Four functions cover the four points, in this order: `judge_cast`, `sum_ballots`, `split_pooled` and `fingerprint`.

## The idea, without math

Locked boxes can be added without opening them. From file 04, two ballots hold `(α, β)` pairs:

```
ballot 1: (α, β) = (6, 5)
ballot 2: (α, β) = (4, 5)

sum:      (α, β) = (6 + 4, 5 + 5) = (10, 10)
```

The sum is a box that holds the sum of the two votes (one vote and one zero, so 1). With the key s = 4, the decryption is `β − s·α = 10 − 40 = −30`, which wraps to 3 = 1·B. So the total is 1, and nobody opened either ballot.

This is why the machine can total a section while holding no key and no plaintext. It only does the addition above, once per option and per contest.

## Where this sits in the pipeline

| step | function | output | spec |
|---|---|---|---|
| 1. judge every cast ballot, in board order, then package order | `judge_cast` | `JudgedBallot` per ballot | §12.6 |
| 2. add the boxes of counted contests, per option | `sum_ballots` | `ContestSum` per homomorphic contest | §18.1 |
| 3. move contests with too few counted ballots aside | `split_pooled` | kept sums and pooled sums | §18.1 |
| 4. fingerprint the kept and pooled sums | `fingerprint` | 32 bytes, printed on the pre-BU | §18.1, §16.2 |
| 5. record the section tally (and, after the cutoff, the pool and the index) | `SectionTally`, `PoolTally`, `EncryptedTally`, `merge_sums` | signed-by-nobody records anyone can recompute | §18.1 to §18.3 |

Step 1 must come first. Step 2 only sees ballots whose contests were judged counted.

## Judging a cast ballot (`judge_cast`, §12.6)

`judge_cast` does three things, in order.

1. **Well-formedness.** It calls `ballot::check_ballot` (rules 1 to 4 of §12.6): right election, right contest list for the machine, one link proof per candidate in each link group, and no α equal to the identity point. If this fails, the whole ballot is excluded and `well_formed` holds the reason. Nothing else is judged.
2. **α reservation.** Walking the contests in ascending order, each contest whose proofs passed tries to reserve its α values in `Reservations`. If any of them is already reserved, the contest is excluded with the reason `"α already reserved"`.
3. **Link groups.** If any contest of a link group is excluded, every counted contest of that group on this ballot is excluded too, with the reason `"link group N: …"`. A link group is a set of contests over the same candidates in which a voter may pick each candidate at most once across the whole group (§7.5). A ballot that breaks this comes from misbehaving software, so the group's contests on that ballot leave the tally together, and the rest of the ballot still counts.

### α reservation, with a toy example

Every ballot's box has an α, a "hint" about its nonce (file 04). A ciphertext with the same α is the same box. So reserving α values means remembering every box that has already been counted.

Take α values as clock hours, the same way as the rest of the walkthrough:

```
Ballot X (cast in package 1, board entry 40): contest 0 has α = (6, 9).
  Reserved so far: {}           proofs pass      -> reserve {6, 9}, counted.
Ballot Y (the same bytes, copied into package 2, board entry 77): contest 0 has α = (6, 9).
  6 is already reserved         proofs still pass, but -> excluded "α already reserved".
```

The copy in package 2 has valid proofs, because proofs bind the ballot id (§11), and that id is unchanged. Without reservation the vote would count twice. The reservation makes the first copy in board order count and the second not count.

### The attacks reservation stops, as stories

**Replay.** A party with access to the board copies Ana's cast ballot bytes into a second package, perhaps from another session of the same machine. The copy's proofs are valid. Reservation excludes the second copy, and the exclusion is public and attributed to the machine (§23).

**Burning an honest α.** An attacker wants Ana's ballot to be excluded. They copy Ana's ciphertexts into a package that comes **earlier** on the board, but with a wrong proof on every contest. That copy fails its proofs, so it reserves nothing (`ballot_with_failing_proofs_reserves_nothing`). When Ana's real ballot is judged later, its α values are still free, and it counts.

This is why the spec reserves on **proof success**, not on counting. If failures reserved α, the cheap copy above would block the honest ballot.

**Nonce reuse.** Two different ballots with the same α would mean a machine reused a nonce. The first one in board order counts. The second is excluded. The spec also wants the first one reported (§12.6), and `judge_cast` alone cannot do that, because it judges one ballot at a time. The verifier must cross-check the reservation set and list both. See the gaps section below.

### Reservations within a link group

A subtle case: contest 4 and contest 5 form a link group. Contest 4 passes its proofs and reserves its α. Contest 5 is then excluded for some other reason, so the whole group is excluded. Contest 4's α stay reserved, so a later ballot that copies contest 4 is still caught. The code comment says this is deliberate: "those α are still burned for later ballots, since the spec reserves on proof success, not on counting". This is spec issue 12 (file `docs/spec-issues.md`).

## Adding the boxes (`sum_ballots`, §18.1)

For each homomorphic contest in ascending order:

- start with one empty box `(O, O)` per option (`Ciphertext::zero()`);
- for each ballot whose contest is `Counted` in its `JudgedBallot`, add that ballot's boxes to the running sums, option by option (`selections` zipped with the option list, so placeholder boxes at the end are dropped);
- count the ballot in `counted`.

The output covers every homomorphic contest that appears in any judged list, even if `counted = 0`. A contest with zero counted ballots gets `(O, O)` sums, which means "no votes, not decrypted" (§18.2).

Toy example, with two options A and B and two counted ballots, one voting A and one voting B. Using the box values from the example above, each ballot holds `(α, β)` for A and for B:

```
ballot 1 (votes A):   A: (6, 5)   B: (4, 5)      (box for 1 vote, box for 0 votes)
ballot 2 (votes B):   A: (4, 5)   B: (6, 5)      
sum:                  A: (10, 10)  B: (10, 10)   counted = 2
```

Each option's sum decrypts to 1 vote out of 2 ballots, so A = 1, B = 1. Only the sums are decrypted (file 20), never the ballots.

## Pooling small contests (`split_pooled`, `merge_sums`, §18.1 and §18.2)

**Why.** Suppose one section has only two ballots in a contest, and both voted for candidate X. The section's total for that contest would read "X = 2", which tells everyone how those two people voted. So §18.1 says a contest with fewer than `min_section_ballots` counted ballots is **pooled**: it leaves the section tally, and it is added to a single pool that covers the whole election.

`split_pooled` does the split. It sorts the sums by contest index and partitions them into those with `counted >= min_section_ballots` (kept) and the rest (pooled). The section tally records the pooled contest indices in its field 7, so anyone can see which contests were moved and why.

**Why the pool is safer.** The pool adds the small pieces of several sections together. A published pool number is therefore not one section's few votes. It is still a number that can reveal something when combined with others, which is what §18.3 warns about: if the election total is published, the pool is that total minus the section results, and a small pool is exposed. The verifier warns when a pool contest has fewer than `min_section_ballots` ballots.

**`merge_sums`** adds sums contest by contest, keeping ascending order. It is used to build the pool (§18.2): the pooled contests of every pre-BU are merged together, and the cast ballots of packages that no pre-BU covers are added on top. The function panics if the same contest has a different number of options in the two inputs. Both come from the same manifest, so that would be a programming error, not bad data.

## The subtotal fingerprint: pinning the result before anyone decrypts

This is the part that makes the paper pre-BU meaningful.

The machine computes its section tally when the session closes, from its own cast ballots and any recovered packages it imports (§16.2). It then hashes the result:

```
fingerprint = Digest("eg/v1/subtotal",
                     context_hash, machine_id, session_id,
                     pre_bu field 6  (the imported list),
                     section_tally field 6  (kept contests, with their boxes),
                     section_tally field 7  (pooled contest indices))
```

The fingerprint goes in pre-BU field 14. The pre-BU is printed, and the poll workers and observers sign the paper copies **before** the package leaves the section (§16.2).

Later, anyone can do the following:

1. take the packages from the board;
2. recompute the section tally, byte for byte;
3. recompute the fingerprint and compare it with pre-BU field 14.

If they match, the section tally is the one the paper pre-BU describes. If they don't, the section is reported as `mismatch` (§18.1, §21).

Why this pins the result: the fingerprint covers **every box** of the section tally. Trustees can only open the boxes that exist (file 20). If someone decrypts a different set of boxes, its fingerprint is different and does not match the paper copy in observers' hands. So the paper pre-BU fixes the section's result before anyone can decrypt it.

Why the fingerprint names the session, not the package: the package contains the pre-BU, so the pre-BU cannot name the package without a circular reference. The session fields (`machine_id`, `session_id`, and the frame digest and chain head in pre-BU fields 7 and 8) pin the session's contents instead.

Toy illustration. The fingerprint is a hash, so it can't be checked by hand. What matters is that changing any input changes it. The test `fingerprint_binds_every_input` changes each input in turn (context hash, machine id, session id, an imported count, a counted total, the pooled list, and an emptied pooled list) and asserts that the digest changes every time.

## The records

| record | field 0 tag | what it holds | strict decode checks |
|---|---|---|---|
| `Imported` | (none, it is an array) | `[digest, uint, digest]`: RecordId of a recovered package, its cast count, its last chain head | exactly three items |
| `SectionTally` | `section_tally` | context hash, RecordId of the pre-BU, section id, RecordIds of the package and each imported package (field 5, at least one), kept contests (field 6), pooled indices (field 7) | version 1, field 5 non-empty, fields 6 and 7 strictly ascending |
| `PoolTally` | `pool_tally` | context hash, tree size at the cutoff, one `ContestSum` per homomorphic contest | version 1, contest indices strictly ascending |
| `EncryptedTally` | `encrypted_tally` | context hash, STH root and tree size at the cutoff, RecordId of each section tally in board order, RecordId of the pool | version 1 |

All of them are **unsigned** here. Their trust comes from the board (they are recomputed from entries on the board) and from the pre-BU signature (which carries the fingerprint). `SectionTally::record_id` returns `board::record_id` of the record, the name that the final BU and the section result use (file 15).

`ContestSum` is `[uint, uint, [+ [point, point]]]`: contest index, counted ballots, and one box per option.

Every record is encoded in canonical CBOR (file 01). Because the fingerprint is a hash of those bytes, two verifiers that build the same tally must produce the same bytes, which is why the lists are kept in ascending order.

## The code, function by function

| function | file | what it does | why |
|---|---|---|---|
| `Reservations::new` | tally.rs | an empty set of reserved α | one set per election, shared across all ballots |
| `Reservations::try_reserve` | tally.rs | reserves the α of one contest if none is reserved and none repeats inside the contest | the all-or-nothing rule within a contest |
| `judge_cast` | tally.rs | well-formedness, then reservation, then link-group rule | the single place where §12.6 is applied to a cast ballot |
| `ContestSum::to_value`, `from_value` | tally.rs | encode and strictly decode `[uint, uint, [+ [point, point]]]` | the sum record's wire form |
| `sum_ballots` | tally.rs | per homomorphic contest, adds the boxes of ballots where the contest is counted | §18.1; the only place boxes are added |
| `split_pooled` | tally.rs | partitions sums by `min_section_ballots` | §18.1 pooling threshold |
| `indices` | tally.rs | the contest indices of a list of sums, in order | field 7 of the section tally |
| `merge_sums` | tally.rs | adds sums contest by contest | builds the pool (§18.2) |
| `Imported::to_value`, `from_value` | tally.rs | `[digest, uint, digest]` | pre-BU field 6 |
| `fingerprint` | tally.rs | the §18.1 subtotal fingerprint | the value on the paper pre-BU |
| `SectionTally::to_value`, `from_value`, `record_id` | tally.rs | the §18.1 record, its strict decode and its RecordId | the name the final BU uses |
| `PoolTally::to_value`, `from_value` | tally.rs | the §18.2 record | |
| `EncryptedTally::to_value`, `from_value` | tally.rs | the §18.3 index | |
| `check_ascending` | tally.rs | errors unless the indices are strictly ascending | canonical order |

## Design choices

- **Judge first, then add.** A bad ballot never contributes a box, and a contest that fails never reaches the sum. The judging rule is written once, in `judge_cast`, so the machine's pre-BU and the verifier's recomputation cannot disagree about it.
- **Reserve on proof success, not on counting.** Explained above: a copy with bad proofs must not be able to burn an honest α.
- **One reservation set for the whole election, in board order.** The α rule is global, because a copy can be placed in any package. Judging per package would let the same ballot count once in each package.
- **Sum per contest, not per ballot.** The output is a short list of sums, not a list of every ballot. Anyone can add the same boxes again and get the same answer.
- **Canonical order and strict decoding.** Every list is ascending and every field is checked. The fingerprint is only useful if two honest implementations produce the same bytes.
- **Pooling is by count, not by value.** The threshold uses how many ballots, never what they say. The machine never looks at the totals to decide.
- **The fingerprint covers the imported list and the pooled indices too.** A section tally that quietly drops an imported package, or pools a different contest, changes the fingerprint.

## Attacks each check stops

| attack | what stops it |
|---|---|
| a cast ballot copied into a second package to count twice | α reservation: the second copy is excluded, reported by contest |
| a copy with bad proofs placed earlier, to block an honest ballot | a failing contest reserves nothing (`reserve` runs only after proofs pass) |
| a ballot with a bad proof in one contest | only that contest (and its link group) is excluded; the others count |
| a link-group contest that is bad, and its group-mates | the group rule excludes every counted contest of the group on that ballot |
| the machine's pre-BU claims a different subtotal from the one it encrypted | the recomputed fingerprint does not match: `mismatch` against the machine |
| trustees open a different set of boxes than the paper pre-BU | the fingerprint covers every box, so the boxes must match the paper copy |
| a small section's total reveals a few voters | the contest is pooled below `min_section_ballots` |
| a pool contest so small that its total is exposed | the verifier warns (§18.3) |
| a section tally with unsorted lists or a missing package | strict decode and the fingerprint |

## Tests (11)

- **Decryption of sums:** the sums of 5 ballots decrypt to the right counts per option, and placeholder boxes are not summed (`sums_decrypt_to_counts_and_exclude_placeholders`).
- **Exclusion:** an excluded contest does not count, but the other contests on the same ballot do (`excluded_contest_does_not_count_but_others_do`).
- **Replay:** the same ballot cast twice is excluded the second time, with `"α already reserved"` (`same_ballot_cast_twice_is_excluded_by_reservation`).
- **Failing proofs reserve nothing:** a ballot with broken proofs does not block the honest ballot it copies (`ballot_with_failing_proofs_reserves_nothing`).
- **All or nothing:** a contest with a repeated α inside itself reserves nothing, and a contest that shares one α with an earlier one is refused and reserves nothing new (`reservation_is_all_or_nothing_within_a_contest`).
- **Pooling threshold:** contests below the threshold are pooled, and the rest are kept (`split_pooled_threshold`).
- **Merging:** `merge_sums` adds contest by contest and keeps every contest from either side (`merge_sums_adds_contest_wise`).
- **Fingerprint:** the digest equals its definition, and changing any input changes it (`fingerprint_binds_every_input`).
- **Strict records:** round trip and rejection of malformed `Imported` and `SectionTally` values (`imported_round_trip_and_strictness`, `section_tally_round_trip_and_strictness`).
- **Pool and index:** `PoolTally` and `EncryptedTally` round trip (`pool_and_encrypted_tally_round_trip`).

## Spec gaps and issues relevant here

- **Spec issue 12 (α reservation inside link groups).** Reservations made by a group member stay even when the group is excluded. The code keeps them on purpose. The spec should say so.
- **§12.6, nonce reuse.** The spec says that when two valid contests share an α, "both are reported". `judge_cast` only sees one ballot, so it excludes the later contest and cannot name the earlier one. The verifier has to keep the reservation history and report both. This is not in `spec-issues.md` yet.
- **§18.2, composition of the pool.** The rule that the pool is the pooled contests plus the cast ballots of uncovered packages is only in the spec's prose. `tally.rs` provides `merge_sums` and nothing that chooses which packages go in. The caller does, and it is only exercised by the decryption test.
- **Spec issue 9 (verifier independence).** The verifier reuses `judge_cast` and `fingerprint`. A bug in either would be reproduced by both sides. Their tests and the test vectors (file 07) are the defence.
