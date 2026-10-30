# 24 · The authority pipeline: from the board to the result

**Code:** `crates/eg-core/src/authority.rs`. **Spec:** §16.2 (the pre-BU's fingerprint), §16.5 (final BU), §17.7 (the tally cutoff), §18 (section tallies, the pool, the index), §19.1 (mix units, through `mixnet.rs`), §20.5 (what a trustee refuses to open), §21 (results), §22 (seats, through `apportionment.rs`).

**Scope of this file.** `authority.rs` is the glue between the board and the published numbers. It takes the board entries and produces, in order, every record that the tally needs. It also holds the trustee's own refusal check and the code that puts the trustees' answers together into a result. It does not do the maths itself. The steps it calls are: ingestion in `package.rs` (file 21), judging and sums in `tally.rs` (file 18), mix planning and the chain check in `mixnet.rs` (file 22), share combination and decoding in `decrypt.rs` (file 20), and seats in `apportionment.rs` (file 17). Read this file after those.

## The problem

Once the machines have closed and the packages are on the board, four things have to be true at the same time:

1. **Everyone computes the same tally.** Anyone with the board must get the same bytes, or the paper pre-BUs mean nothing.
2. **Nothing is counted that the board did not accept.** Packages after the cutoff, duplicated ballots and ballots with broken proofs must be left out, and the leaving out must be visible.
3. **The trustees open only what they were shown from the board.** A corrupt election authority (EA) must not be able to hand them one voter's ballot dressed up as a section total (§20.5).
4. **Small groups stay private.** A contest with few counted ballots is pooled, and the published numbers must not reveal a group of two or three voters (§18.1, §18.2).

Everything in `authority.rs` is a pure function of the board, the manifest and the context. So a verifier calling the same functions gets the same answer. The module comment says this directly, and it is the reason the trustee and the verifier share code (spec issue 9).

## The idea, without math

Think of the pipeline as a set of boxes that get filled in order. Each box is a published record, and each one is a function of the boxes before it:

```
board entries ──► board_view ──► section_tallies ──► pool_tally ──► encrypted_tally
  (up to cutoff)   (ingest,        (one per pre-BU,     (pooled sums         (index of
                    judge every     fingerprint          plus uncovered        the above)
                    cast ballot)    check)               packages)
                       │                 │
                       ▼                 ▼
                   mix_plan      trustee_decrypt  ──► share sets ──► final_bu ──► election_result
                 (mix units,     (refuses targets                   (one per      (contests,
                  input lists)    that do not match                  section)      sections, pool,
                                  the board)                                       seats)
```

The important property is the **single source**. Only `board_view` reads the board. It judges every cast ballot once, in board order, with one set of reservations. Every later stage reads its output and never the raw entries. That is also why a trustee can check its target in one place (`trustee_decrypt` recomputes `section_tallies` and compares).

## Worked example: a tiny election

Set `min_section_ballots = 3`. There is one homomorphic contest 0 with options A and B, and two sections.

- **S1**, machine M1: three cast ballots, voting A, A, B.
- **S2**, machine M2: two cast ballots, voting B, B.

The board, in order, has a `tally_cutoff` after both packages. Judging finds no faults, so all five ballots count.

1. **`board_view`** ingests the entries up to the cutoff and judges the five ballots in board order. Each has its contest 0 counted.
2. **`section_tallies`**, one tally per pre-BU:
   - S1 has 3 counted ballots, which is at least 3, so contest 0 is **kept**. The section tally has the sum of its boxes for A and for B, and the fingerprint recomputed from the board equals the pre-BU's field 14. The flag is `true`.
   - S2 has 2 counted ballots, which is below 3, so contest 0 is **pooled**. S2's section tally has no kept contests, and it lists contest 0 in its pooled indices. The 2 ballots' boxes go to the pool.
3. **`pool_tally`** starts from a zero sum for each homomorphic contest, adds S2's pooled sum (2 counted), and adds the ballots of any package no pre-BU covers (none here). The pool now has contest 0 with 2 counted ballots.
4. **`encrypted_tally`** lists the two section tally ids in board order and the pool id, at the cutoff's tree size.
5. **Trustees** open S1's section tally: the decryption gives A = 2, B = 1. They open the pool: A = 0, B = 2. Both come with share sets that name their target, and the trustees check the target first (see below).
6. **`election_result`** adds the parts: contest 0 has A = 2 + 0 = 2 and B = 1 + 2 = 3, counted 5.

Two things in this example are worth noticing.

- **The pool has only one small section, so its total is exactly S2's result.** The spec warns about this (§18.3) and asks the verifier to flag a pool contest with fewer than `min_section_ballots` ballots. No code in `eg-core` produces that flag yet. A real election pools many sections, so the total of the pool is not one section's count. This toy is exactly the case the flag is for.
- **If M1 had lied about its subtotal**, say its pre-BU fingerprint covered different boxes, step 2 would have computed a different fingerprint. The flag would be `false`, and the section would appear as `mismatch` in the result. The votes that the board really holds would still be opened and counted (§18.1: "The tally recomputed from the board is the one that is opened, so the valid votes still count").

## The stages, one by one

### 1. Ingestion and judging (`board_view`, §17.7, §12.6)

`board_view` does the following.

- It finds the first `tally_cutoff` entry. If there is none, it returns an error. **The whole pipeline needs a cutoff** (see the gaps below).
- It feeds the entries up to the cutoff to `BoardState::ingest` (file 21). Entries the board refuses are kept in `rejected` with the reason. A refused cutoff is an error.
- It takes the registry in force at the cutoff. Then, for every accepted package in board order, it decodes the package (`Package::from_signed` with the machine's key, or `RecoveredPackage::from_value`), finds the pre-BU in it (`pre_bu_of`, which checks the machine's signature), and reads the cast and spoiled ballots (`ballots_of`).
- It judges every cast ballot with `judge_cast`, using **one** `Reservations` for the whole board (file 18). A copy of a ballot in a later package is therefore excluded, even if it is in another section.
- Spoiled ballots are kept with their reveals, but not judged and not tallied.
- A superseded recovered package (file 21) keeps its entry but has no ballots, so it does not reserve any α.

The result is a `BoardView`: the manifest, the context, the cutoff index, the registry, and one `ViewPackage` per accepted package with its judged ballots.

### 2. Section tallies (`section_tallies`, §18.1)

For each package that carries a pre-BU, in board order:

- the **covered** ballots are its own cast ballots plus those of each recovered package listed in the pre-BU's field 6 that is found among the view's packages;
- `sum_ballots` adds the boxes of the ballots where each contest is counted, and `split_pooled` moves contests with fewer than `min_section_ballots` counted ballots aside;
- `fingerprint` is computed over the context, the machine, the session, the imports, the kept sums and the pooled indices (file 18);
- the flag is `fingerprint == pre-BU field 14`.

The function returns the `SectionTally`, the flag and the pooled sums of that section. The section tally's `packages` field lists every package id the pre-BU names, including any import that is not on the board.

**Gap: a missing import is dropped without a refusal.** Look at the loop over `pb.imported`. If an import is not on the board, the `if let Some` skips it. The fingerprint is then computed over the pre-BU's full list, so it does not match, and the flag is `false`. But nothing refuses the section, and `trustee_decrypt` still signs for it (see below). Spec §20.5 says the trustee must check that every imported recovered package is accepted. This is not in `spec-issues.md` yet.

**Gap: a package imported twice is counted twice.** If two pre-BUs list the same recovered package, each section tally covers its ballots, so the totals double count (spec issue 22). The board does not check the pre-BU's import list at all (`package.rs` has no such check), and this module does not check for duplicates either.

### 3. The pool (`pool_tally`, §18.2)

The pool is the sum of three things per homomorphic contest, starting from a zero sum:

- the pooled sums of every section tally (`merge_sums`);
- the cast ballots of every non-superseded package that **no pre-BU covers**. A package is covered if it is a pre-BU's own package or one of its imports (matched by RecordId).

Every homomorphic contest appears in the pool, even if nothing was pooled into it, with the identity sum `(O, O)` and zero counted. The pool's `tree_size` is the cutoff index.

The "uncovered" part matters for recovered packages. If a dead machine's journal is recovered but no replacement imports it, its ballots are still counted here (§16.4). The verifier reports that package.

### 4. The index (`encrypted_tally`, §18.3)

`encrypted_tally` records the STH root at the cutoff (given by the caller, because the board's signed tree head is the board's business, file 15), the tree size, the record id of each section tally in board order, and the record id of the pool. Anyone who recomputes the index from the board at the same size must get identical bytes.

### 5. Mix planning (`mix_plan`, §19.1)

`mix_plan` takes every cast ballot of every non-superseded package, in board order, with the region of its section (`ViewPackage::region`), and calls `mixnet::plan` (file 22). It returns each mix unit with its first input list. This is the list the first mixer must start from, and `trustee_decrypt` checks that the input it is shown equals this list.

### 6. What a trustee opens (`Target`, `trustee_decrypt`, §20.1 and §20.5)

`Target` is what the trustees open. It has three kinds:

- `Section(SectionTally)`: a section tally. Its digest is the record id of the section tally.
- `Pool(PoolTally)`: the pool. Its digest is the record id of the pool.
- `MixFinal { unit, input, outputs, last_output_value }`: the final list of a mix unit. Its digest is the record id of the last `mix_output`. This is spec issue 23.

`Target::items` gives the ciphertexts to open, in canonical order (§20.1): section contests in the tally's order, then options; pool contests in order, skipping those with no counted ballots; mix rows in order.

`trustee_decrypt(rng, view, sections, target, trustee, z_j, trustee_sk)` is what a trustee runs before it signs. It refuses unless all of the following hold:

1. the trustee index is one of the manifest's trustees, and the signing key is that trustee's key;
2. `z_j · B` equals the trustee's `Z_j` in the context, so the trustee is using its own secret share;
3. `sections` **equals** `section_tallies(view)`. The caller hands over its own recomputation, and it must be the board's;
4. the target is the right kind of thing: a `Section` must be one that was recomputed; a `Pool` must equal `pool_tally(view, sections)`, and so must its `tree_size`; a `MixFinal` must have the planned input, pass `check_mix_chain`, and have a last output whose signature decodes to the last step;
5. there is something to open.

Only then does it create the share set (`DecryptionShareSet::create`) and sign it.

The spec wants the trustee to hold the board dump, not bare ciphertexts (§20.5 last paragraph). The `sections` argument and the equality in step 3 are how this code does that.

### 7. The final BU (`final_bu`, §16.5)

`final_bu(view, section, share_sets)` assembles a section's final BU:

- it refuses unless the section is one `section_tallies` recomputes from the view;
- `verified_sets` keeps only share sets that decode, come from a manifest trustee, carry that trustee's valid signature, and name this section's record id as their target;
- `combine` (file 20) checks the proofs and keeps the lowest `k` valid trustee indices. Any share sets that fail are reported by `combine` but dropped here;
- `decode_sums` turns the combined points into counts, and the result is a `FinalBu` with the context, pre-BU id, section tally id, results and the share sets used.

`final_bu` does not compare the fingerprint. The caller already has the flag from `section_tallies`.

### 8. The result (`election_result`, §21)

`election_result(view, sections, pool, inputs)` produces the published result, and it checks everything it is given.

1. It recomputes `section_tallies` and `pool_tally` and refuses unless the given ones are equal to them.
2. For each section, it takes the final BU with the section tally's id from `inputs.final_bus`, checks its record id, and calls `check_final_bu` (file 20), which recombines the shares and compares the decoded results with the final BU. Its results go into the homomorphic totals. A section with nothing to open has no final BU, and the all-zero digest is used instead (`NO_FINAL_BU`, spec issue 21).
3. For the pool, it decodes the contests with counted ballots using the verified pool share sets, and it adds a row for every pool contest, with zeros where nothing was counted.
4. For each mix unit in the plan, it checks the mix chain (`check_mix_chain`), combines the verified share sets over the final list, decodes the slots with `decode_slot`, and counts the rows with `count_mix_rows`. An invalid slot is counted as invalid, not excluded (spec issue 24).
5. For each contest in ascending order, it chooses the total (homomorphic or mixnet), adds `excluded` (the ballots excluded under §12.6, counted per contest from every package), and for a proportional contest adds the party totals and seats (`party_totals`, `apportion`, file 17).
6. It returns an `ElectionResult`, with each section's result (its final BU id, the pre-BU id, the contests, its exclusions and the `matches` flag) and the pool rows.

## The trustee check, as a story

A corrupt EA wants to learn how Ana voted. It cannot open the ciphertexts itself, so it asks the trustees to open a "section tally" in which the sum for option A of contest 0 has been replaced by Ana's own ballot box. If the trustees open it, the result is Ana's vote.

The trustee's check refuses it. `trustee_decrypt` recomputes the section tallies from the board, and the object the EA handed over is not equal to the recomputed one. So the trustee signs nothing. The test `doctored_section_tally_is_refused` does exactly this swap: the honest section tally is accepted, the swapped one is refused, and a pool with a different `tree_size` is refused too.

The check is not about the trustee believing the EA. It is about the trustee recomputing from the board, and comparing bytes.

## The code, function by function

The number is the line of the definition in `crates/eg-core/src/authority.rs`, unless the row names another file.

| function | line | what it does | why |
|---|---|---|---|
| `tally`, `decryption` | 52, 56 | build an `Error::Tally` or `Error::Decryption` | every refusal names its stage |
| `NO_FINAL_BU` | 62 | the all-zero id used for a section with nothing to open | spec issue 21 |
| `BoardView` | 65 | the manifest, context, entries, cutoff index, registry, packages and rejections | the single input of every later stage |
| `BoardView::election` | 83 | the `Election` the ballot checks use | one place builds it |
| `ViewPackage` | 94 | one accepted package: its ids, machine, section, region, offered contests, pre-BU, judged cast ballots and spoiled ballots | what every stage reads |
| `entry_tag` | 117 | the type tag (field 0) of a board entry | finds `tally_cutoff` |
| `ballots_of` | 122 | cast and spoiled ballots of a journal, in journal order | the same walk as `Session::import_recovered` in `machine.rs` (file 23), written separately |
| `pre_bu_of` | 141 | the machine-signed pre-BU of a package's journal | refuses a pre-BU the machine did not sign |
| `board_view` | 159 | ingests up to the cutoff and judges every cast ballot with one set of reservations | §17.7 and §12.6 |
| `zero_sums` | 258 | a zero sum for each homomorphic contest | the pool starts from these |
| `exclusions` | 277 | per contest, how many cast ballots were excluded (a malformed ballot excludes all its contests) | the `excluded` column of the result |
| `add_counts` | 298 | adds one count map into another | totals of exclusions |
| `section_tallies` | 312 | one section tally per pre-BU: sums, the pooled split, the fingerprint and its flag | §18.1 |
| `pool_tally` | 361 | the pool: pooled sums of every section plus the uncovered packages' ballots | §18.2 |
| `encrypted_tally` | 393 | the index of section tallies and the pool, at the cutoff's tree size | §18.3 |
| `mix_plan` | 410 | the mix units and their input lists, from the non-superseded packages | §19.1 (through `plan` in `crates/eg-core/src/mixnet.rs`) |
| `Target` | 428 | what a trustee opens: a section tally, the pool, or the final mix list | §20.1 |
| `Target::digest` | 445 | the RecordId the share proofs bind to | §20.1 |
| `Target::items` | 456 | the ciphertexts to open, in canonical order | §20.1 |
| `trustee_decrypt` | 481 | the trustee's refusal check, then signs the share set | §20.5 |
| `verified_sets` | 583 | the share sets that decode, come from a trustee, verify, and name the target if one is given | the filter before `combine` |
| `trustee_keys` | 603 | the trustees' signing keys in index order | for `check_final_bu` |
| `final_bu` | 612 | assembles a section's final BU from verified share sets | §16.5 |
| `Tot`, `Tot::add` | 646, 653 | running counts of one contest (counted, invalid, votes) | used by `election_result` |
| `contests_sorted` | 666 | the manifest's contests in ascending index order | result order |
| `TallyInputs` | 674 | the final BUs, the pool's share sets, and each mix unit's steps and share sets | what the caller supplies |
| `election_result` | 691 | recomputes and checks the sums, checks each final BU and the pool, counts the mix units, and produces the result with seats | §21 |
| `crates/eg-core/src/decrypt.rs`: `check_final_bu`, `combine`, `decode_sums` | (file 20) | recombine the shares, compare the decoded results, and turn points into counts | §16.5, §20.2, §20.4 |
| `crates/eg-core/src/mixnet.rs`: `plan`, `check_mix_chain` | (file 22) | the unit plan and the mixer chain check | §19.1, §19.2 |

## Attacks each check stops

| attack | what stops it |
|---|---|
| a ballot copied into another package to count twice | the single `Reservations` for the whole board: the later copy is excluded and counted as excluded (file 18, `same_ballot_cast_twice_is_excluded_by_reservation`) |
| a corrupt EA hands trustees one voter's ballot as a section total | `trustee_decrypt` refuses any section tally that is not byte-identical to the board's recomputation (`doctored_section_tally_is_refused`) |
| a corrupt EA hands trustees a doctored pool | `trustee_decrypt` refuses a pool that is not `pool_tally(view, sections)` (also `doctored_section_tally_is_refused`) |
| a machine's section tally that does not match its pre-BU | the section is reported with `matches = false`, and the valid votes are still counted (`broken_proof_ballot_is_excluded_and_its_section_mismatches`) |
| a ballot with a broken proof in one contest | only that contest is excluded, and the rest of the ballot counts (file 18); the section then mismatches |
| a ballot encrypted under the wrong key | the mixnet slot proofs still pass, so the row is counted as invalid (§19.6); the homomorphic contests exclude it (`broken_proof_ballot_is_excluded_and_its_section_mismatches`) |
| a share set from an unknown trustee, with a bad signature, or for another target | `verified_sets` drops it before `combine` sees it (file 20) |
| a trustee with a share that does not match its `Z_j` | `combine` rejects its proof, and `trustee_decrypt` refuses to sign if `z_j` is wrong (`z_j does not match Z_j`) |
| a final BU whose numbers differ from what the shares prove | `check_final_bu` refuses (file 20) |
| fewer than `k` valid trustees | `combine` refuses: the decryption is incomplete, and nothing is published as a result |
| packages after the cutoff counted | `board_view` ingests only entries up to the cutoff, so later entries cannot change the tally |
| a pool that is too small to protect its voters | nothing in code yet: §18.3 asks the verifier to flag it, and `eg-core` has no such flag. Until it does, a small pool is published silently |

## Design choices

- **One reservation set, in board order, for the whole board.** A replay is the same bytes in another package. Judging per package would count it once in each. The spec says the α rule is global (§12.6).
- **Recompute, do not trust.** `section_tallies` and `pool_tally` are recomputed every time they are needed. `trustee_decrypt` and `election_result` compare what they are given with the recomputation. Nothing is taken from a caller on trust.
- **The mismatch flag does not block the count.** §18.1 says the board's recomputed tally is the one opened, so an honest voter's vote is not lost because a machine's pre-BU was wrong. The machine is reported instead.
- **Every homomorphic contest is in the pool.** Even an empty one has a zero sum. The result then has the same shape in every election, so a missing row cannot hide a contest.
- **The target digest is the record id of what is opened.** A share set names the thing it opens, and its proofs bind to that name. For sections and the pool, `final_bu` and `election_result` both require the set to name the right target. The mix path is the exception (spec issue 23).
- **Seats come from the totals after the checks.** `election_result` computes party totals and seats only from the votes it has already verified, so the seat step never sees an unchecked number (file 17).

## Tests (4 in `authority.rs`)

- **End to end:** two sections, a mixnet contest with two units, one spoiled ballot, and a proportional contest. The result matches the cast choices, every section matches its pre-BU, and the seats are present (`end_to_end_election_matches_the_cast_choices`).
- **Pool:** a threshold of 100 pools every contest, and the pool total is the election total (`pooled_election_counts_through_the_pool`).
- **Trustee refusal:** an honest section tally is opened, a swapped one is refused, and a pool with a different tree size is refused (`doctored_section_tally_is_refused`).
- **Broken proofs:** a wrong-key ballot is excluded in the homomorphic contests, counted as invalid in the mixnet contest, and its section reports `false` while the others report `true` (`broken_proof_ballot_is_excluded_and_its_section_mismatches`).

**Not tested in `authority.rs`:**

- a missing import (the silent drop above);
- a double import (spec issue 22);
- a `z_j` that does not match `Z_j` (the code is there, the test is not);
- a mix input that differs from the plan, which is tested in file 22 but not through `trustee_decrypt`;
- `election_result` called with sections or a pool that differ from the board. The code refuses them, and the tests do not check that path.

## Spec gaps and issues relevant here

- **Spec issue 19 (judging order).** The machine judges imports first and then its own ballots, with its own reservations (`section_sums` in `machine.rs`, file 23). This module judges everything in board order with the board's reservations. The two agree when there is no shared α, and they can disagree when one exists. The spec should state the order.
- **Spec issue 20 (nonce reuse reports both contests).** The later contest is excluded and counted, and nothing names the earlier one. `exclusions` only counts. The verifier must keep the reservation history and report both, and this module does not.
- **Spec issue 21 (a section with everything pooled).** `election_result` uses the all-zero digest as the final BU id (`NO_FINAL_BU`), and `final_bu` refuses such a section. The spec should allow an absent final BU.
- **Spec issue 22 (double import).** `section_tallies` covers the same recovered package in both sections, and nothing refuses it. This is a double count, and the board does not forbid it.
- **Spec issue 23 (the mix target's digest).** `election_result` passes `None` as the target for the mix share sets, so a set's target is never compared with the RecordId of the last mix output. `combine` checks each set's proofs against the target the set names, so a set made for some other target still verifies, provided it covers the same α values. Those shares would then be the same openings, so the damage is limited. The binding to the last mix output is only in the trustee's signature, and the verifier should compare the digest, as spec issue 23 says.
- **Spec issue 24 (a wrong-key slot).** The invalid count is the only trace of a machine that encrypted under the wrong key. The wrong-key test above shows this.
- **Not yet in `spec-issues.md`: section tallies need `tally_cutoff`.** §16.5 and §18.1 say a section tally can be opened as soon as its packages are on the board, on election night, before the cutoff. §20.5 says the same. `board_view` returns an error without a `tally_cutoff` entry, and every stage starts from a view. So this code cannot open a section tally before the cutoff. The spec and code disagree.
- **Not yet in `spec-issues.md`: the trustee does not check imports.** §20.5 requires the trustee to check that every imported recovered package is accepted. `trustee_decrypt` checks only that the section tally is byte-identical to the board's recomputation, and that recomputation drops a missing import silently (above). A trustee can therefore sign a section whose fingerprint does not match.
- **Not yet in `spec-issues.md`: the verifier's `section_tallies` is not `section_sums`.** `section_sums` in `machine.rs` has a doc comment that says verifiers share it. In fact only the machine calls it. The verifier uses `section_tallies`, which judges board-wide. Both use `judge_cast`, so the sums agree when no α is shared across the two, but they are different functions.
