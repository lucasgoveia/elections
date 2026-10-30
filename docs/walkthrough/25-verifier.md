# 25 · The verifier: checking a board in 16 steps

**Code:** `crates/eg-verify`. `src/lib.rs` (the entry point, the `Report`, the ledger), `src/board.rs` (steps 1 to 5), `src/packages.rs` (steps 6 to 8), `src/tally.rs` (steps 9 to 12), `src/result.rs` (steps 13 to 16). Tests in `tests/verify.rs`, with the board builder in `tests/support/mod.rs`. **Spec:** §23 (the 16 steps), §2.4 (what rests on the election authority's word), and the sections of §17 to §22 that each step re-reads.

**Scope of this file.** The verifier takes a board dump and at least one signed tree head, and returns a report. It talks to no one, it trusts no key it has not been given, and it does not run the machines or the trustees. It is the program that anyone holding the board can run to check the result. It is not yet independent of the code that produced the board; see "The deviation" below.

## The problem

A voter, an observer or a party does not want to accept the result on the word of the election authority (EA). The protocol already gives each voter a receipt and each observer a paper record. The verifier answers the question the receipts cannot: **does the published result follow from the public board, all of it, with every rule applied?**

It also has to answer that question in a useful way. "FAIL" is not enough. A checker that says FAIL without saying who misbehaved, at which entry, and against which rule is no help to the party that has to act on it.

## The idea, without math

Think of an auditor who is given the whole ledger of an office and asked to sign a statement that the totals are right. The auditor works through a fixed checklist, in order:

1. Is the ledger complete and unchanged? (Are the signed tree heads consistent with the entries?)
2. Is the charter genuine? (Is the manifest signed by the EA, and is it well formed?)
3. Was the joint key made honestly? (Every trustee's ceremony message checks out.)
4. Does everything name the same key ceremony?
5. Were the registry and the rules frozen before polls opened?
6. Is every package on the board one that the rules allow, and which ballots were thrown out and why?
7. Is anything missing, duplicated or out of place?
8. Do the spoiled ballots open to what they claim?
9. Do the sub-totals add up to the same bytes as the board?
10. Do the mixes follow the rules?
11. Do enough trustees agree on each opened total?
12. Does every final total match its sub-total?
13. Recompute the counts from the verified parts.
14. Recompute the seats.
15. Compare with the result that was published.
16. Write down who this result depends on, and who did not show up.

Each step either passes or adds a **finding**. Steps do not share state except through the ledger described below. The checklist stops early only when the board is too broken to read (no manifest, a ceremony that does not verify, or a board that cannot be tallied at all). Those cases are described under step 3 and step 6.

## Inputs and the report

```rust
pub fn verify(entries: &[Value], sths: &[Value]) -> Report
```

(`lib.rs:107`.) `entries` is every board entry in order, entry 0 first. `sths` is at least one signed tree head, from the board or from a mirror.

The output is a `Report` (`lib.rs:50`), with five parts. They are not the same kind of thing, and the difference matters when reading the output.

| part | field | what it means | does it make the result FAIL? |
|---|---|---|---|
| failures | `failures: Vec<Finding>` | an invariant is broken: a signature does not verify, a number is wrong, a rule is not met | yes: `passed()` (`lib.rs:69`) is true only when this is empty |
| warnings | `warnings` | something needs attention but breaks no invariant: a missing optional record, a pool below `min_section_ballots`, a package the board refused, a release log that was not checked | no |
| excluded | `excluded` | every ballot or contest that §12.6 left out, with its machine, session, ballot and the failing check | no, but it is the list that explains the count |
| independence | `independence: Independence` | what rests on the EA's word alone (§2.4, step 16): trustees, release signers, mirrors, the three bloc rules, party key fingerprints, sections without an observer signature, parties that did not observe | no |
| result | `result: Option<ElectionResult>` | the result the verifier recomputed from the board | no, but step 15 compares it with the published one |

Every `Finding` (`lib.rs:38`) has four fields: the step of §23 it belongs to (`step`, 1 to 16), the board entry index if one entry is at fault (`entry`), the section of this spec it breaks (`section`, for example `"§12.6"`), and a message. The message names the machine, the session, the trustee or the contest, so that the finding can be read without the code. Excluded findings always have step 6.

Two details of the report are easy to miss.

- The report also carries `context_hash`, the hash recomputed from the key ceremony at step 4.
- A failure in step 16 for rules 11 to 13 is filed under step 2, not 16 (`result.rs:248` to `257`). That is the one place where the step number on a finding does not match the step that produced it. The text says "§7.2", so it can be read correctly, but a tool that groups findings by step will put it under 2.

## The ledger: one pass over the board

Most steps need to know the verdict the board gave each entry, and the list of accepted packages. The verifier runs the board once through the eg-core ingester and keeps the result in a `Ledger` (`lib.rs:141`, built by `Ledger::run` at `lib.rs:156`).

`Ledger::run` does four things:

- it feeds every entry to `BoardState::ingest` (`eg_core::package`, file 21), which applies the board's rules of §17.6 and §17.7, and keeps one verdict per entry (`Accepted` or `Rejected(reason)`);
- it keeps the accepted packages and the accepted section attestations;
- it builds the list of observers in force: the observers the registry names, plus each accepted `observer_cert` that verifies under a party key, minus each accepted `observer_revoke`;
- it records which parties have an accepted observer certificate (`cert_parties`), for step 16.

`Ledger::is_observer` (`lib.rs:210`) asks whether a key is in that observer list. The helpers `fail`, `warn` and `exclude` (`lib.rs:216`, `232`, `248`) add a finding to the report, and `tag`, `uint_at`, `text_at` (`lib.rs:263` to `273`) read fields of a CBOR record. `fingerprint` (`lib.rs:278`) gives the 16-character fingerprint of a key, used everywhere the report prints a key. `entry_id` (`lib.rs:284`) is the RecordId of an entry. `records_of` (`lib.rs:291`) decodes the records of a package with the machine's key, or of a recovered package without one.

## The 16 steps

Each step below gives: what it checks; which records it reads; what misbehaviour it catches; and who it names. "Names" means the finding's message identifies the party, so the report can be sent to them.

### Step 1: the board (`board.rs:59`, `step1_board`)

- **Checks.** Every STH is signed by the board key, or by a mirror key (§17.4). It names this manifest. It covers no more entries than the dump. Its root is the root of the dump at its size. Every pair of STHs is consistent: the same size means the same root, and a different size needs a consistency proof from the dump (`check_sth_pair`, eg-core `board.rs`, file 15).
- **Reads.** The STHs given to `verify`, the manifest (for the board key and the mirror keys), the Merkle log built from the dump (`build_log`, `board.rs:14`).
- **Catches.** A board that shows two views: two STHs at one size with different roots (equivocation, §17.4). A tree head that does not match the entries it claims to cover.
- **Names.** The board (no entry index, since the fault is in a tree head). The message gives the STH index, its size and the sizes of the two heads that disagree.

### Step 2: the manifest (`board.rs:25`, `step2_manifest`)

- **Checks.** Entry 0 is a `signed_manifest`, and the EA's signature on it verifies. `open_signed_manifest` (eg-core `manifest.rs`, file 12) also runs the manifest's well-formedness rules (§7.2).
- **Reads.** Entry 0.
- **Catches.** A board whose first entry is not the manifest, or a manifest the EA did not sign. An empty board stops here.
- **Names.** The EA (the manifest is signed by the EA's key). If the manifest does not open, verification stops and returns the report.

### Step 3: the key ceremony (`board.rs:171`, `step3_ceremony`)

- **Checks.** Every Round 1, Round 2, Round 3, complaint and reveal record of the ceremony verifies (§8.1 to §8.5), with `verify_ceremony` (eg-core `ceremony.rs`, file 11). That includes: all trustees accepted the same transcript; every complaint has a valid reveal; and the joint key `K` and the verification keys `Z_j` are recomputed. The trustees' organisations and key fingerprints go into the independence report.
- **Reads.** Every `dkg_round1`, `dkg_round2`, `dkg_round3`, `dkg_complaint` and `dkg_reveal` entry, and the manifest's trustee list.
- **Catches.** A missing round, a bad proof, a trustee that did not accept the transcript, a complaint that has no valid reveal, a joint key that is not the one the shares give.
- **Names.** The ceremony has no entry index for most faults, because the fault is in the set of records as a whole (for example, a missing round 3 names no entry). When the ceremony does not verify the function returns `None` and `verify` stops: no later step can run without a context.
- **Note.** A complaint that is answered by a valid reveal is the protocol working as designed. The verifier does not report it as a failure. See the attack table in file 26 for the simulator's `bad_dkg_share` switch.

### Step 4: the context (`board.rs:217`, `step4_context`)

- **Checks.** The context hash is taken from the ceremony (step 3). Every `polls_open` and `tally_cutoff` entry that verifies under the EA key must name that same hash (§9, §17.7).
- **Reads.** The `polls_open` and `tally_cutoff` entries. The context from step 3.
- **Catches.** A polling record that was signed for another election or another key ceremony.
- **Names.** The entry index, and the EA (it signed the record). A record that does not verify is left to step 5.

### Step 5: the freeze (`board.rs:253`, `step5_freeze`)

- **Checks.**
  - There is exactly one `polls_open`. A second one is a failure.
  - No `signed_registry` or `software_policy_update` comes after `polls_open` (§7.7, §24.4). Any such entry is board misbehaviour, whatever the reason.
  - Every entry the board refused, among the registry, policy, polls and cutoff records, is a failure. Its reason is given.
  - Every `signed_registry` verifies under the manifest (§7.7).
  - `polls_open` names the registry in force, which is the last registry before it (§17.7).
  - There is exactly one `tally_cutoff`, after `polls_open`, and it verifies under the EA key (§17.7).
  - A `software_policy_update` gives a **warning**, and so does the release records check. See "The release-log gap" below.
- **Reads.** `polls_open`, `tally_cutoff`, `signed_registry`, `software_policy_update`, and the verdicts in the ledger.
- **Catches.** A registry swapped in after the polls opened (the registry is the list of who may vote and on which machine, so changing it late changes the election). A second cutoff. A polls record that names another registry.
- **Names.** The entry index of the offending record, and the EA for a bad signature on `polls_open` or `tally_cutoff`.

### Step 6: the packages and the judging of ballots (`packages.rs:51`, `step6_packages`)

- **Checks.**
  - It builds the board view with `board_view` (eg-core `authority.rs`, file 24). This is the same function the trustees and the result use. Its only input is the board.
  - Every `observer_cert` and `observer_revoke` verifies under some party key (§16.3).
  - Every package the board refused gives a **warning**, with the reason. A rejection is not always the board's fault.
  - Every `rejection` entry must verify under the board key, and must name a package that really was refused. A rejection that names an accepted package is a failure. A rejection that names no package on the board is a failure.
  - For each non-superseded cast ballot, §12.6 is applied: a malformed ballot is excluded from every contest, and a contest excluded by α reservation (nonce reuse) is listed with **the other ballot that holds the same α**. Each exclusion becomes an `excluded` finding with its machine, session and ballot number.
- **Reads.** All entries, the registry, the cutoff. The packages and recovered packages through `board_view`.
- **Catches.** A package the board should have refused and did not; a rejection that is a lie; a ballot that is not well formed; a ballot whose contest reuses an encryption nonce (α) already used by another ballot. That last one is listed twice, once for each ballot, as spec issue 20 asks.
- **Names.** The machine and session of every excluded ballot, and the other ballot in a nonce reuse. Rejected packages are warnings and name the entry index.
- **If the board cannot be tallied at all** (for example, the cutoff is missing), `board_view` returns an error, step 6 records a failure, and `verify` stops.

### Step 7: completeness (`packages.rs:237`, `step7_completeness`)

This is the longest step, because it looks for what is **missing**, not what is wrong. Each check below is a separate loop in the code.

- **Sections and machines.** Every registered section must have an accepted package before the cutoff (failure). A registered regular machine with no accepted package is a warning. Reserve machines are idle unless needed.
- **Attestations (§16.3).** Every accepted `section_attestation` names a record: a pre-BU or a zerésima, with its machine and session. That record must have a package on the board. The pre-BU or zerésima in the package must have the same RecordId as the one attested. A missing package, a different pre-BU (the message gives the chain head and frame digest of each), or a different zerésima is a failure.
- **Two pre-BUs for one session (§16.2).** For each machine and session, the verifier collects every machine-signed pre-BU from the packages and from the attestations. Two different ones are a failure. This is the test for a machine that signs two stories about one session.
- **Imports (§16.4, spec issue 22).** A recovered package that no pre-BU imports is a failure. A recovered package imported by two pre-BUs is a failure (double count).
- **Disagreeing media.** Two different recovered packages for one machine and session are a failure, because the paper copies of the journal disagree.
- **Reserve machines (§7.7).** A reserve machine must serve one section only, and its contests must equal those of the section's regular machines. The code does not check the poll worker keys, which the spec also asks for (see the gaps below).
- **Cast totals (§16.2, §7.7).** For each section, the number of cast ballots must be at most the largest voter-roll count in its pre-BUs or recovered packages, and at most its eligible voters. A section that breaks either is a failure.
- **Observer signatures.** For each section, the verifier looks for an observer's signature on a zerésima or a pre-BU, or on an attestation signed by a key that is not a poll worker. A section with none goes into `independence.sections_without_observer`. That is not a failure: it is a fact the report must show (§2.4, §28.18).
- **Reads.** The view, the attestations, the packages (decoded again with the machine keys), the recovered packages, the registry, the ledger's observer list.
- **Catches.** A section with no package, a package that was dropped by the board, a pre-BU that differs from the one the machine attested, a machine that signed two versions of one session, a recovered journal that nobody imports (or two that import the same one), two recovered copies that disagree, a reserve machine that serves two sections, more ballots in a section than the voter roll allows.
- **Names.** The section (by id), the machine and session, and the entry index where there is one. For the observer report, the section.

### Step 8: spoiled ballots (`packages.rs:646`, `step8_spoiled`)

- **Checks.** Every spoiled ballot's reveal (§14.2) names that ballot, and re-encrypts to it byte for byte (`check_reveal`, eg-core `ballot.rs`, file 13).
- **Reads.** The spoiled ballots and reveals of the view's packages.
- **Catches.** A reveal that claims other choices than the ballot holds on the board, a reveal for another ballot.
- **Names.** The machine and session of the ballot, and the entry index of its package.
- **What it does not see.** Step 8 only checks the reveals that the board holds. A spoil receipt that a voter keeps, and that differs from the board's reveal, is not on the board, so this step cannot see it. See file 26 for the case where the machine's receipt lies and the voter's own check catches it.

### Step 9: the homomorphic tally (`tally.rs:34`, `step9_homomorphic`)

- **Checks.**
  - It recomputes the section tallies (one per pre-BU), the pool and the encrypted tally at the cutoff's tree size, with `section_tallies`, `pool_tally` and `encrypted_tally` (eg-core `authority.rs`, files 18 and 24).
  - For each pre-BU, its fingerprint (field 14) must equal the fingerprint of the recomputed section tally. A mismatch is a failure, with the machine and session named.
  - Every `section_tally`, `pool_tally` and `encrypted_tally` on the board must equal the recomputed one **byte for byte** (`cbor::encode` on both sides). A published section tally for a pre-BU that is not on the board is a failure.
  - Warnings: a section tally that is not published, no pool tally published, no encrypted tally published, and any contest in the pool with fewer than `min_section_ballots` counted ballots (§18.3).
- **Reads.** The view, the tree log (for the root at the cutoff), the pre-BU fields, the published tallies.
- **Catches.** A machine whose pre-BU covers other ballots than the board holds (the subtotal it signed is not the sum of the board's). An EA that publishes a doctored tally.
- **Names.** The machine and session for a fingerprint mismatch. The section for a tally that differs. The contest number for the pool warning.
- **What it does not catch.** The section that mismatches still has its valid ballots counted (§18.1). The mismatch is a finding, and the count goes on. See file 24.

### Step 10: the mixnet (`tally.rs:205`, `step10_mixnet`)

- **Checks.**
  - The planned mix units come from `mix_plan` (eg-core `authority.rs`, file 24), which uses the same plan that the mixers started from.
  - Each `mix_output` names a contest, a mixer index and a region. It must be signed by the trustee with that index, under the trustee's signing key.
  - For each unit, the steps are put in order, and `check_mix_chain` (eg-core `mixnet.rs`, file 22) checks the whole chain: each step's input is the previous output, every shuffle proof verifies, and at least `mix_policy.min_mixers` trustees mixed (§19.2, §19.3). It returns the final list.
- **Reads.** The view (for the plan), every `mix_output` entry, the manifest's trustees and mix policy.
- **Catches.** A mixer that signs a step with a key that is not a trustee's. A mix output for a unit the board did not plan. A broken shuffle proof. A step whose input is not the previous output. A unit mixed by too few trustees.
- **Names.** The trustee index for an unsigned or wrong-key output, and the contest and region for a broken chain.
- **Note.** The step uses the eg-core chain check, so the verifier is re-checking the same code as the mixers. See the deviation below.

### Step 11: decryption shares (`tally.rs:308`, `step11_decryption`)

- **Checks.**
  - It builds the list of **targets**: each non-empty section tally, the pool, and the final list of each mix unit. A target's digest is the RecordId of what is opened (§20.1). For a mix unit it is the RecordId of its last `mix_output` (spec issue 23).
  - Each `decryption_shares` entry is decoded with the signing key of the trustee it names (§20.1). A set that does not verify is a failure and is discarded (§20.3).
  - A set that names no target on the board is a failure.
  - For each target, `combine` (eg-core `decrypt.rs`, file 20) checks every trustee's proofs against the target's items and keeps the lowest `k` valid trustees. A trustee whose proofs fail is reported as `rejected` by `combine`, and the verifier makes each one a failure naming the trustee. Fewer than `k` valid sets is a failure.
  - The verifier keeps the valid sets, keyed by the target they name (`VerifiedSets`), for steps 13.
- **Reads.** Every `decryption_shares` entry, the targets from steps 9 and 10, the manifest's trustees (`k`).
- **Catches.** A trustee's signature that does not verify, a share set made for another target, a share that does not match the trustee's commitments, a decryption that cannot be completed.
- **Names.** The trustee index in every message, and the entry index of the share set. Decryption goes on with the valid trustees, so the result is still recomputed (the test below checks this).

### Step 12: final BUs (`tally.rs:437`, `step12_final_bus`)

- **Checks.** Each `final_bu` (§16.5) decodes. The section tally it names must be one the board holds. `check_final_bu` (eg-core `decrypt.rs`) recombines the shares and compares the decoded numbers with the final BU's numbers. There is at most one final BU per section. Every section with contests to open must have one.
- **Reads.** Every `final_bu`, the section tallies from step 9, the trustees' signing keys, `k`.
- **Catches.** A final BU whose numbers differ from what the shares prove, a second final BU for a section, a section whose final BU is missing.
- **Names.** The section, and the entry index of the final BU.

### Step 13: the counts (`result.rs:22`, `step13_counts`)

- **Checks.** The verifier calls `election_result` (eg-core `authority.rs`, file 24) with everything it has verified: the view, the section tallies, the pool, the final BUs, the pool's share sets, and each mix unit's final list with its share sets. This is the same function that the EA's pipeline uses, so the counts come out of the verified parts. Homomorphic contests come from the final BUs and the pool; mixnet contests come from the decrypted mix units (§19.6, §21).
- **Reads.** The outputs of steps 9 to 12.
- **Catches.** Nothing by itself. Its role is to give step 15 a number to compare. If `election_result` refuses (for example, because a section was not verified), the error is a failure, and `result` stays `None`.
- **Names.** Nothing: it is a computation.

### Step 14: the seats (`result.rs:92`, `step14_apportionment`)

- **Checks.** For every **published** result (`decode_published`, `result.rs:66`, which checks the result against the EA key, §21), each proportional contest's party totals and seats are recomputed from its own vote counts with `party_totals` and `apportion` (eg-core `apportionment.rs`, file 17). A difference is a failure.
- **Reads.** The published `result` entries and the manifest's contests.
- **Catches.** An EA that publishes seats that do not follow from the votes it published (§22).
- **Names.** The EA's result entry, and the contest number.
- **Note.** The seats are checked against the **published** votes, not the recomputed ones. Step 15 checks that the two sets of votes are the same, so together they cover both.

### Step 15: the result (`result.rs:145`, `step15_result`)

- **Checks.** The published result must equal the recomputed one. A difference is a failure. The message names the contests whose votes or counts differ, and says whether the sections or the pool differ. If no result is published, the report has a **warning** and carries the recomputed result alone.
- **Reads.** The published `result` entries and the recomputed result from step 13.
- **Catches.** A published count that is wrong: an EA that added votes, dropped a contest, or changed a section.
- **Names.** The EA (the result is signed by it), by entry index, and the contests that differ.

### Step 16: the independence report (`result.rs:205`, `step16_independence`)

This step does not check a signature. It writes down, for a reader, who this result depends on. It fills `rep.independence` (see the next section), and it checks the three bloc rules of §7.2:

- **Rule 11.** No bloc holds `k` or more trustees.
- **Rule 12.** No bloc holds `k_r` or more release signers.
- **Rule 13.** At least two mirrors are outside the EA's bloc.

A failure of any rule is a failure, filed under step 2 (see the note on the report).

- **Reads.** The manifest (trustees, release signers, mirrors, parties, the EA's bloc), the ledger's list of parties with an observer certificate.
- **Catches.** A manifest whose trustees or mirrors are all in one bloc, which means the independence the spec promises does not exist.
- **Names.** The blocs, by name.

### Who the findings name

| party | steps that name it | what they are blamed for |
|---|---|---|
| the board | 1, 5, 6 (warnings) | an STH that does not match the entries, two views of the log, a board that refused a registry or a cutoff |
| the EA | 2, 4, 5, 14, 15 | a manifest that does not open, a context hash or registry the ceremony does not give, a result that does not follow from the votes or from the board |
| a trustee | 3, 10, 11, 12 | a bad ceremony message, a mix step signed with a non-trustee key, a share set that does not verify or does not prove its numbers, a final BU that does not check |
| a machine (and its session) | 6, 7, 8, 9 | an excluded ballot, a pre-BU that does not match the board, a spoiled reveal that lies, two pre-BUs for one session, a dropped or duplicated package |
| a section | 7, 9, 12 | no package, too many cast ballots for its roll, a tally that differs |
| a party or observer | 6, 16 | an observer certificate that does not verify, parties that did not observe |

## The independence report

`Independence` (`lib.rs:76`) is what §2.4 says a reader should be able to see. It has seven parts.

- **`trustees`** (step 3): each trustee's organisation, bloc and signing-key fingerprint.
- **`release_signers`** (step 16): the signers of the software policy, with bloc and fingerprint.
- **`mirrors`** (step 16): the mirrors of the manifest, with the operator, bloc and fingerprint.
- **`rules_11_13`** (step 16): the three bloc rules, each with its result.
- **`party_keys`** (step 16): every party of the manifest with the fingerprint of its key, if it has one.
- **`sections_without_observer`** (step 7): each section where no zerésima or pre-BU carries an observer signature.
- **`parties_without_observer`** (step 16): each party with no accepted observer certificate. These are the independent parties that did not take part in observing.

A fingerprint is the first 8 bytes of SHA-256 over the public-key bytes, in lower-case hex (16 characters). It is printed so that a reader can compare it with the value a trustee or a party publishes itself.

In the honest test board, the report says that both sections have no observer signature and that both parties have no observer certificate. That is a true fact about the test board, not a failure: the test board is built without observers.

## The deviation: the verifier reuses eg-core (spec issue 9)

§23 says the verifier **MUST NOT** depend on code used to produce ballots, packages or tallies. The reference build does depend on it. `docs/spec-issues.md` item 9 records this as a deliberate deviation for now, and the crate's own doc comment (`lib.rs:8`) says so.

The verifier takes from `eg-core` the following, which is not a small amount of code.

| what | where in eg-core | used at step |
|---|---|---|
| the Merkle log and STH checks | `board.rs` (`Log`, `check_sth_pair`, `record_id`) | 1, 4, 9 |
| the ceremony check | `ceremony.rs` (`verify_ceremony`) | 3 |
| the manifest check | `manifest.rs` (`open_signed_manifest`) | 2 |
| package ingestion and the §17.6 rules | `package.rs` (`BoardState::ingest`, `ObserverCert::from_signed`) | 5, 6, 7 |
| the §12.6 judging of every ballot, and the view | `authority.rs` (`board_view`, which uses `judge_cast`) | 6 |
| the spoil check | `ballot.rs` (`check_reveal`) | 8 |
| the sums, pool and index | `authority.rs` (`section_tallies`, `pool_tally`, `encrypted_tally`) | 9 |
| the mix plan and chain | `authority.rs` (`mix_plan`), `mixnet.rs` (`check_mix_chain`) | 10 |
| the share checks and decoding | `decrypt.rs` (`combine`, `check_final_bu`) | 11, 12 |
| the counts | `authority.rs` (`election_result`) | 13 |
| the apportionment | `apportionment.rs` (`party_totals`, `apportion`) | 14 |

What the verifier writes itself is the **orchestration and the cross-checks**: the order of the steps, the comparisons between records, the attestation and recovered-package checks of step 7, the observer and reserve-machine checks, the cast-against-roll check, the nonce-reuse holder in step 6, the independence report, and the bloc rules.

The consequence is plain. If a bug is in `judge_cast`, in `section_tallies`, in `check_mix_chain` or in `election_result`, the verifier and the election will agree on the wrong number. The verifier then reports PASS on a board that the spec would fail. That is the thing §23 exists to prevent. A fully independent reimplementation, written from the spec alone, is still needed before the verifier is used for a real election. The tests cannot show this, because the honest board and the tampered boards are both produced by the same eg-core code.

The point of the design still holds in part. Steps 1 to 4 and the cross-checks of step 7 are the verifier's own logic on the board's public records, so a tamper there is caught by code that is not the producer's. The parts that share code are the arithmetic.

## The release-log gap (§24 is not an input)

§24.3 says that release records and signatures go into a **release log**, a separate Merkle log with its own signed tree heads. The verifier does not take the release log as an input. `verify` takes only the board's entries and STHs.

What this means in practice:

- step 5 gives a **warning** that the release records and signatures are not checked. It gives a second warning when a `software_policy_update` adds approved hashes, because the k_r release signatures behind them are not checked either;
- step 16 lists the release signers in the independence report, but does not check that they signed anything;
- nothing checks that the release log shows the same view to every party. §24.3 says a release log that showed different views would let a secret release slip through. The verifier cannot see that.

So a software change approved on the board is taken on trust. The honest test board triggers only the standing §24 warning, and the wasm test checks that an honest run gives no other warning (file 26).

## Gaps found while writing this file

These come from reading the code against §23. None of them has a test. Each is listed so that it can be fixed or written into `spec-issues.md`.

1. **Observer certificates are not matched to their party (step 6, step 16).** The spec says each `observer_cert` is checked against its party key. The code tries every party key until one verifies the signature, and then takes `party_index` from the certificate itself (`eg_core::package::ObserverCert::from_signed`, `lib.rs:173` to `181`). It never checks that the key which verified the certificate belongs to the party the certificate names. A party could sign a certificate that names another party, and `parties_without_observer` would then count the wrong party as observing.
2. **Reserve machines: poll worker keys are not checked (step 7).** §23 step 7 asks that each reserve machine serves one section "with that section's poll worker keys and contests". The code checks the section and the contests, not the keys.
3. **"Published nothing" is only partly checked (step 16).** §23 step 16 lists as recommended independent parties those that published nothing: no observer certificate, no mirror tree head, no trustee message. The code checks only the observer certificate.
4. **Some failures are filed under the wrong step (step 16).** The bloc rule failures are filed under step 2 (see the note in the report section above).
5. **Two cases stop the run early.** A ceremony that does not verify (step 3) and a board that cannot be tallied (step 6) end `verify` with the findings so far. The report then has no result, and its independence report is incomplete (steps 7 and 16 never run). This is correct, but a reader should know that a short list of findings can mean "stopped", not "passed". `passed()` is still false in that case, because the stop itself is a failure.

## Tests

The tests are in `crates/eg-verify/tests/verify.rs`. They build a complete honest board with `honest()` (`tests/support/mod.rs:559`): a real key ceremony, two sections with machines, six contests, a mix, the decryption and the result. Each tamper test changes one thing and re-signs it with the key that a malicious party would hold, so that the tamper is a valid-looking record, not an unsigned one. The `reseal` helper (`support/mod.rs:264`) rebuilds a package after an edit so that it still passes the board's journal checks.

The test helpers are: `world()` (`support/mod.rs:63`), which runs the ceremony; `honest_packages` (`:551`); `honest` (`:559`); `session` and `session_under` (`:183`, `:196`), which make one machine's session with its voters; `reseal` (`:264`), which edits a package; `publish` (`:439`) and `sths` (`:522`), which put the records on a board and sign tree heads; `resigned_share_set` (`:591`); and `published_result` (`:609`).

### Tamper table

The tests in `verify.rs`, with the step that fails and the finding it produces. "Only" means the step is the only one with a failure. A failure in a step later than the tampered one can still appear in some tests; the table shows the steps that are actually asserted.

| tamper | test | step that fails | what the finding says |
|---|---|---|---|
| none: the honest board | `honest_board_passes` | none; `excluded` is empty | passes; the result equals the published one; both sections and both parties have no observer (reported, not failed) |
| the published result gets one extra vote, re-signed by the EA, with a fresh STH | `altered_result_vote_count_fails_at_step_15` | 15 only | "published result differs from the recomputed result", at the result's entry index |
| an STH signed by the board with a wrong root at size `tally_cutoff + 1` | `sth_with_a_wrong_root_fails_at_step_1` | 1 only | the STH has a root that does not match the dump |
| trustee 1's share set has one share moved, re-signed by trustee 1 | `corrupted_share_fails_at_step_11_and_decryption_continues` | 11 only | "share set of trustee 1 ... discarded", at the set's entry index; the result is still the honest one (trustees 2 and 3 cover every target) |
| a second `signed_registry` (version 2) after `polls_open` | `registry_after_polls_open_fails_at_step_5` | 5 only | "board misbehaviour: signed_registry ... after polls_open" |
| the round 3 record of trustee 1 is removed | `missing_dkg_round3_fails_at_step_3` | 3 only | the ceremony does not verify; the run stops there |
| machine M-S2-01's pre-BU fingerprint replaced, the package resealed by the machine | `pre_bu_fingerprint_mismatch_fails_at_step_9` | 9 only | the message names M-S2-01 and the fingerprint mismatch |
| machine M-S1-01's spoiled reveal claims another choice, resealed | `spoiled_reveal_that_claims_other_selections_fails_at_step_8` | 8 only | the message names M-S1-01 and says the reveal does not match |
| a `rejection` entry signed by the board naming an accepted package | `rejection_naming_an_accepted_package_fails_at_step_6` | 6 only | "rejection names a package that passes the rules" |
| a second S2 session encrypted under a key that is not the election key | `ballot_with_broken_proofs_is_excluded_and_reported` | 9 (failure) and 6 (excluded) | the ballot is excluded and its machine M-S2-01 is named; the S2 fingerprint no longer matches |
| garbage boards: empty; entry 0 not a record; a board of five entries; no STH; garbage after entry 0; forty `polls_open` records with no manifest | `malformed_boards_fail_without_panicking` | any; never a panic | every case reports a failure |
| resealing a package with no edits | `resealing_without_edits_reproduces_the_package` | none: a check of the test helper | the reseal gives back the same bytes |

The honest board is not a tamper. It appears here because it defines what "nothing wrong" looks like in the report.

### Tamper tests in the wasm crate

These are in `crates/eg-wasm/tests/native.rs`. They run the same verifier on boards made by the simulator (file 26), so they cover the same checks with a different board builder.

| tamper (by simulator switch) | test | step(s) that fail |
|---|---|---|
| `ea_alters_result` | `verify_ea_altered_result_fails_at_step_15` | 15 ("Result") |
| `trustee_lies` | `verify_trustee_lies_fails_at_step_11_and_keeps_result` | 11, and the result is still produced |
| `board_equivocates` | `verify_equivocating_board_fails_at_step_1` | 1 |
| `board_drops_package_of` | `verify_dropped_package_is_flagged_at_step_7` | 7 as a failure and as a warning |

### What is not tested

Most of step 7 has no test: the double import, the recovered package nobody imports, the disagreeing recovered media, the reserve machine serving two sections, the cast total above the roll, the attestation whose package is missing. Steps 10, 12, 13 and 14 have no tamper test of their own. Step 16 has no test for the bloc rules, and no test for gap 1 above. The pool warning of step 9 is never triggered by the tests. These are the first places to add tests before the verifier is used on a real board.

## Design choices

- **One report, four kinds of finding.** A failure, a warning, an excluded ballot and an independence fact are different things, and each has its own list. A reader can then see "the count is right, but three ballots were excluded and two sections have no observer" without any of it being read as a failure.
- **Every finding names a step and a section of the spec.** A finding is useful only if the reader can find the rule it breaks. The step and section are in every `Finding`.
- **Stop only when there is nothing to check against.** The verifier continues after almost every failure, because a single bad share set should not stop the count. It stops only when it has no manifest, no context or no tally view. That keeps one tampered record from hiding the rest.
- **Recompute, do not compare fields.** Steps 9 and 15 compare **bytes**: the published record is encoded again and compared with the encoding of the recomputed one. A comparison of a few fields could miss a difference in a field nobody looked at.
- **No record is trusted for what it says about itself.** A `rejection`, an `observer_cert`, a `section_attestation`, a `result`: each is checked against the key that should have signed it, and against the board's own records.
- **The verifier never panics.** Every decode error becomes a `Finding` (`lib.rs:16`, the malformed-board test).

## See also

- File 24 for the pipeline that the verifier calls at steps 6, 9, 10 and 13.
- File 26 for the simulator that produces the boards used in the wasm tests, and for the attacks listed above.
- `docs/spec-issues.md` items 9, 19, 20, 22 and 23, which are about the verifier and the authority.
