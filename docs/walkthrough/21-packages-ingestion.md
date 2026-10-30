# 21 · Packages and board ingestion: what the board accepts, and what anyone can check

**Code:** `crates/eg-core/src/package.rs`. **Spec:** §16.1 (package), §16.3 (observer certificates, revocations and section attestations), §16.4 (recovered packages and the truncation argument), §17.6 (the ingestion rules), §17.7 (polls open and tally cutoff), and §24.4 (the software policy update, which the board applies before polls open).

**Scope of this file.** `package.rs` has the package records and the `BoardState` ingester. `BoardState` is the code that decides which entries count. The board service runs it over entries as they arrive, and a verifier runs the same code over the same entries and must get the same answers (§23, step 6). It does not check ballot proofs (rule 8 is explicit about that), it does not check the subtotal fingerprint (file 18), and it does not check release signatures (§24.4, the verifier's job). Board entries that this module does not understand (key ceremony records, tallies, mix outputs, results, rejections) are accepted by `ingest` and checked by the verifier.

## The problem

Many parties write to one public log, and the log decides which machine packages count in the tally. Five things can go wrong, and each needs an answer:

1. **A package can be forged or altered.** The board must check that each package is signed by the machine that the frozen registry names.
2. **A package can arrive at the wrong time.** Before polls open, the EA could pre-load votes. After the cutoff, it could add packages after seeing the results. Both must be refused.
3. **The board can drop a package silently.** Observers who hold paper copies must be able to show that a package is missing, without relying on the board's word.
4. **A machine can die.** Its journal must still be recoverable, without giving a truncated journal the same weight as a complete one.
5. **The EA can pick the observers.** A party must be able to certify its own observers, so the EA cannot choose who watches for it.

The answers are the records in this file, and the rules `BoardState` applies to them.

## The idea, without math

`BoardState` is a state machine. It reads entries one at a time, in board order. For each entry it either accepts it, or refuses it with a reason. Its state is the frozen registry, the software approvals, the certified observers, the revoked observers, the sessions seen so far, and the accepted packages.

Two properties follow from this design:

- **Decisions are reproducible.** The board and the verifier both run `BoardState::ingest` over the same entries. Nobody's word is needed about what the board decided, because anyone can re-run the decision.
- **Refusals are reported.** A refused entry returns a reason. The board must publish that reason as a signed `rejection` entry (§17.6, file 15), so a dropped package is visible.

## The records

### Package (§16.1)

A package is the whole journal of a session, with a header, signed by the machine:

```
package = { 0: "package", 1: 1, 2: header, 3: [journal records], 4: Sign(machine_sk, "eg/v1/sig/package", fields 0..3) }
header  = { context_hash, machine_id, section_id, session_id, software measurement,
            ? attestation, record count, final frame digest, final chain head }
```

`build_package` makes one from a journal that ends in `session_close`. It takes the record count and the last frame digest from the journal, and the chain head from the `session_close` record. The package carries no attestation (field 7 is optional, and filled only when the machine's software policy requires one, §24.5).

The header is a summary that the board checks against the records (rule 5). If a header names a different machine, session or measurement than its journal, or a different count, frame digest or chain head, the package is refused.

### Recovered package (§16.4)

A dead machine cannot sign a package. A replacement machine, or a poll worker under supervision, builds a `recovered_package` from the surviving journal, cut at its last checkpoint (`build_recovered`). The poll workers and observers then sign it, not the machine:

```
recovered_package = { 0: "recovered_package", 1: 1, 2: header, 3: [journal records up to the last checkpoint],
                      4: voter-roll count at the time of failure, 5: [section signatures over fields 0..4] }
```

`RecoveredPackage::add_sig` adds a poll worker signature over `unsigned_value`, which is the object of fields 0 to 4. The header's frame digest and chain head come from the last checkpoint, so the header describes the cut journal, not the whole thing.

### Observer certificate and revocation (§16.3)

A party certifies its own observers with its party key. The key is in the manifest, field 5 of the party (file 12):

```
observer_cert   = { 0: "observer_cert", 1: 1, 2: context_hash, 3: party_index, 4: observer public key, 5: Sign(party_sk, "eg/v1/sig/observer-cert", fields 0..4) }
observer_revoke = { 0: "observer_revoke", 1: 1, 2: context_hash, 3: party_index, 4: observer public key, 5: Sign(party_sk, "eg/v1/sig/observer-revoke", fields 0..4) }
```

`party_key_sign` and `party_key_decode` build and check both, and `ObserverCert::sign` and `from_signed` (and the same pair for revocation) wrap them.

**Why a party certifies its own observers.** If the EA chose the observers, it could leave a party's observers out, or pick ones who would not object. A party certifying its own people means the EA is not in the loop.

**Why only before `polls_open`.** A party that colludes with the EA could certify keys after the election and use them to "witness" sections that never existed. So `on_observer_cert` refuses any certificate after `polls_open` (§16.3).

**Revocation.** A lost or stolen observer device is revoked by its party, at any time before the cutoff. `on_observer_revoke` enforces the rules: a party may revoke only keys that it certified (or keys nobody has certified yet), and never a key in the registry (a machine, a poll worker or an EA-registered observer). Revocation after the cutoff is refused.

### Section attestation (§16.3)

Observers who countersign a zerésima or a pre-BU publish the **full signed record**, not just its hash:

```
section_attestation = { 0: "section_attestation", 1: 1, 2: the full zeresima or pre_bu (with the machine's signature),
                        3: observer or poll worker public key, 4: Sign(sk, "eg/v1/sig/section", RecordId(field 2)) }
```

The signed bytes are the same as a `SectionSig` (file 19), so a poll terminal's signature and an observer app's signature are interchangeable. `SectionAttestation::create` and `verify` build and check it. `from_value` accepts only a `zeresima` or a `pre_bu` as the attested record.

**Why the full record.** This is the evidence that a package is missing. If observers hold a copy of a pre-BU whose package never reaches the board, the copy shows which machine, section, counts and chain head should have been there. The board's silence then becomes a claim that can be checked against paper.

### Software policy update (§24.4)

`PolicyUpdate` is signed by the EA. It adds approved software hashes and withdraws others. The board applies it before `polls_open`. After that it is refused, so the approved list is frozen with the registry. Checking that each added release has enough release signatures (§24.4) is the verifier's job, not this module's.

## The board state, field by field

| field | what it holds | set by |
|---|---|---|
| `manifest` | the election's manifest | `BoardState::new` |
| `context_hash` | the hash the election's context must have | `BoardState::new` |
| `next_index` | the index of the next entry on the board (every entry counts, rejected ones too) | `ingest` |
| `registry`, `registry_value` | the registry in force, and the `signed_registry` record it came from | `on_registry` |
| `polls_open`, `cutoff` | the two freezes | `on_polls_open`, `on_tally_cutoff` |
| `approved` | approved software hashes; starts from the manifest | `BoardState::new`, `on_policy_update` |
| `observers` | certified observer keys, with the party that certified each | `on_observer_cert` |
| `revoked` | revoked observer keys | `on_observer_revoke` |
| `sessions`, `sessions_per_machine` | one entry per `(machine_id, session_id)`, and the count per machine | `admit` |
| `packages`, `attestations` | the accepted packages and attestations, in board order | `admit`, `on_attestation` |

## The rules of §17.6, and the code that applies them

Each rule is applied to a `package` or `recovered_package` before it is accepted. The rule number is in the code's error message. The attack column says what the rule stops.

| rule | what it requires | where | the attack it stops |
|---|---|---|---|
| 1 | `polls_open` is on the board, and the package arrives after it and before `tally_cutoff` | `check_window` | votes added before the polls open, or packages added after the cutoff to pick the results |
| 2 | the signature verifies under the registered key of `machine_id`, in the registry frozen at `polls_open` | `on_package` (`machine`, `Package::from_signed`) | a forged package, or one from a machine the registry does not know |
| 3 | the context hash matches | `check_records` | a package from another election |
| 4 | the software measurement is on the approved list; if the policy requires attestation, the attestation verifies | `check_records` | unapproved software. The attestation check is not implemented (see gaps) |
| 5 | the journal frames re-chain to the header's frame digest, and the chain re-computes to the header's chain head. The header's machine, section, session and measurement match the journal | `check_records` (with `check_journal`) | a header that describes a different journal |
| 6 | the zerésima is signed by the machine, names this session and its `head_0`, and carries a poll worker signature | `check_journal` (`on_zeresima`), and `check_records` for the section and reserve rules | a session that never started empty (file 19) |
| 7 | every §15.4 invariant holds, including the poll worker signatures on authorizations and cancellations | `check_journal` | every journal fault in file 19 |
| 8 | ballot proof failures do **not** reject the package | not checked here; the tally excludes the ballot (file 18) | throwing away every honest ballot on a machine because one proof failed |
| 9 | the `(machine_id, session_id)` pair is not already on the board, and the machine has at most `max_sessions` sessions | `admit` | replaying a session under a second package, and flooding the board with sessions |

### Rule 8 in detail

This is the rule most likely to be misread. Suppose a machine's package contains one ballot with a broken proof. If the board rejected the package, every honest voter on that machine would lose their vote. So the spec does the reverse: the package is accepted, the bad ballot is excluded, and the exclusion is reported. The package then stands as evidence against the machine, and the honest voters keep their votes (`ballot_with_broken_proof_still_accepted`).

### Reserve machines (§7.7, spec issue 10)

A registry may name a **reserve machine**, one with an empty section. It can serve any section in its place. `check_records` enforces two things about it, since the registry cannot check them on the day it is made:

- its offered contests must equal those of the regular machines of the section it serves;
- all of its sessions must name the same section.

Without these, a reserve machine could carry a different section's votes into the tally under the registry's name.

## Recovered packages (§16.4)

`on_recovered` accepts a recovered package under rules 1, 3, 4 and 7 to 9, and adds:

- the journal must end at a checkpoint, and that checkpoint must be valid (`check_journal` with `complete = false`);
- at least one section signature must verify under a poll worker key of the section (`on_recovered`).

A recovered package is accepted only if its session has no package yet. If the machine's own package arrives later, the package wins, and the recovered one is marked `superseded` (`admit`). The rule is "if the machine's own package later appears, it wins" (§17.6).

### Why a truncated journal is detectable (§16.4)

Here is the danger. The journal on the surviving medium has checkpoints 1 to 5. Someone publishes a recovered package cut at checkpoint 3, which omits the votes after it. The package is valid, because it is signed up to checkpoint 3. Nothing in the package says that the rest exists. The spec gives three ways the omission shows:

1. **The count on paper.** The pre-BU carries the voter-roll count. If the section's cast total is short of it, that shortfall is visible at the section. This is a *signal*, not a proof: a voter may leave without voting. So it prompts a look, and does not by itself prove truncation.
2. **Codes that are missing.** Voters after the cut hold signed slips whose tracking codes never appear on the board. That is a proof: a slip is signed by the machine, and its code is the output of the chain.
3. **A later medium.** A surviving medium that turns up later may hold a further valid checkpoint, which proves the cut.

The spec also says that recovery reads every surviving medium and uses the longest journal whose checkpoints verify, and reports any disagreement (§16.4). That choice is made by the people recovering the journal, before a package exists. `BoardState` only sees the package that results, so the comparison of media is outside this file.

So the design is: a truncation is not hidden by the package's own checks, but it leaves traces that voters' slips and other media can expose.

### Import and the section pre-BU

A replacement machine imports the recovered package and lists it in its pre-BU field 6 (file 19). Then one pre-BU covers the whole section, and the encrypted subtotal covers both machines. A recovered package that no pre-BU imports is still counted; its cast ballots go into the pool (file 18), and the verifier reports it.

## The freeze (§17.7)

The EA's power is bounded at four points, and each point is one rule:

| point | what closes | function | why |
|---|---|---|---|
| `polls_open` | new `signed_registry` and `software_policy_update` are refused | `on_registry`, `on_policy_update` | the EA cannot add a machine or a poll worker key once voting has started |
| `polls_open` | new `observer_cert` is refused | `on_observer_cert` | a colluding party cannot certify witnesses after the fact |
| `polls_open` | `polls_open` itself must name the registry in force, by RecordId | `on_polls_open` | the freeze is of a specific registry, not of "whatever is current" |
| `tally_cutoff` | no package is accepted after it, and no revocation (`observer_revoke`) | `check_window`, `on_observer_revoke` | the set of tallied packages is fixed by its place in the log |

`on_tally_cutoff` requires that `polls_open` is already on the board, and that the cutoff is not already on it. It also checks the cutoff's context hash and EA signature.

The freeze is what makes the verifier's choice unambiguous. "Every package is judged against the one registry in force when polls opened" (file 15). Without it, the EA could add a machine after seeing turnout, and forge its packages.

## Attestations and the missing package

`on_attestation` accepts a section attestation at any time, with no matching package. The attested record must be a `zeresima` or a `pre_bu` whose machine signature verifies under the registry key of its machine. The attestation's key must be one of:

- a poll worker key of the section the record names; or
- an observer key that is certified (or registered by the EA) and not revoked.

Then the attestation's own signature must verify. The board records it in `attestations`, with the record's RecordId.

The result is that a missing package is visible: an attestation names the machine, section, counts and chain head, and the verifier looks for a matching accepted package. If there is none, or it differs, the verifier reports it (§17.7, §23 step 7).

## The code, function by function

| function | what it does | why |
|---|---|---|
| `kv`, `req` | build pairs; read a required field of an optional-field record | shared helpers |
| `board_err` | a board refusal, with its reason | the reason goes into the `rejection` entry |
| `decode_records`, `records_value` | journal records as a list, both ways | |
| `PackageHeader::to_value`, `from_value` | the §16.1 header, with the optional attestation | |
| `Package::sign`, `from_signed` | the machine-signed package | rule 2 |
| `build_package` | a package from a journal that ends with `session_close` | the machine's output |
| `RecoveredPackage::unsigned_value`, `add_sig`, `to_value`, `from_value` | the recovered package and its poll worker signatures | §16.4 |
| `build_recovered` | a recovered package from a journal that ends with a checkpoint | the replacement machine's output |
| `party_key_sign`, `party_key_decode`, `party_index_of` | the shared shape of certificates and revocations | one place for the party signature |
| `ObserverCert::sign`, `from_signed` | a party's certificate | §16.3 |
| `ObserverRevoke::sign`, `from_signed` | a party's revocation | §16.3 |
| `SectionAttestation::create`, `verify`, `to_value`, `from_value` | the attestation, its signature, and its decode | §16.3 |
| `PolicyUpdate::from_signed` | the EA's software policy update | §24.4 |
| `BoardState::new` | the empty board for a manifest and a context | |
| `BoardState::ingest` | applies one entry, dispatches on its tag, returns `Accepted` or `Rejected(reason)` | the only public entry point for entries |
| `accepted_packages`, `attestations`, `registry`, `polls_open`, `cutoff` | read access to the state | the verifier's inputs |
| `on_registry` | accepts a registry with the next version, before polls open | §7.7, §17.7 |
| `on_polls_open` | sets the freeze, naming the registry in force | §17.7 |
| `on_tally_cutoff` | sets the cutoff, once, after polls open | §17.7 |
| `on_policy_update` | applies approved-hash changes before polls open | §24.4 |
| `party_key` | the key of a party, from the manifest | §16.3 |
| `on_observer_cert` | records a certification before polls open; a key certified by two parties is refused | §16.3 |
| `on_observer_revoke` | records a revocation before the cutoff, within the party's own certifications | §16.3 |
| `is_observer` | whether a key is certified or EA-registered | |
| `on_attestation` | checks the record, the key and the signature, then records the attestation | §16.3 |
| `check_window` | refuses packages before polls open or after the cutoff | rule 1 |
| `machine` | the registered machine, from the registry in force | rule 2 |
| `check_records` | rules 3, 4, 5 and 6 (section and reserve), then `check_journal` | the shared check for packages and recovered packages |
| `admit` | rule 9, the superseding of a recovered package, and the session accounting | |
| `on_package` | the package path: window, signature, records, admit | §17.6 for a package |
| `on_recovered` | the recovered path: window, records, poll worker signature, admit | §17.6 and §16.4 |
| `registry_keys` | every machine, poll worker and observer key in a registry | used to refuse revoking a registry key |

## Design choices

- **One ingester, run by everyone.** Because the board and the verifier use the same `BoardState`, a disagreement can only come from the entries themselves. This is the reason for the "run the same code" design in §23. The cost is that a bug here is shared; spec issue 9 notes this.
- **Refusals are reasons, not silence.** Every refusal returns text, and the board publishes it. A dropped package therefore leaves a trace.
- **Freeze by RecordId, not by time.** `polls_open` names the registry it freezes. A time could be argued about, and a name cannot.
- **Refuse by position in the log.** The cutoff is an entry, so "packages before the cutoff" is a fact about the log, not about clocks.
- **Accept attestations without a package.** This is what turns a missing package into evidence. Refusing them would hide the evidence.
- **Party certificates before polls open, and only for the party's own observers.** It gives each party a voice in who watches, without the EA in the loop.
- **Rule 8 excludes ballots, not packages.** Rejecting a package would discard honest votes for another voter's proof failure.
- **Superseding, not refusing, for recovered packages.** If the machine comes back with its own package, the recovered one is marked superseded and reported, not deleted. The history stays visible.

## Attacks each check stops

| attack | what stops it |
|---|---|
| a package forged with another key | rule 2 (`package_signed_by_wrong_machine_key_is_rejected`) |
| a package from another election | rule 3 (`context_mismatch_is_rejected`) |
| unapproved software | rule 4 (`unapproved_measurement_is_rejected`) |
| a package before polls open | rule 1 (`package_before_polls_open_is_rejected`) |
| a package after the cutoff | rule 1 (`package_after_tally_cutoff_is_rejected`) |
| a broken journal inside a package | rules 5 to 7 (`broken_journal_invariant_is_rejected`) |
| the same session twice | rule 9 (`duplicate_session_is_rejected`) |
| more sessions than `max_sessions` | rule 9 (`exceeding_max_sessions_is_rejected`) |
| a poll worker from another section authorizing | the section check (`poll_worker_of_another_section_is_rejected`) |
| a ballot with a broken proof sinking the package | rule 8 (`ballot_with_broken_proof_still_accepted`) |
| a recovered package without a poll worker's signature | §16.4 (`recovered_package_without_poll_worker_signature_is_rejected`) |
| a recovered package displacing the machine's own package | superseding (`recovered_package_is_superseded_by_the_real_package`), and the reverse order is refused (`recovered_after_package_for_same_session_is_rejected`) |
| the registry changed after voting starts | `polls_open` freeze (`registry_after_polls_open_is_rejected`) |
| a party's observer certified after the election | `observer_cert_after_polls_open_is_rejected` |
| a revoked observer still attesting | `revoked_observer_attestation_is_rejected_and_earlier_ones_stay_valid` |
| a party revoking the registry's keys | `revocation_by_a_party_of_a_registry_key_is_rejected` |
| a revocation after the cutoff | `revocation_after_tally_cutoff_is_rejected` |
| an attestation by an unknown key | `section_attestation_by_unknown_key_is_rejected` |
| a reserve machine carrying another section's votes | `reserve_machine_serves_the_section_it_names` |

## Tests (27)

- **Happy path and pass-through:** a full session is accepted and listed; entries the module does not check are accepted (`happy_path_is_accepted_and_listed`, `unknown_entries_are_accepted_without_checks`).
- **Freeze and window:** registry and observer certificates after polls open are refused; packages before polls open or after the cutoff are refused (`registry_after_polls_open_is_rejected`, `observer_cert_after_polls_open_is_rejected`, `package_before_polls_open_is_rejected`, `package_after_tally_cutoff_is_rejected`).
- **Package rules:** wrong machine key, context mismatch, unapproved measurement, broken journal, duplicate session, `max_sessions`, a poll worker of another section (`package_signed_by_wrong_machine_key_is_rejected`, `context_mismatch_is_rejected`, `unapproved_measurement_is_rejected`, `broken_journal_invariant_is_rejected`, `duplicate_session_is_rejected`, `exceeding_max_sessions_is_rejected`, `poll_worker_of_another_section_is_rejected`).
- **Rule 8:** a ballot with a broken proof does not reject the package (`ballot_with_broken_proof_still_accepted`).
- **Recovered packages:** accepted with a poll worker signature, rejected without, superseded by a real package, and refused after one (`recovered_package_with_poll_worker_signature_is_accepted`, `recovered_package_without_poll_worker_signature_is_rejected`, `recovered_package_is_superseded_by_the_real_package`, `recovered_after_package_for_same_session_is_rejected`).
- **Attestations:** by an observer for a pre-BU, by a poll worker for a zerésima, by an unknown key (refused), and by a revoked observer (refused, with earlier ones still valid) (`section_attestation_of_pre_bu_by_observer_is_accepted`, `section_attestation_by_poll_worker_of_zeresima_is_accepted`, `section_attestation_by_unknown_key_is_rejected`, `revoked_observer_attestation_is_rejected_and_earlier_ones_stay_valid`).
- **Revocation:** a party cannot revoke a registry key, and cannot revoke after the cutoff (`revocation_by_a_party_of_a_registry_key_is_rejected`, `revocation_after_tally_cutoff_is_rejected`).
- **Policy:** approved hashes are added and withdrawn before polls open (`policy_update_adds_and_withdraws_hashes_before_polls_open`).
- **Records and reserve machines:** every record round-trips; a reserve machine serves the section it names; `build_package` needs a closed journal (`records_round_trip`, `reserve_machine_serves_the_section_it_names`, `build_package_needs_a_closed_journal`).

## Spec gaps and issues relevant here

- **§24.5 attestation.** Rule 4 says that if the software policy requires attestation, the opening and closing attestations must verify. `check_records` refuses every package when the policy requires attestation, because this module does not verify them. The refusal is honest, but it means such an election cannot be run with this code.
- **§16.3 rate limits.** The spec lets the board rate-limit attestations per key, but not refuse the first one. `on_attestation` does not rate-limit, which is allowed.
- **§16.3 revocation wording.** The spec says attestations by a revoked key after its revocation are "ignored". The code refuses them with a reason. The tally result is the same, and the refusal is more visible.
- **Pre-revocation.** A party may revoke a key that nobody has certified yet (`on_observer_revoke`). The spec does not say whether that is allowed. The code permits it, and `on_observer_cert` does not clear the revocation later. A party could block an observer key before it is certified.
- **Two parties, one key.** A key certified by a second party is refused. The spec does not say this either. It is a sensible rule, and it is now implemented without a spec statement.
- **§17.7 listing.** The cutoff check lists every section with no accepted package, and every pre-BU attestation whose package is missing. `BoardState` gives the data (`accepted_packages`, `attestations`), but the list itself is the verifier's job (§23, step 7).
- **§17.6 rejection entry.** The board must publish the reason as a signed `rejection`. `ingest` returns the reason. Signing and publishing it are the board service's job.
- **Spec issue 9 (verifier independence).** The verifier reuses `BoardState` and `check_journal`, so a bug in either is shared with the board. §23 asks for a verifier that does not depend on the producers' code, and that is still open.
- **Spec issue 10 (reserve machines).** The contest-match check is done here, at ingestion, as the issue says. It is implemented.
