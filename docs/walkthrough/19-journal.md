# 19 · The machine journal: a record that can't be rewritten quietly

**Code:** `crates/eg-core/src/journal.rs`. **Spec:** §15 (journal format, records, privacy rules, invariants and recovery, zerésima), §16.2 (the pre-BU record, which the journal carries).

**Scope of this file.** `journal.rs` defines the records, the frame chain, the signatures on checkpoints, authorizations and the zerésima, and the §15.4 checker `check_journal`. It checks what is on disk. The machine's own restart logic (appending a missing checkpoint, reprinting a slip, abandoning an unfinished ballot) is in `Session::restart`, in `crates/eg-core/src/machine.rs`. It is described in file 23 (`23-voting-machine.md`). This file only says what a correct journal looks like.

## The problem

The voting machine is the only device that sees each voter's choice, while the voter is choosing. Its record of what it did must be:

1. **Tamper-evident.** Changing, deleting, inserting or reordering a record must be detectable by anyone holding a copy.
2. **Checkable after the fact.** The package (file 21) carries the journal, so the verifier can re-run every rule without the machine.
3. **Complete about the machine's authority.** The machine must not invent authorizations for itself, cancel one to hide a dropped ballot, or start counting before voting opens.
4. **Recoverable.** A machine can die mid-session, and the votes it recorded up to a known point must still be provable.
5. **Private.** The record must not link a voter to a time or to an order of arrival, and it must not hold voter data.

Each of these maps to a part of the design below.

## The idea, without math

The journal is a list of records. Each record is stored with a **digest of the record before it**, so the records form a chain, like the chain of blocks in a blockchain but with no network agreeing on it. Change one byte of record 5, and the digest of record 5 changes, so the digests of records 6, 7 and so on no longer match. A deletion or reordering breaks the chain the same way.

Two things are held on top of that chain:

- **Authorizations** come from the poll workers, not the machine. Each one is a signature by a poll worker key of the section, so the machine cannot make one for itself.
- **Checkpoints** are signed by the machine. A checkpoint says "there are N records, the last one has this digest, and the tracking-code chain is at this head". Because the machine signed it, a recovered journal can be trusted up to its last checkpoint, even after the machine dies (§16.4).

Hashes can't be worked by hand, so this file has no toy numbers. The point to check is the chain: each frame includes the digest of the previous frame, and the first frame includes 32 zero bytes.

## Framing (`frame_digest`, `Journal`, §15.1)

Each record is stored as:

```
frame = u32_be(length) || CBOR(record) || Digest("eg/v1/journal", prev_frame_digest, CBOR(record))
```

The first frame's `prev_frame_digest` is 32 zero bytes. The machine must `fsync` after each record and before showing the voter anything that depends on it. In particular, the cast record is synced before the slip is printed.

Reading a file back (`Journal::from_bytes`) does three things:

- a **truncated final frame** (a torn write when power failed mid-write) is dropped, and the function reports it through a flag. This is the only damage that is forgiven;
- any **other** damage (a bad digest, a record that doesn't decode) is an error, and the machine must refuse to continue the session;
- the digest of each frame is recomputed from the one before it, so a wrong digest anywhere is caught.

## The records (§15.2)

Every record is a CBOR map with a type tag in field 0 and version 1 in field 1 (file 01). Decoding is strict: an unknown key, a duplicate key or a missing key is an error (`record_fields` in `cbor.rs`), and an unknown type tag is an error (`every_record_type_round_trips_through_cbor`, `unknown_record_type_is_rejected`).

| record | tag | fields | what it proves | time or voter data? |
|---|---|---|---|---|
| `SessionOpen` | `session_open` | context hash, machine id, section id, session id, software measurement, `opened_at`, the 16-byte `opening_challenge`, optional attestation | which machine, section and software, and when the session opened | `opened_at`: yes, allowed |
| `Zeresima` (inside `ZeresimaSigned`) | `zeresima_signed` | the signed zerésima (§15.5), and the poll worker signatures over it | the session started empty, and was witnessed (see below) | repeats `opened_at`, allowed |
| `Authorization` | `auth` | `auth_seq`, the poll worker's public key, the signature | one voter was authorized | no time, no voter data |
| `Committed` | `committed` | the ballot (file 13), the tracking code | the ballot was encrypted and its code was fixed | no |
| `Cast` | `cast` | the tracking code | a ballot was cast and consumes one authorization | no |
| `Spoiled` | `spoiled` | the tracking code, the reveal (ρ, file 13) | a ballot was spoiled, and the reveal opens it | no |
| `Abandoned` | `abandoned` | the tracking code | a ballot was started and never resolved | no |
| `AuthCancel` | `auth_cancel` | `auth_seq`, poll worker key, signature | an unused authorization was cancelled by a poll worker | no |
| `Checkpoint` | `checkpoint` | record count, frame digest of the previous record, chain head, machine signature | the journal up to here, signed by the machine | no |
| `PreBuSigned` | `pre_bu_signed` | the pre-BU (below) and its section signatures | the section's encrypted subtotal and every ballot's position | no |
| `SessionClose` | `session_close` | authorizations, cast, spoiled, abandoned counts, final chain head, `closed_at`, optional closing attestation | the session's totals | `closed_at`: allowed |

The `Committed` record holds the whole ballot, not just its code. That is what lets the checker recompute the tracking code and the spoil reveal's ballot id.

### Privacy rules (§15.3)

- Only `session_open`, `zeresima_signed` (which repeats the opening time) and `session_close` may contain a time. The decoders for the other records have no time field, so there is nowhere for one to go.
- `authorization` and `auth_cancel` hold a counter, a poll worker key and a signature. Nothing identifies the voter. The signature is over `[context_hash, machine_id, session_id, seq]`, and Ed25519 signatures are deterministic, so the signature reveals nothing about who the voter is.
- The spec also tells hosts (the poll terminals) not to record the order or time in which voters were authorized. That obligation is on the host, which `eg-core` cannot enforce. It is written here so integrators know.

## Authorization and the poll workers (§15.2)

```
authorization signature = Sign(pw_sk, "eg/v1/sig/auth",        [context_hash, machine_id, session_id, auth_seq])
cancellation signature  = Sign(pw_sk, "eg/v1/sig/auth-cancel", [context_hash, machine_id, session_id, auth_seq])
```

The poll worker keys are the section's keys in the registry (§7.7). `auth_signature` and `auth_cancel_signature` make these signatures, and `Checker::on_authorization` and `on_cancel` check them against `SessionKeys::poll_worker_keys`.

Why this matters. A machine that could authorize its own voters could cast any number of ballots without a voter arriving. A machine that could cancel an authorization could hide a dropped ballot. Both are closed off because only a poll worker's key can sign either.

## The zerésima (§15.5)

Before the first authorization, the machine proves in front of the section that it starts empty. Three steps.

1. The poll terminal sends 16 fresh random bytes, the `opening_challenge`. It goes into `session_open`.
2. The machine computes `head_0 = chain_start(context_hash, machine_id, session_id, measurement, opening_challenge)`, prints the zerésima (a list of every offered option with zero votes, plus a QR code), and signs it with the machine key.
3. At least one poll worker of the section signs it on the poll terminal. Those signatures go into `zeresima_signed`.

`Zeresima::sign` and `Zeresima::from_signed` build and check the machine's signature, and `Checker::on_zeresima` checks the rest: the fields agree with `session_open`, `session_open_id` is the RecordId of `session_open`, `head_0` is the chain start computed from the challenge, and a poll worker has signed.

**What it proves**, as the spec states it:

- **Freshness.** `head_0` includes the poll terminal's random challenge, so the zerésima cannot be computed before the ceremony. Every tracking code of the session chains from `head_0`, so no ballot of this session can have been encrypted earlier.
- **No pre-loaded votes.** The zerésima makes the starting point public and witnessed. What stops ballots from being added before voting opens is the rule that every cast needs an authorization journaled after the zerésima (below).
- **Presence.** A machine that the EA registered but that was never opened in front of a real section has no zerésima carrying an observer's signature. Poll worker signatures alone do not prove presence, because the EA registered those keys too (§28.18). So observers may countersign the zerésima as well (file 21).

## The pre-BU (§16.2)

The pre-BU is the section's paper summary. It is printed at close, before anything is transmitted, and it has **no per-candidate numbers**. The record is `PreBu`, and it is signed by the machine (`PreBu::sign`). Then `pre_bu_signed` adds the poll worker signatures.

| field | meaning | checked where |
|---|---|---|
| 2 to 5 | context hash, machine id, section id, session id | `on_pre_bu` (against `session_open`) |
| 6 | imported recovered packages: `[RecordId, cast count, last chain head]` | file 18 (`Imported`) |
| 7 | frame digest of the record just before this pre-BU | `on_pre_bu`: must equal `journal.digest_before(i)` |
| 8 | chain head at this point | `on_pre_bu`: must equal the checker's head |
| 9 to 12 | authorizations, cast, spoiled, abandoned | `on_pre_bu`: must equal the checker's counts |
| 13 | voter-roll count, typed in by a poll worker | not checked here: the poll terminal checks it against its own entry before signing |
| 14 | subtotal fingerprint (file 18) | not checked here: the caller recomputes the tally and compares |
| 15 | contests pooled because they had fewer than `min_section_ballots` counted ballots | not checked here |
| 16 | machine signature over fields 0 to 15 | `PreBu::from_signed` |

Fields 7 and 8 **pin every ballot of the session**: the journal up to this point cannot be changed without changing the frame digest and chain head printed on paper. The poll worker signatures in `pre_bu_signed` are checked by `on_pre_bu`, which requires at least one poll worker of the section.

## Checkpoints (§15.2, §15.4)

After every `zeresima_signed`, `cast`, `spoiled`, `abandoned` and `pre_bu_signed`, the machine appends a `checkpoint`:

```
checkpoint = { count, frame digest of the previous record, current chain head,
               Sign(machine_sk, "eg/v1/sig/checkpoint", [context_hash, machine_id, session_id, count, frame digest, chain head]) }
```

`Checker::on_checkpoint` checks that `count` equals the number of records before it, that the frame digest is the digest of the previous record, that the chain head is the checker's head, and that the signature verifies under the machine key.

**Why recovery needs them.** When a machine dies, its second copy of the journal is recovered (file 21, §16.4). Without checkpoints, a journal cut short looks exactly like a complete one: nothing says where the machine last vouched for its records. With a checkpoint, the dead machine has already signed "here are N records, ending at this digest". Everything up to that checkpoint is authenticated by the machine's own signature. The records after the last checkpoint are at most one ballot in progress, which was never cast and printed no slip, so nothing a voter holds is lost.

A checkpoint follows the zerésima, the pre-BU and every status record (cast, spoiled, abandoned). It never follows an authorization or a committed ballot. So a checkpoint never sits in the middle of a ballot: when a recovered journal is cut at its last checkpoint, it never ends with an open ballot (spec issue 15).

## The §15.4 invariants

`check_journal` walks the records once. The `Checker` keeps the state that each rule needs. The table lists each rule, the function that checks it, and the fraud it blocks.

| # | invariant (§15.4) | checked in | fraud it blocks |
|---|---|---|---|
| 1 | the journal begins with `session_open`, then `zeresima_signed`. No authorization may come before the zerésima | `Checker::step` (records 0 and 1) | voting before the session starts, or before the machine has proved it started empty |
| 2 | the `session_open` context hash equals the election's | `on_session_open` | a journal from another election |
| 3 | `auth_seq` runs 1, 2, 3, … with no gaps or repeats | `on_authorization` | a gap that hides a removed authorization; a repeat that reuses one |
| 4 | each authorization and cancellation is signed by a poll worker of the section | `on_authorization`, `on_cancel` | the machine authorizing its own voters |
| 5 | at most one authorization is unused at any time | `on_authorization` ("second unused authorization") | a relabelled cast that frees an authorization, used later for a fake ballot (see below) |
| 6 | each `cast` consumes the unused authorization, and its code is the pending committed ballot's | `on_cast` | a cast with no voter |
| 7 | each `auth_cancel` names the unused authorization | `on_cancel` | cancelling a used authorization, which would hide a cast |
| 8 | every `committed` ballot is followed by its `cast`, `spoiled` or `abandoned` before any other record | `Checker::step` (pending check) | a ballot that disappears between encryption and status |
| 9 | the code of each `committed` ballot is the tracking code of that ballot, from the chain head | `on_committed` | a ballot whose code does not match its contents |
| 10 | a `spoiled` record reveals the ballot it names | `on_spoiled` | a reveal for another ballot, to make a spoil look valid |
| 11 | a `checkpoint` follows every `zeresima_signed`, `cast`, `spoiled`, `abandoned`, `pre_bu_signed` | `need_checkpoint` in `Checker::step` | records added after a point the machine did not vouch for |
| 12 | each checkpoint has the right count, frame digest, chain head and machine signature | `on_checkpoint` | any edit, deletion or reordering that the chain would not show |
| 13 | the pre-BU's frame digest, chain head and counts match the journal, and a poll worker signed it | `on_pre_bu` | a pre-BU that describes some other journal |
| 14 | nothing follows `pre_bu_signed` except its checkpoint and `session_close` | `Checker::step` | ballots added after the paper pre-BU was printed |
| 15 | `session_close` counts and final head match the journal, and `authorizations = cast + cancellations` | `on_close`, `finish` | unused authorizations that are never explained |
| 16 | nothing follows `session_close` | `Checker::step` (`closed`) | records appended to a closed session |

### The "at most one unused authorization" rule (invariant 5)

This rule is the one that is easiest to misread, so the mechanism is worth stating. A cast consumes the unused authorization, and a spoil does not. Suppose a machine wants to make a voter's **cast** disappear by recording it as **spoiled** (the spec's §28.20). The authorization stays unused, so it is "freed". The machine could then use it for a fake ballot, cast with no poll worker authorization of its own.

A counted ballot needs an authorization, and each authorization is good for one cast. The rule means the machine can never hold a stock of unused authorizations. The only unused authorization it can ever have is the one a poll worker just signed for a voter who is present. If the machine relabels that voter's cast as spoiled, the authorization is freed, and the machine can put a fake ballot in its place. That is one fake for one relabel, and the voter's signed slip still says "cast" with that code, while the board shows the code as `spoiled`. A voter who checks their code (file 15, §17.5) can prove the relabel. The spec's own words are that the attack "is detected only if voters check their codes" (§28.20).

Without the rule, a stock of pre-signed authorizations would let the machine cast ballots at will, with no voter present, and nothing in the journal would tie them to a relabel. Note that the count invariant (15) alone does not catch the relabel-and-fake case: after the relabel and the fake cast, authorizations still equal cast plus cancellations. The rule (5) and the voter's slip are what close it.

### The count invariant (invariant 15)

`session_close` says how many authorizations, casts, spoils and abandons there were. `on_close` checks each count against the journal, and that `authorizations = cast + cancelled`. The count of cancelled authorizations includes unused authorizations left in a recovered journal (`finish`).

Abandoned ballots do not consume an authorization (§15.4), so they are not part of this equation. An abandoned ballot is never tallied.

### What a committed-but-unresolved ballot does

A `committed` record with no status is the state after a crash. On a live machine, the machine appends `abandoned` for it (§15.4). The checker here is stricter: `Checker::step` rejects any record that arrives while a committed ballot is pending, unless the record is its status. A recovered journal cut at a checkpoint never ends in that state, because the checkpoint comes after the status. So the rule is that a committed ballot without a status is always an error in the journal, in both modes. The spec's "becomes abandoned" wording applies to the live machine. `Session::restart` in `crates/eg-core/src/machine.rs` appends `abandoned` for such a ballot (file 23, spec issue 15).

## Recovered journals (`complete = false`, §16.4)

`check_journal(keys, journal, false)` checks a journal that was cut at a checkpoint:

- it must end with a checkpoint (`finish`);
- it normally has no `session_close`, so invariant 15 is not checked. The usual cut comes before the pre-BU too (§16.4 says "No `pre_bu_signed` or `session_close` exists"). A pre-BU, if present, is still checked by `on_pre_bu`;
- authorizations that were never used are counted as cancelled (`finish`: `cancelled += 1` if `unused` is still set). This matches §15.4 and §16.4.

The same checker runs in both modes, and only the ending differs.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `kv`, `field` | build `(key, value)` pairs; read a field of an optional-field record | shared helpers |
| `journal_err`, `fail` | build a journal error, or a `record i: …` error | every failure names the record |
| `auth_message`, `auth_signature`, `auth_cancel_signature` | the signed `[context, machine, session, seq]` and its two signatures | poll worker authority |
| `checkpoint_message`, `checkpoint_signature`, `verify_checkpoint` | the signed checkpoint content, and its sign and verify | the machine's own vouching |
| `SessionOpen::to_value`, `from_value` | the §15.2 `session_open` record | |
| `Zeresima::sign`, `from_signed` | the machine-signed zerésima | §15.5 |
| `SectionSig::create`, `verify`, `to_value`, `from_value` | a `[pk, sig]` over `RecordId(record)` | the signature every poll worker and observer uses (`section_message`) |
| `PreBu::sign`, `from_signed` | the machine-signed pre-BU, fields 0 to 16 | §16.2 |
| `Record::to_value`, `from_value` | every record type, with strict decoding | §15.2 |
| `key_record` | the shared shape of `auth` and `auth_cancel` | the two must not drift apart |
| `frame_digest` | `Digest("eg/v1/journal", prev, CBOR(record))` | the chain link |
| `Journal::new`, `append` | append a record and return its frame digest | the only way to grow a journal |
| `records`, `last_digest`, `digest_before`, `len`, `is_empty` | read access; `digest_before(i)` is the digest of the record before `i` | used by checkpoints and the pre-BU |
| `Journal::to_bytes` | the framed bytes | the file and package format |
| `Journal::from_bytes` | parse framed bytes, verify each digest, drop a torn final frame | recovery after a crash |
| `Journal::from_records` | rebuild a journal from records (recomputes all digests) | used by the board when it re-checks a package |
| `SessionKeys` | the context hash, machine key, poll worker keys and `min_section_ballots` | everything the checker needs from the registry |
| `check_journal` | the entry point: runs `Checker::step` over each record, then `finish` | §15.4 |
| `Checker::step` | the ordering rules (begin, pending ballot, checkpoints, pre-BU, closed), then dispatch | one place that enforces the sequence |
| `on_session_open`, `on_zeresima`, `on_authorization`, `on_committed`, `on_cast`, `on_spoiled`, `on_abandoned`, `on_cancel`, `on_checkpoint`, `on_pre_bu`, `on_close` | one handler per record type | each handler is one rule group |
| `Checker::finish` | the ending: `session_close` for a full journal, a checkpoint and the unused count for a recovered one | §15.4 and §16.4 |

## Design choices

- **Frames chain digests, not just checksums.** A checksum would catch a torn write but not a deliberate rewrite. A chain of digests makes a rewrite visible to anyone who saved a later digest.
- **Authorizations are poll worker signatures.** Authority to vote lives outside the machine. The machine can only use what the poll worker has signed.
- **Checkpoints are signed by the machine, and never inside a ballot.** The machine vouches for exactly the points where a recovery makes sense. A checkpoint after a committed ballot would be a point where the machine had not yet decided the ballot's fate.
- **The zerésima binds the challenge into `head_0`.** Freshness comes from a value the machine could not know in advance.
- **Strict decoding everywhere.** An extra field could hide a timestamp or a voter's data, so the decoders reject it.
- **One checker, two modes.** A live package and a recovered one are checked by the same code. Only the ending and the cancelled count differ, so the two cannot drift apart.
- **The pre-BU's fingerprint is not checked here.** Checking it needs the tally (file 18), which is computed from the board. Keeping the journal checker independent of the tally keeps each one small. The caller (file 21) does the comparison.

## Attacks each check stops

| attack | what stops it |
|---|---|
| editing a record, deleting one, or reordering two | the frame digests no longer chain (`corrupted_middle_byte_is_rejected`, `wrong_frame_digest_is_rejected`) |
| a torn final frame mistaken for corruption | it is dropped and reported, not rejected (`torn_final_frame_is_dropped`) |
| the machine authorizes its own voters | authorizations need a poll worker signature (`forged_auth_signature_is_rejected`) |
| voting before the zerésima | authorization before `zeresima_signed` is rejected (`auth_before_zeresima_is_rejected`) |
| a zerésima computed in advance | `head_0` must equal the chain start from the challenge (`zeresima_head_0_mismatch_is_rejected`) |
| two authorizations at once, so one spare can cover a fake ballot | `two_unused_authorizations_are_rejected` |
| a cast with no authorization | `cast_without_authorization_is_rejected` |
| a gap or repeat in the sequence numbers | `gap_in_auth_seq_is_rejected` |
| a checkpoint that lies about the count, the digest or the head | `checkpoint_with_wrong_count_is_rejected`, `…_wrong_frame_digest_…`, `…_wrong_head_…` |
| a checkpoint the machine did not sign | `checkpoint_with_forged_signature_is_rejected` |
| a cast without its checkpoint (a crash between) | `missing_checkpoint_after_cast_is_rejected` |
| a tracking code that doesn't match its ballot | `wrong_tracking_code_is_rejected` |
| a pre-BU whose counts differ from the journal | `pre_bu_counts_mismatch_is_rejected` |
| a pre-BU no poll worker signed | `pre_bu_without_poll_worker_signature_is_rejected` |
| a close whose counts or head differ | `session_close_counts_mismatch_is_rejected` |
| records after the close, or after the pre-BU | `record_after_session_close_is_rejected` |
| a recovered journal cut in the middle of a ballot | `recovered_journal_not_cut_at_checkpoint_is_rejected` |
| a committed ballot with no status | `committed_without_status_is_rejected_in_both_modes` |
| a relabelled cast followed by a fake ballot | invariant 5 and the voter's slip (see above) |

## Tests (26)

- **Happy path:** a full session passes and its summary is correct (`happy_path_checks_and_summarises`).
- **Ordering:** authorization before the zerésima; a gap in `auth_seq`; a second unused authorization; a cast without an authorization; a record after the close (`auth_before_zeresima_is_rejected`, `gap_in_auth_seq_is_rejected`, `two_unused_authorizations_are_rejected`, `cast_without_authorization_is_rejected`, `record_after_session_close_is_rejected`).
- **Signatures:** a forged authorization; a checkpoint with a forged signature (`forged_auth_signature_is_rejected`, `checkpoint_with_forged_signature_is_rejected`).
- **Checkpoints:** a missing checkpoint after a cast; a checkpoint with a wrong count, frame digest or head (`missing_checkpoint_after_cast_is_rejected`, `checkpoint_with_wrong_count_is_rejected`, `checkpoint_with_wrong_frame_digest_is_rejected`, `checkpoint_with_wrong_head_is_rejected`).
- **Ballots:** a tracking code that doesn't match the ballot (`wrong_tracking_code_is_rejected`).
- **Pre-BU and close:** pre-BU counts that differ from the journal; a pre-BU without a poll worker signature; close counts that differ; a zerésima with the wrong `head_0` (`pre_bu_counts_mismatch_is_rejected`, `pre_bu_without_poll_worker_signature_is_rejected`, `session_close_counts_mismatch_is_rejected`, `zeresima_head_0_mismatch_is_rejected`).
- **Recovery:** a journal cut at a checkpoint is accepted; one not cut at a checkpoint is rejected; a committed ballot without status is rejected in both modes (`recovered_journal_cut_at_checkpoint_is_accepted`, `recovered_journal_not_cut_at_checkpoint_is_rejected`, `committed_without_status_is_rejected_in_both_modes`).
- **Framing:** round trip, torn final frame, corruption in the middle, and a wrong digest (`framing_round_trips`, `torn_final_frame_is_dropped`, `corrupted_middle_byte_is_rejected`, `wrong_frame_digest_is_rejected`).
- **Encoding:** every record type round-trips through CBOR, and an unknown type is rejected (`every_record_type_round_trips_through_cbor`, `unknown_record_type_is_rejected`).

## Spec gaps and issues relevant here

- **Spec issue 15 (unfinished ballot in a recovered journal).** Checkpoints follow status records only, so a recovered journal never ends inside a ballot. The checker rejects a committed ballot without a status in both modes. The spec's "becomes abandoned" rule applies only to a live machine, which appends `abandoned` itself. That machine is `Session::restart` in `crates/eg-core/src/machine.rs` (file 23).
- **§16.4 "every committed ballot without a final status … is treated as abandoned".** For the same reason this clause cannot arise in a checked recovered journal. It is kept in the spec for the live machine's recovery.
- **Machine restart is in `machine.rs`.** §15.4's restart rules (append the missing checkpoint, reprint the slip byte-identical, abandon an unfinished ballot) are implemented in `Session::restart` (`crates/eg-core/src/machine.rs`, line 646). ρ is not recovered, because it was only in memory. See file 23 for the walkthrough. Its tests are `restart_after_cast_before_checkpoint_reprints_the_same_slip`, `restart_after_committed_abandons_the_ballot`, `restart_drops_a_torn_final_frame` and `restart_refuses_a_corrupted_middle_frame`.
- **Fields 13 to 15 of the pre-BU are checked elsewhere.** The voter-roll count is checked on the poll terminal, the fingerprint and the pooled list by the tally (file 18). A reader of this file alone cannot check them.
- **Spec issue 9 (verifier independence).** The package checks in file 21 use this file's `check_journal`, so a bug here would be shared by the machine's self-check and the verifier. The test vectors (file 07) and the tests above are the guard.
