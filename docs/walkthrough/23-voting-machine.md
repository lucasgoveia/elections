# 23 · The voting machine: one polling day, from opening to package

**Code:** `crates/eg-core/src/machine.rs`. **Spec:** §13.1 (the chain), §14.1 (encrypt, cast, spoil), §15 (journal, invariants, restart, zerésima), §16.1 (package), §16.2 (pre-BU), §16.4 (importing a dead machine's journal), §18.1 (the section fingerprint).

**Scope of this file.** `machine.rs` is the state machine of one polling session. It decides which step may come next, journals every step, and produces the slip, the spoil receipt, the pre-BU and the package. It does not print anything, does not store the journal on disk (the host does that, from `Session::journal().to_bytes()`), and does not type in the voter-roll count (the poll terminal does). The journal records and the checker are in file 19. The chain of codes is in file 14. What happens to the package after it leaves the machine is in files 21 and 24.

## The problem

A voting machine is the one device that sees a voter's choices, and it runs for a whole day with no one watching its internals. Within a single session it must:

1. **Refuse to vote without a voter.** Every counted ballot needs a poll worker's authorization, and the machine must not be able to make one itself.
2. **Keep the ballot's secret until the voter decides.** Cast, spoil and abandon are the three ways a ballot can end, and each one has a different use for the secret ρ (see the table below).
3. **Survive a crash.** Power can fail between any two writes. Whatever the voter already holds (a slip, a spoil receipt, a code on the screen) must still be true after restart.
4. **Stop cleanly.** After the pre-BU is signed, nothing else may be added. Before the close, no authorization may be left hanging.
5. **Let another machine finish a dead machine's work.** Its votes must be counted in the same section, under one pre-BU.

Every rule above is a check in one place: the methods of `Session`. A rule that is only in the spec prose would not be enforced, so the code is written so that each method refuses a step that breaks its rule.

## The idea, without math

The machine is a small set of states, and each method moves it one step:

```
            open            sign_zeresima         authorize            encrypt               cast
  (none) ───────► EMPTY ───────────────► READY ─────────────► UNUSED ────────────► PENDING ──────────► (cast, back to READY)
                                                                 ▲                     │
                                                                 │   spoil             │ abandon
                                                                 └─────────────────────┘  (UNUSED again, same authorization)

            prepare_pre_bu  →  sign_pre_bu  →  close  →  package
```

Two facts about the states matter most.

- A **ballot** is `PENDING` between `encrypt` and its status. Only one may be pending at a time.
- An **authorization** is `UNUSED` from `authorize` until a `cast` or a poll worker's `cancel_authorization`. A spoil or an abandon leaves it unused, so the same voter may vote again under it.

Every transition appends a record to the journal and then, for the steps that matter, a checkpoint (file 19). The host saves the journal bytes after each call and before it shows or prints anything that depends on the call. The code does not do the saving; the spec (§15.1) requires it.

## The state the machine keeps

| field | meaning | changed by |
|---|---|---|
| `head` | the chain head after the last decision, starting at `head_0` (§13.1) | `cast`, `spoil`, `abandon`, restart |
| `zeresima`, `zeresima_signed` | the zerésima, and whether poll workers have signed it | `open`, `sign_zeresima` |
| `auth_count` | how many authorizations have been journaled | `authorize` |
| `unused` | the authorization that is neither cast nor cancelled, if any | `authorize`, `cast`, `cancel_authorization`, restart |
| `cancelled` | how many authorizations were cancelled | `cancel_authorization`, restart |
| `ballot_count` | how many ballots were committed (the next ballot is this plus one) | `encrypt`, restart |
| `pending` | the committed ballot waiting for its status, with its ρ and its choices | `encrypt`, `cast`, `spoil`, `abandon` |
| `cast_ballots` | the cast ballots, in journal order | `cast`, restart |
| `spoiled`, `abandoned` | counts for the pre-BU and the close | `spoil`, `abandon`, restart |
| `imports`, `imported_ballots` | recovered packages imported, and their cast ballots | `import_recovered` (not journaled, see below) |
| `prepared` | the pre-BU built by `prepare_pre_bu`, waiting for signatures; any journal append clears it | `prepare_pre_bu`, `append` |
| `pre_bu_signed`, `closed` | the two terminal flags | `sign_pre_bu`, `close`, restart |

## The day, as a story

### 1. Opening: the challenge and the zerésima (§15.5)

`Session::open` takes the section, the session id, the time and 16 random bytes from the poll terminal (the `opening_challenge`). It journals `session_open`, computes

```
head_0 = chain_start(context_hash, machine_id, session_id, measurement, opening_challenge)
```

and builds the zerésima: a list of zero votes for every offered option, signed by the machine. `open` returns that zerésima for printing. Nothing is authorized yet.

Then the section's poll workers sign the zerésima on the poll terminal, and `sign_zeresima(sigs)` checks that each signature is by a poll worker of this section and verifies. It journals `zeresima_signed` and a checkpoint. From this point, `ensure_open` lets voting begin. Until it returns, `authorize` and `encrypt` both refuse.

Why the challenge matters. `head_0` depends on bytes the machine could not know in advance, so no ballot of this session can have been encrypted before the ceremony. (The reason the empty start is witnessed, and not just claimed, is in file 19.)

### 2. A poll worker authorizes the voter (§15.2)

The poll worker signs `[context_hash, machine_id, session_id, auth_seq]` on the poll terminal with the key of a section poll worker. The poll terminal calls `next_auth_seq()` to learn the number, and the signature is made with `journal::auth_signature`. Then `authorize(pw_key, sig)`:

- refuses if another authorization is still unused (`unused` is set);
- refuses if the key is not a poll worker of this section (`check_poll_worker`);
- refuses if the signature does not verify (`sign::verify` with the tag `eg/v1/sig/auth`).

Only then does it journal `auth` and set `unused`. The machine cannot do this on its own. It has no poll worker keys of its own to sign with, and the check above turns away any other key, including its own machine key.

### 3. The voter chooses: encrypt, then cast or spoil (§14.1, Benaloh)

This is the step where the machine sees the vote. `encrypt(rng, choices)` does the following:

1. It draws a fresh ρ (32 random bytes, held in `Zeroizing` memory). If the nonce comes out as zero, which is astronomically rare, it draws again (`Error::ZeroNonce`).
2. It builds the ballot with `ballot::encrypt_ballot` from the choices, the offered contests and the ballot id `(machine, session, ballot_count + 1)`.
3. It computes the **tracking code** `code = tracking_code(head, ballot)` (§13.1). The machine shows this code to the voter before the voter chooses.
4. It journals `committed` with the whole ballot and the code. The journal never contains ρ at this point. The ballot is now fixed, and the machine keeps ρ and the choices in `pending`.

The voter then chooses. The machine has two ways to finish.

**Cast** (`cast()`): the voter accepts the ballot.
- it journals `cast` with the code, and sets `head = next_head(code, Cast)`;
- it consumes the authorization (`unused = None`) and adds the ballot to `cast_ballots`;
- it journals a checkpoint;
- only then does it drop ρ, and return the slip signed by the machine (`Slip::sign`).

The slip is printed after `cast()` returns. The slip has no choices and no sequence number, so it reveals nothing.

**Spoil** (`spoil()`): the voter says "this is not what I chose".
- it builds a `Reveal` from the ballot id, ρ and the choices, and journals `spoiled` with the code and the reveal;
- it sets `head = next_head(code, Spoiled, reveal)`, which folds the reveal into the chain;
- it journals a checkpoint, and returns a signed spoil receipt. The authorization stays unused, so the voter may encrypt again under it.

A spoiled ballot is never tallied. The voter can check the receipt against the board (file 14, §14.2). That check is the Benaloh audit: the machine has to show the ballot it encrypted. Anyone can rebuild the ballot from the revealed ρ and choices, recompute its code from the chain head, and see whether it matches the code on the slip.

### 4. Abandon and cancellation (§15.4)

Sometimes the voter walks away with a ballot on the screen and does not choose. `abandon()` journals `abandoned` with the code and a checkpoint, moves the head with status "abandoned", and erases ρ **without** revealing it. The authorization stays unused.

Whether the voter gets another try under the same authorization is the poll worker's decision. The poll worker may cancel it with `cancel_authorization(pw_key, sig)`. That call refuses while a ballot is pending, refuses if no authorization is unused, and checks the poll worker's signature over the tag `eg/v1/sig/auth-cancel`. It journals `auth_cancel` and counts it. The machine never cancels on its own. A machine that could cancel would be able to hide a dropped ballot.

### 5. A crash, and restart (§15.4)

`Session::restart(cfg, journal_bytes)` rebuilds a session from the bytes the host saved. It works in five steps.

1. `Journal::from_bytes` parses the frames. A torn final frame (power failed mid-write) is dropped. Any other damage is an error and the machine must not continue.
2. The machine replays the records. For each `cast`, `spoiled` and `abandoned` it moves the head as the live machine did. Nothing is checked yet. The checker runs at the end.
3. If the last record is a `cast` with no checkpoint after it, the restart **reprints the slip**: it signs the same `Slip` again and returns it. Ed25519 signatures are deterministic, so the reprint is byte-identical to the slip the voter may already have, or to the slip that was never printed. Either way, the voter gets the same code.
4. If a ballot was `committed` and never got a status, the restart **abandons it**: it journals `abandoned`, moves the head, and adds a checkpoint. ρ was only in memory, so it is gone, and it cannot be recovered. The authorization is still unused, so the next voter, or the same voter, can vote again.
5. If the last record is a zerésima, cast, spoil, abandon or pre-BU signature with no checkpoint, the restart adds one. It then runs `check_journal` on the result (recovered mode if the session is still open). A journal that does not pass is refused.

**The torn-write example.** Suppose the power fails while writing the checkpoint after Ana's cast. The file ends with part of a frame. `from_bytes` drops that part and reports it. The last complete record is the `cast`, so restart reprints Ana's slip and writes the missing checkpoint. The test `restart_drops_a_torn_final_frame` cuts 5 bytes off the checkpoint and checks exactly this.

**The corrupted-middle example.** If one byte in the middle of the journal is flipped, the frame chain no longer matches, and the restart refuses (`restart_refuses_a_corrupted_middle_frame`). A torn tail is forgiven. Anything else is not.

**Software changes.** `start` refuses a journal whose measurement, machine or context hash differs from the running software. A different build cannot take over the session.

### 6. A dead machine, and the reserve machine (§16.4)

Suppose machine A is in section S1, casts two ballots, and then dies without closing. Its journal survives on a second medium. Files 21 and 24 explain how the recovered journal is checked and countersigned by a poll worker. Here we only need the replacement's side.

A reserve machine R of the same section runs its own session. It calls `import_recovered(&value)`. The method checks, in order:

1. the recovered package has a signature by a poll worker of this section (`section.poll_worker_keys`);
2. the dead machine is registered, and its key checks the journal in recovered mode (`check_journal(..., false)`);
3. the header matches the journal (count, frame digest, chain head, machine, section, session, measurement);
4. the section is this section, the contests offered by the dead machine are the same as R's, and the package is not R's own session;
5. the package was not imported already (its RecordId is compared).

Then it takes the cast ballots out of the journal (the same walk as `ballots_of` in file 24) and adds them to `imports` and `imported_ballots`.

**Important.** The import is **not journaled**. The journal format has no record for it, so after a restart the host must import the package again, before `prepare_pre_bu`. Otherwise the pre-BU silently covers fewer ballots. This is spec issue 17.

The test `recovered_package_is_imported_and_counted_in_the_pre_bu` runs the whole thing: A casts 2, R imports them, R casts 1, and the section tally has 3 counted ballots for contest 0. The pre-BU of R counts only R's own session (`cast = 1`), and lists the import in field 6 with A's cast count and last chain head.

### 7. Closing: the pre-BU, the signatures, the package (§16.2, §16.1)

**Prepare.** `prepare_pre_bu(roll_count)` refuses while a ballot is pending or an authorization is unused. It then:

- computes the section sums with `section_sums`: the imported ballots first (in import order), then R's own cast ballots (in journal order), judged with one set of reservations, and split into kept and pooled contests (§18.1);
- computes the **fingerprint** over the session id, the imports, the kept sums and the pooled indices (`fingerprint`, file 18);
- builds the `PreBu` with the frame digest and chain head at this point (fields 7 and 8, which pin every ballot), the counts, the roll count typed by the poll worker, the fingerprint and the pooled list;
- signs it with the machine key, and keeps it as `prepared`. Nothing is journaled yet.

**Sign.** `sign_pre_bu(sigs)` takes the poll worker signatures on the prepared pre-BU, checks them (at least one, all by poll workers of the section, all valid), journals `pre_bu_signed`, and adds a checkpoint. The pre-BU is printed before this step, so the paper copies and the journal say the same thing. Any journal append clears `prepared`, so a pre-BU that became stale cannot be signed.

The host is responsible for one check that the machine does not make: the poll terminal must confirm that the pre-BU's roll count (field 13) equals the count it sent, before it signs (§16.2 step 4).

**Close.** `close(closed_at)` refuses unless the pre-BU is signed, no authorization is unused, and `authorizations = cast + cancelled`. It journals `session_close` with the counts and the final head, and then `build_package` makes the signed package from the whole journal (file 21). No checkpoint follows `session_close`. The spec's journal shape is: `pre_bu_signed`, its checkpoint, then `session_close`.

## Worked example: a short day, record by record

Three voters. Ana votes and casts. Bruno spoils his first attempt and casts the second. Carla walks away and the poll worker cancels her authorization.

| step | call | journal records added | state after |
|---|---|---|---|
| 1 | `open` | `session_open` | head = h0; zerésima printed |
| 2 | `sign_zeresima` | `zeresima_signed`, checkpoint | ready to vote |
| 3 | `authorize` (seq 1, Ana) | `auth` 1 | unused = 1 |
| 4 | `encrypt` (Ana) | `committed` (code c1, ballot 1) | pending = ballot 1 |
| 5 | `cast` | `cast` c1, checkpoint | head = h1; unused = none; slip for c1 |
| 6 | `authorize` (seq 2, Bruno) | `auth` 2 | unused = 2 |
| 7 | `encrypt` (Bruno, first try) | `committed` (c2, ballot 2) | pending = ballot 2 |
| 8 | `spoil` | `spoiled` c2 with reveal, checkpoint | head = h2; unused = 2 still; receipt for c2 |
| 9 | `encrypt` (Bruno, second try) | `committed` (c3, ballot 3) | pending = ballot 3 |
| 10 | `cast` | `cast` c3, checkpoint | head = h3; unused = none; slip for c3 |
| 11 | `authorize` (seq 3, Carla) | `auth` 3 | unused = 3 |
| 12 | `encrypt` (Carla) | `committed` (c4, ballot 4) | pending = ballot 4 |
| 13 | `abandon` | `abandoned` c4, checkpoint | head = h4; unused = 3 still |
| 14 | `cancel_authorization` (seq 3, poll worker) | `auth_cancel` 3 | unused = none |
| 15 | `prepare_pre_bu(roll)` | none | pre-BU prepared: authorizations 3, cast 2, spoiled 1, abandoned 1 |
| 16 | `sign_pre_bu` | `pre_bu_signed`, checkpoint | pre-BU signed |
| 17 | `close` | `session_close` | package built |

Check the close: `authorizations = 3`, `cast = 2`, `cancelled = 1`, so `3 = 2 + 1`. Abandoned ballots do not use an authorization (§15.4), which is why c4 does not appear in that equation.

Notice step 8. Bruno's spoil leaves authorization 2 unused. That is why step 9 is allowed without a new poll worker signature: the same authorization covers his second try, which is the behavior the spec asks for. Notice step 13 too. An abandoned ballot does not decide anything. The poll worker, not the machine, decides what happens to the unused authorization.

## What happens to ρ

ρ is the secret that opens a ballot. Anyone holding ρ and the ballot can read the choices. So ρ must exist only as long as the machine still needs it, and it must be revealed only when a voter spoils.

| event | what happens to ρ | visible afterwards? |
|---|---|---|
| `encrypt` | drawn fresh, held in `pending` (`Zeroizing`); the journal gets only the ballot | no |
| `cast` | journaled `cast` and a checkpoint, then dropped | never |
| `spoil` | written into the `spoiled` record's reveal, then dropped | yes, on purpose: the reveal opens the ballot so anyone can check it |
| `abandon` | dropped without being written anywhere | never |
| crash while pending | lost with the process; restart abandons the ballot | never |

The order inside `cast()` matters. The checkpoint is written before ρ is dropped. So after a crash in the middle, the journal has the cast, and restart can still reprint the slip. ρ is not needed for that.

The erasure itself is enforced by Rust's `Zeroizing` wrapper, which overwrites memory when the value is dropped. No test checks that the bytes are gone. The `drop(rho)` calls are the only enforcement.

## The code, function by function

Every row is in `crates/eg-core/src/machine.rs`. The number is the line of the definition.

| function | line | what it does | why |
|---|---|---|---|
| `journal_err` | 46 | builds a `Error::Journal` | every refusal in this file is one of these |
| `auth_message` | 53 | the signed `[context_hash, machine_id, session_id, auth_seq]` | the object poll workers sign (§15.2) |
| `MachineConfig` | 63 | election, registry, machine id and key, measurement | everything a session needs about its machine |
| `Pending` | 78 | a committed ballot with its code, ρ (`Zeroizing`) and choices | the only place ρ lives |
| `Session` | 86 | the session state (see the table above) | one polling session of one machine |
| `Session::open` | 124 | journals `session_open` and returns the zerésima for printing | §15.5 steps 1 and 2 |
| `Session::start` | 149 | an empty session from a `SessionOpen`, with `head_0` and the signed zerésima | shared by `open` and `restart` |
| `Session::sign_zeresima` | 204 | journals `zeresima_signed` and a checkpoint, after checking the poll worker signatures | §15.5 step 3 |
| `Session::next_auth_seq` | 220 | the number the next authorization will carry | the poll terminal needs it before it signs |
| `Session::authorize` | 227 | journals `auth` after checking the poll worker key and signature | §15.2, the machine cannot authorize itself |
| `Session::encrypt` | 254 | draws ρ, builds the ballot, computes the code, journals `committed` | §14.1 step 1 |
| `Session::cast` | 301 | journals `cast` and a checkpoint, consumes the authorization, erases ρ, returns the signed slip | §14.1 step 2 |
| `Session::spoil` | 333 | journals `spoiled` with the reveal and a checkpoint, returns the spoil receipt | §14.1 step 3 |
| `Session::abandon` | 369 | journals `abandoned` and a checkpoint, erases ρ without revealing it | §15.4 |
| `Session::cancel_authorization` | 384 | journals `auth_cancel` after a poll worker signs the cancellation | §15.2, only a poll worker cancels |
| `Session::import_recovered` | 421 | checks and imports a dead machine's recovered package | §16.4 |
| `Session::prepare_pre_bu` | 508 | computes the section sums, the fingerprint and the pre-BU, signed by the machine; journals nothing | §16.2 steps 1 to 3 |
| `Session::sign_pre_bu` | 558 | journals `pre_bu_signed` with the poll worker signatures, and a checkpoint | §16.2 step 4 |
| `Session::close` | 572 | journals `session_close` and builds the package | §16.1 |
| `Session::journal`, `section_id`, `session_id`, `head` | 615 to 632 | read access | used by the host and the tests |
| `Session::restart` | 646 | rebuilds a session from journal bytes, finishes what a crash interrupted, runs `check_journal` | §15.4 |
| `Session::append` | 756 | appends a record and clears `prepared` | any change makes an old pre-BU stale |
| `Session::checkpoint` | 762 | appends a checkpoint over the current head | §15.2 |
| `Session::ensure_open` | 768 | refuses unless the zerésima is signed and no pre-BU or close has happened | the order of the session |
| `Session::section` | 779 | the registry entry of this section | the poll worker keys come from it |
| `Session::offered` | 787 | the contests this machine offers | §7.7 |
| `Session::check_poll_worker` | 800 | refuses a key that is not a poll worker of the section | §15.2 |
| `Session::check_section_sigs` | 810 | at least one signature, all by poll workers of the section, all valid | zerésima and pre-BU |
| `Session::session_keys` | 826 | the keys `check_journal` needs | used by restart |
| `check_identity` | 846 | the machine key matches the registry, and the section is one it may serve | §7.7 |
| `checkpoint_record` | 869 | builds a signed checkpoint over the journal and head | §15.2 |
| `section_sums` | 904 | judges and sums the ballots of the section, and splits off the pooled contests | §18.1, called only by `prepare_pre_bu` |

## Design choices

- **The machine never holds a count.** It keeps the cast ballots and their boxes, not the totals. Totals come only from the sums that trustees open (file 24).
- **The machine cannot authorize or cancel.** Both need a poll worker signature, checked against the section's keys. The machine's own key is not on that list.
- **One pending ballot, one unused authorization.** These two limits are what make the states simple enough to check. They also match invariant 5 of file 19.
- **The checkpoint is written after the status and before the slip is returned.** So a crash never leaves a voter with a slip that the journal does not reflect.
- **Restart does not trust the journal blindly.** It replays the state, fixes the interrupted step, and then runs the same checker that the verifier runs (`check_journal`). Both sides call one function, so they apply the same rules.
- **Imports are kept outside the journal.** Adding an `import` record would be the right fix (spec issue 17), but until the format has one, the host must repeat the import on every restart. The code says so in its module comment.
- **Prepare and sign are two steps.** The pre-BU is computed without being journaled, so it can be printed and checked by the poll workers first. `sign_pre_bu` then journals only what was signed. Any journal change clears the prepared copy.

## Attacks each check stops

| attack | what stops it |
|---|---|
| the machine authorizes its own voter | `authorize` needs a poll worker key (`refuses_authorization_by_a_key_that_is_not_a_poll_worker`) |
| a second authorization while one is unused, so a spare can cover a fake ballot | `authorize` refuses while `unused` is set (`refuses_second_authorization_while_one_is_unused`) |
| a ballot encrypted without a voter | `encrypt` needs an unused authorization (`refuses_encrypt_without_authorization`) |
| a cast with nothing pending | `cast` refuses without a pending ballot (`refuses_cast_with_nothing_pending`) |
| a pre-BU or close while a spare authorization is still open | `prepare_pre_bu` and `close` refuse (`refuses_close_and_pre_bu_with_an_unused_authorization`) |
| another section's poll worker signs this machine's zerésima | `sign_zeresima` checks the section (`refuses_zeresima_signed_by_a_poll_worker_of_another_section`) |
| a crash between the cast and its checkpoint, so the slip is lost | restart reprints the same slip (`restart_after_cast_before_checkpoint_reprints_the_same_slip`) |
| a crash mid-ballot, so the voter's code is on screen but the ballot is unfinished | restart abandons it; ρ is gone; the authorization stays unused (`restart_after_committed_abandons_the_ballot`) |
| a torn write at the end of the journal | it is dropped and the session carries on (`restart_drops_a_torn_final_frame`) |
| a damaged frame in the middle of the journal | restart refuses (`restart_refuses_a_corrupted_middle_frame`) |
| a pre-BU that is changed after signing, or a stale pre-BU signed after a new record | `append` clears `prepared`; `ensure_open` refuses after `pre_bu_signed` |
| a recovered journal from another section, a machine that is not registered, a session importing itself, or the same package twice | refused by `import_recovered` (**no test in `machine.rs` yet**; see below) |
| a small section whose total would expose its voters | the contest is pooled below `min_section_ballots` (`small_section_pools_every_homomorphic_contest`) |

## Tests (13 in `machine.rs`)

- **Happy path:** a full session closes, and the board accepts its package (`full_session_closes_and_the_board_accepts_its_package`).
- **Ordering and refusals:** encrypt without authorization, a second authorization while one is unused, cast with nothing pending, close and pre-BU with an unused authorization, a zerésima from another section, an authorization by a non-poll-worker key (`refuses_encrypt_without_authorization`, `refuses_second_authorization_while_one_is_unused`, `refuses_cast_with_nothing_pending`, `refuses_close_and_pre_bu_with_an_unused_authorization`, `refuses_zeresima_signed_by_a_poll_worker_of_another_section`, `refuses_authorization_by_a_key_that_is_not_a_poll_worker`).
- **Restart:** a cast before its checkpoint reprints the same slip and the session still verifies; a committed ballot is abandoned; a torn final frame is dropped; a corrupted middle frame is refused (`restart_after_cast_before_checkpoint_reprints_the_same_slip`, `restart_after_committed_abandons_the_ballot`, `restart_drops_a_torn_final_frame`, `restart_refuses_a_corrupted_middle_frame`).
- **Import and pre-BU:** a dead machine's journal is imported, counted in the section, and accepted by the board (`recovered_package_is_imported_and_counted_in_the_pre_bu`).
- **Pooling:** a section below the threshold pools every homomorphic contest (`small_section_pools_every_homomorphic_contest`).

**Not tested in `machine.rs`:**

- the refusals inside `import_recovered` (wrong section, the machine's own session, a duplicate import, different contests, a tampered header). They are in the code, but only the happy path is exercised here.
- `cancel_authorization` refusals, and a cancellation that succeeds. The full-session test covers the success path only indirectly.
- the erasure of ρ (see above).
- a crash after `spoil`, before the receipt is printed (see the spec gaps below).

## Spec gaps and issues relevant here

- **Spec issue 17 (imports are not journaled).** `import_recovered` writes nothing to the journal. After a restart the host must import again before `prepare_pre_bu`, or the pre-BU silently covers fewer ballots. The spec should add an `import` record.
- **Spec issue 18 (torn tail versus a damaged length).** `restart` uses `Journal::from_bytes`, which drops everything after a damaged length prefix in the middle of the file, just as it drops a torn final write. On a live machine this could lose cast ballots without an error. The mitigation is in file 19.
- **Spec issue 19 (judging order for a section tally).** `section_sums` judges imported ballots first, then the machine's own, with one reservation set. The verifier in file 24 judges in board order. The spec should fix the order. The two can disagree when an imported ballot and one of the machine's own ballots share an α.
- **Spot check: `section_sums` is not used by the verifier.** The doc comment on `section_sums` says it is "shared by the machine and by verifiers". In the code it is called only by `prepare_pre_bu` and by the tests. The verifier path (`section_tallies` in `crates/eg-core/src/authority.rs`) judges board-wide and does not call it. The comment is out of date. Nothing is broken, because both sides use `judge_cast`, but the comment should say so.
- **Not yet in `spec-issues.md`: a spoiled ballot's receipt after a crash.** §15.4 says that restart reprints a `cast` slip. It says nothing about a spoil. If the crash comes after `spoil` has journaled the reveal and before the receipt is printed, `restart` returns no receipt and the voter has none. The spec should either name the spoil receipt as reprinted too, or say that the voter must spoil again.
- **Not yet in `spec-issues.md`: the roll-count check is on the poll terminal.** §16.2 step 4 requires the poll terminal to check field 13 before signing. `sign_pre_bu` does not check it, because the machine has no roll count of its own to compare with. This is by design, but the tests cannot check it.
