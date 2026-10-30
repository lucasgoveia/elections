# Spec issues found during implementation

Gaps, ambiguities and deliberate deviations found while building the reference
implementation of SPEC.md Draft 0.4. Each entry says what the code does today,
so the spec can be updated to match (or the code changed).

## Open

1. **§19.3 vs §5.2: generator label type.** §5.2 defines `Gen(label, i)` with a
   text label, but §19.3 uses the array `["shuffle", contest_index, region, step]`.
   The code hashes `CBOR(["eg/v1/gen", context_hash, <that array>, i])`
   (`shuffle.rs`, `shuffle_gen`). The spec should allow any CBOR value as label.

2. **§19.3: which `c` goes into `u_j`.** The prover step writes
   `HashToScalar("eg/v1/shuffle-u", ctx, E, Ẽ, c, j)`. The code reads `c` as the
   vector of permutation commitments `c_1..c_N`. The spec should say `c_vec`.

3. **§22.3 step 3: QE can be 0.** When V is small relative to the seats (for
   example V = 1, seats = 3), QE = 0 and `list_total div QE` divides by zero. The
   code falls back to step 2 (most-voted candidates). Needs a legal reading.

4. **§22.3 step 4: quotient seats can exceed the seats.** With QE rounded down
   (for example V = 4, seats = 3, QE = 1), Σ QP(F) = 4 > 3. The code caps awards
   at `seats` in list order, which is arbitrary. Needs a rule.

5. **§22.5 applied to ratio ties.** The list tie-break is worded for list totals.
   The code also applies it to highest-average ratio ties (D'Hondt and step 5),
   first by higher `list_total`, then by lowest candidate rank.

6. **§22 with zero valid votes.** The spec is silent. The code awards no seats
   (all unfilled). `seat_allocation` field 3 is `[+ uint]` in the CDDL, but the
   code accepts an empty list so that this case round-trips.

7. **§22.2 zero-vote candidates.** D'Hondt can award a seat to a candidate with
   0 votes once a list's voted candidates are used up. The code follows the text
   literally.

8. **§12.3a link witness when no contest selects the candidate.** The witness
   bit is 0 then; the spec could say so explicitly.

9. **§23 verifier independence.** §23 says the verifier crate MUST NOT depend on
   code used to produce ballots, packages or tallies. The reference build plans a
   separate verifier crate that reuses the primitive codecs and *verify*
   functions of `eg-core` and recomputes everything else itself. A fully
   independent reimplementation is still needed before real use.

10. **§7.7 reserve machine contests.** A reserve machine's offered contests must
    equal those of the section it serves, but the binding happens on the day, so
    registry validation can't check it. It is checked at package ingestion.

11. **§22.3 parameter ranges.** The brazil-2021 basis-point parameters have no
    stated bounds; the code doesn't range-check them.

12. **§12.6 α reservation inside link groups.** When a later contest of a link
    group is excluded by reservation, the code keeps the reservations already
    made by earlier contests of that group on the same ballot (those α stay
    burned). The spec doesn't say.

13. **§19.1 merged region names.** The order of names in a merged region isn't
    specified. The code joins the merged group's region names sorted by name
    (`"A+C"` even when C merged into A).

14. **§19.1 row counts used for merging.** The code counts a ballot toward its
    region only if all contests of the unit are counted on it (the same rule
    as the input list).

15. **§15.4/§16.4 unfinished ballot in a recovered journal.** Checkpoints only
    follow status records, so a recovered journal cut at its last checkpoint
    never ends inside a ballot. The checker rejects a committed ballot without
    a status in both modes; the §15.4 "becomes abandoned" rule applies only to
    a live machine replaying its own journal, which appends `abandoned`.

16. **§20.3 rejected share sets in final BU checks.** `check_final_bu` discards
    share sets that fail; the verifier reports them separately through
    `combine`'s `rejected` list.

17. **§16.4 imports aren't journaled.** The journal has no record for importing
    a recovered package. After a restart the host must re-import before
    `prepare_pre_bu`, or the pre-BU silently covers fewer ballots (the voter-roll
    count on paper would expose it). The spec should add an `import` record.

18. **§15.1 torn tail vs a damaged length field.** A damaged length prefix in a
    middle frame that points past the end looks exactly like a torn final
    write, so the frames after it are dropped without an error. On a live
    machine this could silently lose cast ballots. Mitigations: compare both
    journal media on restart, or add a per-frame length check (e.g. repeat the
    length after the record).

19. **§12.6 judging order for a section tally.** The machine judges imported
    recovered ballots first (import order), then its own cast ballots (journal
    order), with one reservation set. The verifier must use the same order;
    the spec should state it.

20. **§12.6 nonce reuse reports both contests.** The tally excludes only the
    later contest that hits a reserved α; the verifier must still report both
    ballots (and their machine) as evidence of nonce reuse.

21. **§16.5 section with every contest pooled.** Its final BU would need
    `[+ decryption_share_set]` over zero items, which can't exist. The code
    builds no final BU for such a section and uses the all-zero digest as
    `section_result` field 3. The spec should allow an empty final BU or say
    that field 3 is absent.

22. **§16.4 double import.** If two pre-BUs list the same recovered package,
    both section tallies cover its ballots and the totals double count. The
    spec should forbid it (and the verifier report it).

23. **§19.2 mix share sets and their target.** The target digest of a final
    mix list is the RecordId of the last `mix_output`. The result assembly
    checks the share proofs against the list's items; the digest binding is
    checked by the verifier.

24. **§12.4 mixnet slots under a wrong key.** A slot proof shows knowledge of
    the nonce behind α only, so a machine encrypting under a wrong key passes
    the proof; the slot decrypts to garbage and is counted invalid (§19.6),
    not excluded. That's by design, but the invalid count is the only trace.

25. **§16.5/§18.1 election-night opening.** The spec allows opening a section
    tally before `tally_cutoff`. The reference pipeline builds its board view
    only at the cutoff, so section tallies open after it.

26. **§15.4 crash after spoil.** Restart reprints a cast slip, but a crash
    between `spoiled` and printing leaves the voter with no spoil receipt. The
    spec is silent; reprinting the receipt the same way would close it.

27. **§14.2 vote flipping is caught only by the voter's own check.** When a
    machine encrypts something other than the voter's choice and then signs a
    spoil receipt claiming the real choice, the board's reveal is consistent
    with the flipped ballot, so the public verifier (step 8) passes. Only the
    independent check of the voter's receipt shows the mismatch. That is the
    Benaloh design, but it means receipts must actually be checked.

28. **§23 verifier gaps not yet closed.** Reserve machines' poll-worker keys
    aren't re-checked in step 7 (the journal checker enforces them); step 16's
    "published nothing" covers observer certificates only, not mirror heads or
    trustee messages; steps 7, 10, 12, 13 and 14 have no tamper tests.
