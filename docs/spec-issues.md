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
