# 17 · Seat apportionment: from verified votes to seats

**Code:** `crates/eg-core/src/apportionment.rs`. **Spec:** §22 (§22.1 party totals and lists, §22.2 the `dhondt` rule, §22.3 the `brazil-2021` rule, §22.4 list indices, §22.5 ties). Gaps in the spec are listed in `docs/spec-issues.md`, items 3 to 7 and 11.

> **Legal review required.** The `brazil-2021` rule encodes a reading of the Código Eleitoral as amended in 2021 and of the STF ruling of 2024. The spec says that an electoral lawyer must confirm each step and parameter before any real use. This file explains what the code does. It is not a legal opinion.

## The problem

Once the tally has produced a verified total for every option of a proportional contest (the deputies, file 12), the seats have to be shared out. The rules are:

- seats go to **lists** (a party, or a federation of parties) in proportion to their votes;
- within a list, seats go to the **candidates** with the most votes;
- ties are settled by fixed rules;
- anyone with the same numbers must get the same seats.

The last point is why the function uses **integer arithmetic only**. A floating-point rounding difference on two machines could turn a tie into a win for one list. With integers, the answer is the same everywhere. Fractions are compared by cross-multiplying, in 128-bit integers so the products don't overflow.

## Lists and federations (§22.1, §22.4)

A **party total** is the votes for the party's own option, plus the votes for every candidate of that party. Blank and null votes belong to no party.

```
party_total(p) = votes(party option of p) + Σ votes(candidate x with party p)
list_total(F)  = Σ party_total(p), over the parties p in list F
V              = Σ list_total,    over all lists
```

A **list** is either a **federation** (several parties standing together) or a single party that isn't in any federation. Federations come first in manifest order, then unfederated parties, also in manifest order (§22.4).

**Worked example** (the `fixture_party_totals_and_lists_without_federation` test). Eight options in order: Dora 10 (party 0), Edu 20 (party 0), Fabi 5 (party 1), Gil 7 (party 1), Partido Azul 3 (party 0), Partido Verde 4 (party 1), Branco 1, Nulo 2.

- party 0 = 10 + 20 + 3 = **33**
- party 1 = 5 + 7 + 4 = **16**
- blank and null are excluded, so V = **49**

Without a federation, the lists are party 0 (33) and party 1 (16). If parties 0 and 1 form one federation, there is a single list of 49 with all four candidates. The test `federations_come_first_and_absorb_their_parties` checks both.

## The `dhondt` rule (§22.2)

Seats are given out **one at a time**. Each seat goes to the list with the highest `list_total / (seats_won + 1)`, among lists that still have an unseated candidate. Within a list, seats go to its candidates in descending order of individual votes.

An optional **threshold** (in basis points of V) excludes small lists first. A list with `list_total · 10000 < threshold · V` takes no part. 500 basis points is 5%.

**Worked example: the 8-seat test** (`dhondt_textbook_example`). Four lists: A = 100 000, B = 80 000, C = 30 000 and D = 20 000 votes. Each has eight candidates, all with 0 votes, so every seat comes from the list quotients.

Each list's successive quotients are its total divided by 1, 2, 3, and so on:

- A: 100 000, 50 000, 33 333, 25 000, …
- B: 80 000, 40 000, 26 667, 20 000, …
- C: 30 000, 15 000, …
- D: 20 000, 10 000, …

Take the eight largest quotients, in order, and count:

| seat | largest remaining quotient | list | cumulative seats |
|---|---|---|---|
| 1 | 100 000 | A | A 1 |
| 2 | 80 000 | B | B 1 |
| 3 | 50 000 | A | A 2 |
| 4 | 40 000 | B | B 2 |
| 5 | 33 333 | A | A 3 |
| 6 | 30 000 | C | C 1 |
| 7 | 26 667 | B | B 3 |
| 8 | 25 000 | A | A 4 |

The result is A 4, B 3, C 1, D 0. The test asserts exactly this.

**Worked example: a tie and a threshold** (`dhondt_threshold_excludes_small_list`). Lists P0 = 48 (one candidate, rank 1), P1 = 48 (one candidate, rank 2) and P2 = 4 (three candidates). V = 100, 3 seats.

- Seat 1: P0 and P1 both have 48/1. The lists tie on the ratio. The higher total is the same, so the candidate with the lower tiebreak rank decides: P0 (rank 1) wins.
- Seat 2: P0 has 48/2 = 24, P1 has 48/1 = 48. P1 wins.
- Seat 3: P0 and P1 have no candidates left. P2 has 4/1, so P2 gets it.
- Result: 1, 1, 1.

With a 5% threshold (500 basis points), P2 is excluded, since 4 · 10 000 = 40 000 is less than 500 · 100 = 50 000. The result is 1, 1, 0, and one seat stays unfilled. Lists that run out of candidates leave their seats unfilled (`dhondt_unfilled_seats_when_lists_run_out`).

## The `brazil-2021` rule (§22.3)

The Brazilian rule has more steps, because the law gives a **quotient** part and a **remainder** part, and sets minimum vote levels for each. The parameters are in the manifest, in basis points of the electoral quotient QE: the candidate minimum for quotient seats (default 1000, i.e. 10%), the list minimum for remainder seats (default 8000, i.e. 80%), the candidate minimum for remainder seats (default 2000, i.e. 20%), and whether the final phase is open (default true).

### Step 1: the electoral quotient

```
q = V div seats,   rem = V mod seats
QE = q + 1 if 2 · rem > seats, else q
```

The fraction is dropped if it is one half or less, and rounded up otherwise. `electoral_quotient` implements this, and the tests check the boundary cases:

| V | seats | q | rem | 2·rem > seats? | QE |
|---|---|---|---|---|---|
| 1000 | 3 | 333 | 1 | no | **333** |
| 1001 | 3 | 333 | 2 | yes (4 > 3) | **334** |
| 1002 | 4 | 250 | 2 | no (4 is not > 4) | **250** |
| 1003 | 4 | 250 | 3 | yes (6 > 4) | **251** |

### Step 2: nobody reaches QE

If no list has `list_total ≥ QE`, the most-voted candidates are elected across all lists, until the seats run out (Código Eleitoral art. 111). The rule ends here. The test `brazil_no_list_reaches_qe_elects_most_voted_across_lists` has list totals 30, 30, 20 and 20 with V = 100 and three seats. QE = 33, so no list reaches it. The three most-voted candidates win: Y (28), X (25), then Z (20).

The same step covers QE = 0, which happens when V is very small. Step 3 would divide by it, so the code takes the most-voted path. The spec is silent on this (spec issue 3). Example: V = 1, three seats gives QE = 0. The one candidate is elected and two seats stay unfilled.

### Step 3: the party quotient

```
QP(F) = list_total(F) div QE
```

Each list gets QP(F) quotient seats. For V = 100, seats = 3, QE = 33: a list of 70 votes has QP = 70 div 33 = 2, and a list of 30 has QP = 0.

### Step 4: filling the quotient seats

Each list takes up to QP(F) seats, filled by its candidates with at least the **candidate minimum** of QE, in descending order of votes. If a list has fewer eligible candidates than QP(F), the unused places join the remainder pool.

### Step 5: remainder seats, by highest averages

While seats remain, the seat goes to the eligible list with the highest `list_total / (seats_won + 1)`, and within it to the unseated candidate with most votes. A list is eligible if its total is at least the **list minimum** of QE. A candidate is eligible if their votes are at least the **candidate minimum for remainder seats**.

### Step 6: the final phase

If seats still remain and no list is eligible under step 5:

- with the final phase **open** (parameter 4 true), the highest-averages procedure continues with every list, and every unseated candidate, regardless of votes;
- with it **closed** (parameter 4 false), the same procedure runs among lists whose total is at least QE, with no candidate thresholds.

### Step 7: federations

Federations are treated as single lists throughout. Their seats go to their own candidates by individual votes.

### Worked example: the quotient step with a candidate minimum

From the test `brazil_quotient_seats_need_candidate_minimum`. Candidates A = 60, B = 2, C = 8 (party 0, whose party option has 0 votes, so its total is 70), and D = 30 (party 1, total 30). V = 100, three seats.

1. **QE.** q = 100 div 3 = 33, rem = 1, and 2 · 1 = 2 is not greater than 3. So QE = **33**.
2. **Step 2 is skipped.** Party 0 has 70, which is at least 33.
3. **Party quotients.** QP(party 0) = 70 div 33 = **2**. QP(party 1) = 30 div 33 = **0**.
4. **Quotient seats.** The candidate minimum is 10% of 33 = 3.3 votes. A has 60 (eligible), C has 8 (eligible), and B has 2 (not eligible, since 2 < 3.3). Party 0's two quotient seats go to **A and C**.
5. **Remainder.** One seat is left. The list minimum is 80% of 33 = 26.4. Party 0 (70) and party 1 (30) both clear it. The candidate minimum for remainder seats is 20% of 33 = 6.6. Party 0's only unseated candidate is B (2), which is below 6.6, so party 0 has no eligible candidate. Party 1's D (30) is eligible, and party 1 is the only list with an eligible candidate, so **D** takes the seat.
6. **Result.** Elected A, C, D; seats party 0 = 2, party 1 = 1. B is never elected.

Notice that the candidate minimum works in two places. The 10% minimum keeps B out of the quotient seats. B would also fail the higher 20% minimum for remainder seats, so the last seat goes to party 1 rather than to B.

### Worked example: the final phase

From the test `brazil_remainder_seats_need_list_minimum_and_final_phase_param`. Party 0 has A = 60 and B = 40 (total 100). Party 1 has C = 65 (total 65). Party 2 has a party option of 5 plus D = 30 (total 35). V = 200, four seats, so QE = 50 (rem = 0).

- Quotients: QP(party 0) = 2, which gives A and B. QP(party 1) = 1, which gives C. QP(party 2) = 0. One seat remains.
- Step 5: the list minimum is 80% of 50 = 40. Party 2's total is 35, which is below 40, so it is not eligible. Parties 0 and 1 have no unseated candidates. No list is eligible.
- Step 6, with parameter 4 **false**: only lists with total at least QE = 50 are considered. Party 2 (35) is not one of them, so the seat stays unfilled.
- Step 6, with parameter 4 **true**: every list and candidate is eligible. D (30) takes the seat.

The two readings give different results, which is why the parameter is explicit and why the legal review matters.

## Ties (§22.5)

**Between lists** (in the highest-averages comparison): the list with the higher `list_total` wins. If the totals are also equal, the list containing the candidate with the lowest `tiebreak_rank` wins.

**Between candidates**: the lower `tiebreak_rank` wins. The rank comes from the legal criterion (in Brazil, the older candidate, art. 110), and the manifest requires every candidate of a proportional contest to have a distinct rank. That is why the tie rule is always decisive.

The code's `prefers` implements the list rule in the order the spec gives: ratio, then `list_total`, then the rank. There is one extra step. If all three are equal, the list index decides. With distinct ranks, the rank comparison always decides first, so that last step is never reached in practice.

The spec words the list tie rule for list totals. The code also applies it to ties in the highest-averages ratio, first by `list_total`, then by rank (spec issue 5). Within a list, candidates are ordered by votes descending, then by rank ascending.

## Integer arithmetic: why and how

Two fractions `a/b` and `c/d` are compared by checking `a·d` against `c·b` (§22). The code does this in `prefers`, with `ta · wb` against `tb · wa`, where `wa = won + 1`.

**Example.** List A has 100 000 votes and has won 2 seats, so its average is 100 000 / 3. List B has 80 000 and has won 1, so its average is 80 000 / 2. Compare 100 000 · 2 = 200 000 with 80 000 · 3 = 240 000. The larger product is B's, so B's average is higher, and B takes the seat. No division is needed, so nothing is rounded.

Threshold tests use the same idea: `votes · 10000 ≥ bp · QE`. Products are computed in `u128`, so a product of two `u64` values can't overflow. Sums of votes are checked (`add`) for overflow.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `List` | a list: its index, parties, `list_total`, and candidate option indices | the unit of seat allocation (§22.1) |
| `SeatAllocation` | the result: rule name, seats per list, elected candidates in award order, QE (brazil only), unfilled seats | the `seat_allocation` record (§22.3) |
| `SeatAllocation::to_value` | encodes the CDDL map | the signed result |
| `SeatAllocation::from_value` | decodes against the seats of the contest; rejects more elected candidates than seats, and seats per list that don't sum to the elected count | a recorded result must be internally consistent |
| `tally` | builds `Error::Tally` | errors name the stage |
| `add` | checked addition of vote totals | an overflow is an error, not a wrap |
| `check_contest` | the contest is proportional, and has one vote count per option | the function is only defined for those inputs |
| `vote_of` | the vote count of one option | an option with no count is an error |
| `party_totals_by_index` | party totals for every party, with blank and null excluded | §22.1 |
| `party_totals` | the same, as `(party, total)` pairs, for parties that appear in the contest | for the public report |
| `lists` | the lists in §22.4 order, with totals and candidates | federations first, then parties |
| `electoral_quotient` | QE: `q`, plus one when `2·rem > seats` | §22.3 step 1; the `u128` cast avoids overflow |
| `Cand` | a candidate with its votes, rank, and list | the working record |
| `Pool::new` | builds the candidate list and orders each list's candidates | errors if a candidate has no rank or is in no list |
| `Pool::remaining` | seats still to award | the loop bound |
| `Pool::seat` | awards one candidate's seat | the single place seats are recorded |
| `Pool::prefers` | whether list *a* beats list *b* for the next seat: ratio, then total, then rank | §22.2 step 2 and §22.5, in integers |
| `Pool::best` | the best next seat among eligible lists and candidates | one step of highest averages |
| `Pool::by_averages` | awards seats one at a time with `best` until none are left or none are eligible | highest averages, used by D'Hondt and by steps 5 and 6 |
| `Pool::most_voted` | the most-voted candidates across all lists, ties by rank | §22.3 step 2, and the QE = 0 guard |
| `Pool::dhondt` | D'Hondt: lists below the threshold are excluded, then highest averages | §22.2 |
| `brazil` | steps 2 to 6 of §22.3 | the Brazilian rule, with the QE = 0 guard |
| `apportion` | the entry point: validates the contest, computes lists and V, picks the rule, builds the result | what callers use |

## Design choices

- **Pure and deterministic.** `apportion` takes the manifest, the contest and the verified counts, and returns the seats. It reads nothing else. Anyone can rerun it.
- **The rule and its parameters come from the signed manifest.** The thresholds and the brazil parameters are data, so changing them is a manifest change that everyone sees, not a code change.
- **Exact fractions.** Integer comparison in `u128` removes rounding from the decision, which is the only place where rounding could change a result.
- **Ties are never random.** Every tie resolves through a fixed chain of rules, ending in a rank that the manifest requires to be distinct.
- **Errors instead of silent defaults.** A candidate without a rank, or a candidate in no list, is an error. The apportionment doesn't guess.
- **Zero valid votes award no seats.** The spec is silent on V = 0 (spec issue 6). The code awards no seats for either rule and reports all of them as unfilled. This is a decision, and it is marked as one in the code.
- **One pool for both rules.** `Pool` holds the candidates and the seat state, so the seat-awarding rules (highest averages, most voted) are written once and used by both rules.

## Attacks and failure modes each check prevents

| situation | what happens |
|---|---|
| two machines compute a different seat count from the same totals | impossible: integers only, no floating point |
| a tie settled differently by two verifiers | impossible: the tie chain is fixed and ends in distinct ranks |
| a blank or null vote buys a seat | blank and null belong to no party, so they add to no list total |
| a candidate with no rank | `Pool::new` returns an error |
| a recorded result with more elected candidates than seats | `SeatAllocation::from_value` rejects it |
| a recorded result whose per-list seats don't add up | `from_value` rejects it |
| a party's candidates counted in another party's list | a candidate's list is the one holding its party |

## Tests (19)

- **Lists:** party totals and lists with no federation; federations come first and absorb their parties.
- **D'Hondt:** the 8-seat textbook example; a threshold excludes a small list; unfilled seats when lists run out.
- **Electoral quotient:** the rounding cases in the table above, and QE = 0 for V = 0.
- **Brazil, quotient:** the candidate minimum keeps B out; an unused quotient place goes to the remainder pool; the most-voted path when no list reaches QE; QE = 0 uses the most-voted path.
- **Brazil, remainder and final phase:** the list minimum and the final-phase parameter (both readings, as above); the candidate minimum for remainder seats (with a boundary case where a list total is exactly the minimum).
- **Zero votes:** no seats for either rule.
- **Ties:** a list tie broken by candidate rank; a ratio tie broken by the higher `list_total` first; a candidate tie broken by rank, with votes ordered first.
- **Errors:** a missing tiebreak rank is an error; a non-proportional contest or a wrong vote count is rejected.
- **Encoding:** the seat allocation round-trips.

## Spec gaps (`docs/spec-issues.md`, items 3 to 7, and 11)

- **Item 3, QE can be 0.** With a small V and many seats (V = 1, seats = 3), QE is 0 and step 3 divides by zero. The code falls back to the most-voted path. A legal reading is needed.
- **Item 4, quotient seats can exceed the seats.** With QE rounded down, the quotient seats can add up to more than the seats. For V = 4, seats = 3, QE = 1, the quotients give Σ QP = 4 > 3. The code stops at `seats` in list order, which is arbitrary. A rule is needed.
- **Item 5, the list tie-break applied to ratio ties.** The spec states the rule for list totals. The code also uses it for ties in the highest-averages ratio, by `list_total` and then by rank.
- **Item 6, zero valid votes.** The spec is silent. The code awards no seats and reports all of them as unfilled. The `seat_allocation` CDDL requires `[+ uint]` for the elected list, but the code accepts an empty list, so the zero-vote result round-trips.
- **Item 7, zero-vote candidates.** D'Hondt can give a seat to a candidate with 0 votes, once a list's candidates with votes are used up. The code follows the spec's text literally. Whether that is the intent is a question for the legal review.
- **Item 11, brazil parameter ranges.** The basis-point parameters have no stated bounds, and the code doesn't check them. A candidate minimum above 100% would make no candidate eligible for quotient seats.
