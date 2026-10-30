# 20 · Threshold decryption, mixnet counting and results: opening only the sums

**Code:** `crates/eg-core/src/decrypt.rs`. **Spec:** §16.5 (final BU), §19.4 to §19.6 (decrypting and counting the mixnet's final list), §20 (threshold decryption), §21 (results).

**Scope of this file.** `decrypt.rs` has the share sets, the combination of any *k* valid shares, the discrete-log decoding, the mixnet row counting, the final BU check and the result records. The trustee's own checks before it signs a share (§20.5) and the mixnet's shuffle proofs (file 16) are elsewhere. The trustee-side check is discussed at the end.

## The problem

The tally (file 18) is a set of locked boxes. Something has to open the sums, and the opening has to satisfy five things at once:

1. **No single person can open.** The key is split among *n* trustees, and any *k* of them must be needed (file 10).
2. **A lying trustee cannot change the result.** Its partial opening must come with a proof that anyone can check. A bad proof is discarded and the trustee is named.
3. **A missing trustee does not block the count.** Any *k* honest trustees must be enough (§20.3).
4. **The opened boxes are the ones on paper.** The final BU must open exactly the section tally whose fingerprint is on the pre-BU (file 18).
5. **Anyone can check it.** Every opened number is backed by proofs, so the result does not depend on who published it.

## The idea, without math

Each trustee holds a secret share *z_j* of the key *s* (file 10). To open a box `(α, β)`, the trustee computes its **share** `M_j = z_j·α` and proves, with a Chaum-Pedersen proof (file 05), that `M_j` uses the same secret it committed to (its verification key `Z_j = z_j·B`). The trustees' shares are then combined with Lagrange coefficients (file 02), which gives `s·α`. Subtracting that from β leaves the vote times B:

```
M = Σ λ_j · M_j = s·α          T = β − M = m·B
```

Then a small table lookup turns `m·B` into `m` (file 04, §20.4). Nobody ever computes `s`, and no single trustee's share gives anything.

## Worked by hand: 2-of-3 on the 11-hour clock

These numbers continue file 10. The key is `s = 2` (never shown to anyone), with `B = 3` and `K = s·B = 6`. The trustee shares are `z₁ = 8`, `z₂ = 3`, `z₃ = 9`, and their verification keys are `Z_j = z_j·B`:

```
Z₁ = 8·3 = 24 → 2        Z₂ = 3·3 = 9        Z₃ = 9·3 = 27 → 5
```

**Encrypt a vote of m = 5** with nonce r = 4 (file 04):

```
α = r·B = 4·3 = 12 → 1
β = m·B + r·K = 15 + 24 = 39 → 6          so the box is (α, β) = (1, 6)
```

**Each trustee computes its share** `M_j = z_j·α = z_j·1`:

```
M₁ = 8        M₂ = 3        M₃ = 9
```

**Combine {1, 2}.** The Lagrange coefficients at 0 for the set {1, 2} are λ₁ = 2 and λ₂ = −1:

```
M = 2·8 + (−1)·3 = 13 → 2           (this is s·α = 2·1 = 2 ✓)
T = β − M = 6 − 2 = 4               (this is m·B, and 5·3 = 15 → 4 ✓)
```

The table says 4 is m = 5. Decrypted.

**Combine {1, 3} instead.** λ₁ = 7 and λ₃ = 5. Check: 7 + 5 = 12 → 1, so the coefficients add to 1 as they should.

```
M = 7·8 + 5·9 = 56 + 45 = 101 → 2  ✓    same M, same T, same m = 5
```

Any valid set gives the same answer (test `combine_is_independent_of_the_subset`).

**A lying trustee.** Suppose trustee 2 publishes `M₂' = 4` instead of 3. Its Chaum-Pedersen proof is a proof that the same secret *z₂* gives both `Z₂` and `M₂`. There is no such secret for `M₂' = 4`, since `z₂·α` is 3. So the proof fails, and the share set is discarded.

What would happen without the check:

```
M = 2·8 + (−1)·4 = 12 → 1
T = 6 − 1 = 5
```

Solving `3·m ≡ 5` gives **m = 9**, not 5. The fake share decrypts the box to a different, plausible-looking vote. The proof is what stops this. A bound on m (below) is not enough, since 9 may be within the number of ballots.

## Canonical items (§20.1)

Shares are computed for a list of boxes, and both sides must agree on the order. The functions:

- `section_tally_items`: the sums of each contest in field 6 order, options ascending. For example, the sums of contest 0 (options 0 to 2), then contest 4 (options 0 to 4).
- `pool_tally_items`: as above, but skipping contests with no counted ballots, since those are `(O, O)` and not decrypted (§18.2).
- `mix_list_items`: the rows of the final mix list, in order, and the slots of each row, in order.

Each share is bound to its target and its position by a context:

```
ctx = ["dec", context_hash, target_digest, item_index]
```

`target_digest` is the RecordId of the section tally, the pool tally or the final mixer output. So a share for one tally can't be replayed on another, and a share can't be moved to another position in the same list. `dec_ctx` builds it.

## Share sets (`DecryptionShareSet`, §20.1)

A trustee publishes a `decryption_share_set`: its trustee index *j* and, for every box, a pair `(M_j, proof)`. The set is signed by the trustee's own key (tag `eg/v1/sig/shares`, field 6).

| function | what it does |
|---|---|
| `DecryptionShareSet::create` | for each box, computes `M_j = z_j·α` and its proof with `prove_decryption_share` under the box's `dec_ctx` |
| `sign` | the signed record, with the trustee's signature at field 6 |
| `from_signed` | strict decode, and the signature checked under the trustee's public key |
| `verify` | checks the context hash, one share per box, and every proof against `Z_j = context.z[j − 1]` |

`verify` is the trustee's public check. It needs only the context (which holds the verification keys) and the boxes. Anyone can run it.

## Combining *k* valid sets (`combine`, §20.2, §20.3)

`combine(context, k, items, sets)` works in this order:

1. For each set, in input order: if the context hash differs, reject it ("another context"). Otherwise, if its proofs don't verify, reject it ("proofs do not verify"). Otherwise, if that trustee index is already accepted, reject it ("duplicate trustee index"). Otherwise accept it.
2. If fewer than *k* sets are accepted, return an error. Decryption is incomplete, and the trustees must publish again (§20.3).
3. Sort the accepted sets by trustee index and take the first *k*. Those are the "*k* lowest valid indices" of §20.3.
4. For each box, add `λ_j · M_j` over the chosen trustees, using `lagrange` (file 02).
5. Return `T = β − M` for each box, with the list of trustees used and the list of rejected sets with reasons.

The return value `Combined` keeps the `rejected` list. That list is the report of misbehaviour, and it is what the verifier should publish (§20.3).

Test `combine_discards_bad_sets_and_reports_them` checks the lying trustee case. Test `combine_is_independent_of_the_subset` checks that every subset of *k* gives the same points.

## Decoding: from points to counts (§20.4, §19.5)

**Homomorphic subtotals**, `decode_sums(sums, points)`. Each decrypted point is `m·B`, and `m` must be at most `counted`, the number of ballots counted for that contest. `dlog_bounded(p, counted)` walks `0·B, 1·B, …, counted·B` and returns the first match. If there is none, the function returns an error, and the spec says the process must stop, since it signals a bug or an attack (§28.11).

The walk is linear, so its cost is about *N* additions. The spec allows baby-step giant-step, but a linear walk is simpler to check, and the bound is the number of ballots in one section or pool.

**Mixnet slots**, `decode_slot(point, options)`. Each slot is `m·B` for `m` in `0..=options`, where `m = 0` is an empty slot and `m = i` is option `i − 1`. Anything outside that range is invalid (§19.5).

## Counting decrypted mix rows (`count_mix_rows`, §19.6)

After the last shuffle, every box of the final list is decrypted. Each row is then counted under these rules. The code splits them into three helpers: `judge_slice` (one contest's slots), `split_row` (a row into one slice per contest) and `repeats_candidate` (the link-group check).

| rule (§19.6) | code |
|---|---|
| a slot that is 0 is empty | `Some(0)` in `judge_slice` |
| a slot that is invalid (not in `0..=options`), or a candidate index that appears twice in one contest, makes the row invalid for that contest | `judge_slice` returns `None` |
| each non-empty slot adds one vote to option `m − 1` | `picks` in `judge_slice`, added in `count_mix_rows` |
| a row with only empty slots is a blank vote in a multi contest | `Slice::Blank` when `c.kind == Multi` |
| in single and proportional contests an empty row is invalid, since the machine always fills them | `(c.kind == ContestKind::Multi).then_some(...)` otherwise `None` |
| in a multi contest, null with any candidate is invalid, and null alone is a null vote | the `null` check in `judge_slice` |
| in a link group, a candidate chosen in two contests of one row makes **every** contest of that row invalid | `repeats_candidate`, applied in `count_mix_rows` |

A row whose width does not match the unit is invalid for every contest (`count_mix_rows`).

### Examples

Take a single-choice contest with options A, B, C (so *m* = 1, 2, 3 for A, B, C, and 4 is out of range):

```
row [2]    -> B counted               (m = 2 is option index 1)
row [0]    -> invalid                 (single contests must be filled)
row [4]    -> invalid                 (m = 4 is past the 3 options)
```

A multi-choice contest with options A, B, C, Null, slots = 2 (so *m* = 1, 2, 3, 4 for A, B, C, Null):

```
row [1, 0]    -> A                    one vote for A
row [0, 0]    -> blank, counted       a blank vote is legal in multi contests
row [1, 1]    -> invalid              the same candidate twice in one contest
row [1, 4]    -> invalid              null together with a candidate
row [4, 0]    -> null vote, counted   the null option alone
```

A link group of two single contests, 4 and 5, over the same candidates A, B, C:

```
row [1 | 1]   -> invalid for contests 4 and 5   (A chosen in both: repeats_candidate)
row [1 | 2]   -> A in contest 4, B in contest 5, both counted
```

The link-group case is the one the machine is supposed to prevent (file 12, §7.5). Honest software turns a repeat into a null before encrypting. So a repeat in the decrypted row can only come from misbehaving software. The verifier cannot tell which machine produced an anonymous row, so it reports only the count of invalid rows (§19.6).

Tests: `count_single_rows`, `count_multi_rows`, `link_group_repeated_candidate_invalidates_both_contests`.

## Final BU (`FinalBu`, `check_final_bu`, §16.5)

The final BU is the section's result with its proof attached. It is **not signed**. Its authority comes entirely from the share sets it carries, each of which is signed by its trustee. `FinalBu::to_value` and `from_value` keep the share sets as they were published, so that the trustee signatures stay checkable.

`check_final_bu(fb, tally, context, k, trustee_keys)` does this:

1. The context hash must match the context and the section tally.
2. `fb.pre_bu_id` must equal the tally's pre-BU id, and `fb.section_tally_id` must equal `tally.record_id()`. So the final BU is about this section tally.
3. For each share set in the final BU: look up the trustee's key (`trustee_keys[j − 1]`), decode it with `from_signed` (which checks the trustee's signature), and keep it only if its target is this section tally. A set that fails any of these is skipped, as §20.3 requires.
4. Call `combine` with the section tally's boxes. The proofs are checked there.
5. Decode the sums with `decode_sums`, and compare the result with `fb.results` (field 5). They must be equal.

`check_final_bu` returns only `Ok` or an error. It drops the `rejected` list, so a verifier that wants to report the lying trustees must call `combine` itself (spec issue 16).

### The attempt and what catches it

These are the cases of §16.5, with where each is checked:

| attempt | caught by |
|---|---|
| publish numbers other than the ones the share proofs force | `decode_sums` gives the proven numbers, and step 5 compares them (the end-to-end test alters one count and expects failure) |
| decrypt a different set of boxes | the section tally id (step 2) and, before that, the fingerprint on the pre-BU (file 18) |
| a trustee lies in its partial opening | its proof fails in `verify` (step 4) and the set is dropped, and `combine` reports it |
| fewer than *k* valid share sets | `combine` returns an error, and decryption is incomplete (`short` case in the end-to-end test) |
| a share set for another target, or another election | steps 1 and 3 |
| a share set signed by someone other than the trustee | `from_signed` in step 3 |

## Results (§21)

These are the records the EA signs at the end. The spec notes that verifiers recompute everything anyway, so the EA's signature is for accountability, not for trust.

| record | fields | what it reports |
|---|---|---|
| `ContestResult` (`contest_result`) | contest index, votes per option, counted, invalid (mixnet only), excluded, and for proportional contests the party totals and seats | one per contest |
| `SectionResult` (`section_result`) | section id, pre-BU id, final BU id, the kept contests, the excluded counts per contest, and `"match"` or `"mismatch"` | one per pre-BU, in board order |
| `ElectionResult` (`result`) | context hash, tree size at the cutoff, the contest results, the section results, the pool | the whole election, signed by the EA with `eg/v1/sig/result` |

Points to notice:

- **Excluded ballots are reported per section, not hidden in a total** (§21). A count of excluded ballots is public and tied to a machine. Whether to annul is a legal decision outside the protocol.
- **`match` or `mismatch`** is the result of the fingerprint check (file 18). A `mismatch` is reported against the machine, and the tally recomputed from the board is the one that is opened, so valid votes still count.
- `ElectionResult::from_signed` checks each contest against the manifest. A result for a contest the manifest does not have is rejected, and the seat count is taken from the manifest when a proportional result is decoded.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `dec_ctx` | `["dec", context_hash, target, item]` | binds each share to its tally and position |
| `section_tally_items`, `pool_tally_items`, `mix_list_items` | the canonical lists of boxes | both sides must decrypt the same list in the same order |
| `DecryptionShareSet::create` | computes `M_j = z_j·α` and proves each one | what a trustee publishes |
| `DecryptionShareSet::sign`, `from_signed` | the signed record, and its checked decode | the trustee's signature |
| `DecryptionShareSet::verify` | checks the context, length, and every proof against `Z_j` | the public check that makes a lying trustee detectable |
| `share_from_value`, `to_pairs` | small helpers for encoding | |
| `combine` | verifies all sets, takes the lowest *k* valid, interpolates | §20.2 and §20.3 |
| `decode_sums` | `m·B` to `m`, bounded by `counted` | §20.4 |
| `decode_slot` | `m·B` to `m` in `0..=options` | §19.5 |
| `MixCount` | counts per contest for one unit | the output of §19.6 |
| `judge_slice` | one contest's slots, to blank, votes or invalid | §19.6 rules, one contest |
| `split_row` | a row into its contests' slices, by limit | link groups |
| `repeats_candidate` | a candidate in two contests of one row | the link-group rule |
| `count_mix_rows` | counts every row of a unit | §19.6 end to end |
| `FinalBu::to_value`, `from_value` | the final BU; share sets kept as published | §16.5 |
| `share_set_shape`, `trustee_of` | shape check, and the trustee index of a published set | used when reading share sets |
| `check_final_bu` | steps 1 to 5 above | §16.5 checks |
| `results_to_value`, `results_from_value`, `result_item` | `(contest, counted, votes)` lists | the shared shape of field 5 and the pool |
| `ContestResult::to_value`, `from_value` | the §21 contest record, with optional party and seat fields | |
| `SectionResult::to_value`, `from_value` | the §21 section record | |
| `uint_pair`, `pairs_to_value` | `[uint, uint]` pairs | |
| `ElectionResult::fields`, `sign`, `from_signed` | the signed result, checked against the manifest | §21 |

## Design choices

- **A proof per box, not one per tally.** Each box is checked on its own. The cost is larger share sets, but a fault in one box is found and named, and the context binds it to its position.
- **Verify every set, use any *k*.** A verifier does not have to trust the trustee who was first. The result is the same for every valid subset, which the test checks.
- **Discard, do not abort.** A lying trustee cannot stop the count (§20.3). It is still reported, through `combine`'s `rejected` list.
- **The lowest *k* valid indices.** The choice is deterministic, so two verifiers using the same board pick the same set.
- **A bounded discrete log.** The bound *N* stops a lie from decoding to any value at all. A value outside the bound means a bug or an attack, and the spec says to stop.
- **The final BU is unsigned.** Its authority is the proofs. Anyone can publish one, and anyone can check it. This is the point of §16.5.
- **Canonical item order from the spec, not from the code.** The trustee and the verifier must build the same list, so the order is written down in §20.1 and implemented in the three `*_items` functions.
- **Excluded ballots are published, not totalled away.** A total would hide which machine caused the exclusions.

## Attacks each check stops

| attack | what stops it |
|---|---|
| one trustee alone opens a box | the key is shared (file 10), and a share is useless without *k* others |
| a trustee publishes a false share | its proof fails in `verify` (`combine_discards_bad_sets_and_reports_them`) |
| a share set for another tally, or another position | the context includes the target and the item index |
| a share set from an unknown or wrong key | `from_signed` in `check_final_bu` |
| a count that is outside the number of ballots | `decode_sums` fails (`decode_sums_recovers_counts_and_rejects_overflow`) |
| a final BU that states different counts | `decode_sums` gives the proven counts, and step 5 compares (the end-to-end test) |
| a mix row with a repeated candidate in a link group | `repeats_candidate` makes the row invalid for all its contests (`link_group_repeated_candidate_invalidates_both_contests`) |
| a result for a contest the manifest does not have | `ElectionResult::from_signed` |

## What the trustee checks before signing (§20.5), and where they are

A trustee's shares can open any box, so an honest trustee must check the target before it produces shares. These checks are **not** in `decrypt.rs`. They belong to the trustee's own decryption service, which takes the board dump, not bare boxes:

- for a section tally: the pre-BU is in an accepted package, every imported recovered package is accepted, and the section tally recomputed from them is byte-identical, including which contests are pooled. The trustee never opens a pooled contest;
- for a pool tally: only after the cutoff, and recomputed at the cutoff's tree size;
- for a final mix list: the first input list is built per §19.1, every step's proof verifies, each step's input is the previous output, and at least `min_mixers` distinct trustees mixed the unit. The trustee never opens an input or intermediate list.

Without these checks, a corrupt EA could hand the trustees a "tally" that is really one voter's ballot. The spec's `ShareHolder` interface (§25) is meant to enforce this, and it is not written yet.

## Tests (13)

- **Share sets:** a set round-trips and verifies, and a tampered one fails (`share_set_round_trip_and_verify`).
- **Combination:** any subset gives the same plaintext, and a bad set is discarded and reported (`combine_is_independent_of_the_subset`, `combine_discards_bad_sets_and_reports_them`).
- **Decoding:** counts are recovered, and an overflow is rejected (`decode_sums_recovers_counts_and_rejects_overflow`).
- **Mix rows:** single and multi rows, including blanks, nulls and repeats, and the link-group rule (`count_single_rows`, `count_multi_rows`, `link_group_repeated_candidate_invalidates_both_contests`).
- **End to end, homomorphic:** five encrypted ballots, a 2-of-3 ceremony, decryption, the final BU check, and a failure when a count is altered, the pre-BU id is wrong, or fewer than *k* sets are given (`homomorphic_election_end_to_end`).
- **Canonical order:** pool and mix items come out in the order §20.1 gives (`pool_and_mix_items_have_canonical_order`).
- **End to end, mixnet counting:** the rows of a mixnet contest are encrypted, their shares combined and decoded slot by slot, and counted with `count_mix_rows`. There is no shuffle here; the shuffle is file 16 (`mix_unit_end_to_end`).
- **Results:** a result is signed by the EA and opened again (`election_result_sign_and_open`), a section result's strict decode (`section_result_strict_decode`), and a final BU is rejected when it has no share sets or a wrong tag (`final_bu_round_trip_rejects_wrong_tag`).

## Spec gaps and issues relevant here

- **Spec issue 16 (rejected share sets in the final BU check).** `check_final_bu` discards failing share sets and drops `combine`'s `rejected` list. The verifier must call `combine` to report them.
- **§20.4 and the discrete log.** The spec allows baby-step giant-step. The code uses a linear walk, which is simpler to check, and the bound *N* keeps it small enough for one section.
- **§20.5 is in `authority.rs`, not here.** `trustee_decrypt` (file 24) does the trustee's pre-checks for section tallies, the pool and the final mix list. It does not check that every imported recovered package is on the board, so a missing import is dropped silently there. Anything that calls `DecryptionShareSet::create` without those checks can open any box it is given.
- **§28.11.** A failed discrete log must stop the process. `decode_sums` returns an error, and the caller must treat that as fatal, not as a missing count.
