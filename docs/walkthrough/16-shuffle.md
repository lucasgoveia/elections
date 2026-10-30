# 16 · The mixnet: a re-encryption shuffle and its proof

**Code:** `crates/eg-core/src/shuffle.rs`. **Spec:** §19.1 (the input list), §19.2 (the shuffle), §19.3 (the Terelius-Wikström proof), §19.4 to §19.6 (decryption and counting, briefly), Appendix B (the algebra of the proof). The encryption it shuffles is file 04, and the decryption is §20.

## The problem

Most contests use the **homomorphic** tally: all the boxes are added up and only the total is opened (file 04). That works when the question is "how many votes for each option". It can't answer a question about **individual ballots**, for two reasons.

1. **Ballot-level checks.** Some rules can only be checked on one ballot at a time after it is opened. A mixnet ballot is one row of slots, and the counting rules (§19.6) look at each row: is a slot filled twice, does a null appear with a candidate, does a candidate appear in two linked contests. The homomorphic sum can't see those.
2. **Unlinking.** Within a region, the ballots should lose their link to the package that carried them. A voter's ballot can then only be told apart from others in the same region, which is the **anonymity set**. The region is published (§19.1).

A **mixnet** solves both. Each ballot is a row. The rows are passed through a series of **shuffles**, each one putting them in a secret random order and re-wrapping them, and then the final list is decrypted one row at a time. Each shuffle comes with a **proof** that it did only that: permute and re-encrypt, and nothing else.

Section 7.4 of the spec notes the trade-off. Per-section results, which Brazilian law requires, need the homomorphic method. The mixnet is for contests where per-section results aren't required.

## The idea, without math

Picture a deck of cards, each face down, each in a sealed envelope that only the trustees' key can open.

- A **shuffle** takes the deck, shuffles it in secret, and **re-seals every envelope** with fresh wrapping. The sealed contents don't change, but the envelopes look new, so nobody can match an output envelope to its input by looking.
- The shuffle's output is the next shuffle's input. Several mixers do this in turn.
- A **proof** lets everyone check that the output is the input, reshuffled and re-sealed, and that nothing was added, dropped or changed, **without learning the order**.
- As long as **one** mixer in the chain is honest, the order it chose is secret and gone. Nobody can trace an output row back to its input row.

## A toy shuffle on the 11-hour clock

Use the election key *K* = 1 from file 04 (secret s = 4, B = 3, K = s·B = 12 ≡ 1). A row is an encrypted vote `(α, β) = (rB, mB + rK)`, and decryption is `β − s·α`. Three input rows, from earlier worked examples:

| input row | vote *m* | nonce *r* | (α, β) |
|---|---|---|---|
| E1 | 1 | 2 | (6, 5) |
| E2 | 0 | 5 | (4, 5) |
| E3 | 1 | 7 | (10, 10) |

The mixer picks the order **output = [E3, E1, E2]**, which is the permutation π(1) = 3, π(2) = 1, π(3) = 2. Then it **re-encrypts** each row, which adds a fresh `(r̃B, r̃K)` to the pair:

| output | re-encrypts | r̃ | new (α, β) |
|---|---|---|---|
| Ẽ1 | E3 = (10, 10) | 5 | (10 + 15, 10 + 5) = (25, 15) ≡ **(3, 4)** |
| Ẽ2 | E1 = (6, 5) | 1 | (6 + 3, 5 + 1) = **(9, 6)** |
| Ẽ3 | E2 = (4, 5) | 1 | (4 + 3, 5 + 1) = **(7, 6)** |

Check the votes: Ẽ1 decrypts to 4 − 4·3 = −8 ≡ 3 = 1·B, so vote 1. Ẽ2 gives 6 − 36 ≡ 3, vote 1. Ẽ3 gives 6 − 28 ≡ 0, vote 0. The output votes are **1, 1, 0**, the same multiset as the inputs (1, 0, 1), in a new order.

Ẽ1 = (3, 4) doesn't look like E3 = (10, 10), so an observer can't match rows by looking. The proof is what tells everyone the output really is a permuted, re-sealed copy of the input.

**Re-encryption is an encryption of zero.** The formula is `ReEnc(E; r̃) = E ⊕ Enc(0; r̃)`. Adding `(r̃B, r̃K)` leaves the plaintext alone. That is why the row's vote is preserved.

## The shuffle (§19.2)

A mixer *t* takes a list *E* of *N* rows. Each row has *w* ciphertexts, and the *w* ciphertexts of one ballot move together.

```
Ẽ_i[k] = ReEnc(E_{π(i)}[k]; r̃_{i,k})     for i = 1..N, k = 1..w
```

The permutation π is uniform. `shuffle` uses a Fisher-Yates shuffle, and draws each random index by **rejection sampling** on 64-bit integers. That avoids the small bias a plain modulo would introduce when the number of rows doesn't divide 2⁶⁴. The nonces are fresh random scalars.

The mixers are trustees, acting in ascending index order. Each mixes a given unit at most once, and at least `mix_policy.min_mixers` **distinct** trustees must mix it (§19.2). Each output becomes the next mixer's input, and a `mix_output` record carries the output, the input's digest and the proof, signed by the mixer.

### Why one honest mixer is enough

Each mixer draws its own permutation and nonces, at random, and then forgets them. The final order is the composition of all the permutations. To link an output row back to an input row, you need **every** mixer's permutation.

- `min_mixers` ≥ k (manifest rule 8, file 12).
- Fewer than k trustees are assumed corrupt.
- So among any `min_mixers` distinct mixers, at least one is honest.
- That honest mixer's permutation is secret, and it is discarded after use. The witness type wipes itself when dropped.

So the final list is unlinkable to the input, as long as one of those mixers is honest. The proof stops any mixer, honest or not, from changing the rows undetected.

The witness (`ShuffleWitness`) holds the permutation and the nonces. `Drop` zeroes them, and its `Debug` output hides them.

## The proof (§19.3, Terelius-Wikström)

The proof shows: there is a permutation π and nonces r̃ such that every output row is a re-encryption of an input row. It reveals neither π nor r̃.

### Generators

Each mix step has its own set of **generator points**, `H_0`, `H_1`, …, `H_N`. They are derived from a label `["shuffle", contest_index, region, step]` by hashing (`shuffle_gen`), so nobody knows the discrete log of any `H_i` relative to the base point *B*.

That matters. If the prover knew how `H_i` relates to *B*, it could fake the commitments. Deriving the points from a hash, with no secret behind them, removes that possibility.

Each step's label includes its contest, region and step number. So a proof for one step **cannot be replayed as a proof for another**: the bases differ, and the context (`ctx`) names the same things. The spec says "each mix step uses its own generators"; the consequence is that the proof is bound to its place in the chain.

### What the proof shows, one step at a time

The proof is a sequence of checks. Each one is a small equation the prover must satisfy, with a random challenge that the prover can't predict. Here is the intuition for each.

**1. Permutation commitment.** For each input position *j*, the prover makes a commitment `c_j = ρ_j·B + H_i`, where *i* is where row *j* goes in the output. Think of each `c_j` as a **sealed label** for one output slot: it carries exactly one of the `H_i` marks.

**2. Challenges.** Now the verifier's challenges `u_j` are derived from a hash of everything so far (the input, the output and the commitments). The prover can't choose them, because they depend on the commitments it already made. This is the Fiat-Shamir step (file 03).

**3. The "one 1 per row" check (T1).** A permutation matrix has exactly one 1 in each row and each column. The commitments encode that matrix. The sum of all commitments, minus the sum of all `H_i`, must be a multiple of *B* with a random blinding. In words: each output slot is claimed exactly once. This is the check Appendix B shows as `Σ c_j − Σ H_i = ρ̄·B`.

**4. The product check (T2 and the chain ĉ).** The prover commits to a chain of values `ĉ_i`, each built from the previous one and a weight `u'_i`. At the end, the chain must equal the product of all the `u_j`. A permutation of the `u_j` has the same product as the original list. A list that drops one row and duplicates another almost surely does not, because the challenges are random. This check catches duplication and loss.

**5. The weighted sum (T3).** The prover shows that the vector of weights `u'_i`, combined with the commitments, is consistent with the permutation commitments. In words: the weights in the output are the challenges of the rows they came from.

**6. The re-encryption check (T4).** For each component *k*, the **weighted** output must equal the **weighted** input, up to a re-encryption that sums to the nonces `r̃`:

```
Σ_i u'_i · Ẽ_i[k]  =  Σ_j u_j · E_j[k]  +  (Σ_i u'_i · r̃_{i,k}) · (B, K)
```

Because `u` is random, this combination is unlikely to balance unless the output really is a permuted, re-encrypted copy of the input. This is the Terelius-Wikström lemma: random weighted checks on the commitment matrix imply that it is a permutation matrix. Appendix B works the algebra out in full.

The prover's responses (`s1`, `s2`, `s3`, `s4`, `ŝ`, `s'`) are the blinded witnesses, `ω + c·witness`. The verifier recomputes the commitments from the responses and checks that the hash of everything gives the same challenge `c`.

### The verifier's arithmetic

The verifier never sees π or the nonces. It recomputes, from public values only:

- `c̄ = Σ c_j − Σ H_i`,
- `ĉ = ĉ_N − (∏ u_j)·H_0`,
- `c' = Σ u_j·c_j`, and the weighted sums `α'` and `β'` of the input,

then recomputes the six commitments T1 to T̂ from the responses and the challenge, and accepts iff the challenge recomputed from them equals the one in the proof. The verifier uses variable-time multi-scalar multiplication (`vmsm`) because it handles no secrets. The prover uses constant-time (`msm`).

## The code, function by function

| function | what it does | why |
|---|---|---|
| `list_to_value`, `list_from_value` | rows of `[point, point]` to CBOR and back; rejects an empty list, an empty row, or ragged rows | the list is the input and output of every step |
| `list_digest` | `Digest("eg/v1/mix-list", list)` | the `input_digest` in `mix_output`, so the next step names the list it takes |
| `ShuffleWitness` | the permutation and nonces; zeroed on drop; `Debug` hides them | the secret the mixer must discard |
| `uniform_index` | a uniform integer in 0..bound, by rejection sampling | no modulo bias |
| `shuffle` | the §19.2 step: Fisher-Yates permutation, fresh nonces, the re-encrypted list | the mixer's action |
| `ShuffleProof` (`to_value`, `from_value`) | the §19.3 `shuffle_proof` record; strict decode checks the vector lengths | the proof's wire form |
| `ShuffleStatement` | the public statement: context hash, contest, region, step, the key *K*, input and output | everything the proof is about, and nothing secret |
| `shuffle_gen` | `Gen(label, i)`: SHA-512 of CBOR(`["eg/v1/gen", context, label, i]`), mapped to a point | nothing-up-my-sleeve generators |
| `generators` | `H_0`..`H_N` for a statement | the bases of the commitments |
| `ctx_value` | `["shuffle", context, contest, region, step]` | binds the proof to its place |
| `u_challenges` | the challenges `u_j`, from a hash of the context, input, output, and `c_vec` | Fiat-Shamir: the challenges come after the commitments |
| `Commitments` | the six commitments T1, T2, T3, T4α, T4β, T̂ | the set hashed into the challenge |
| `challenge` | the challenge `c` from the context and all commitments | Fiat-Shamir for the proof as a whole |
| `chain_prev` | `ĉ_{i−1}`, with `ĉ_0 = H_0` | the commitment chain's start |
| `prove_shuffle` | the §19.3 prover, steps 1 to 7 | the mixer's proof |
| `verify_shuffle` | the §19.3 verifier: recomputes the commitments from the responses, then the challenge | anyone's check |
| `MixOutput` (`sign`, `from_signed`) | the signed `mix_output` record, with the mixer's signature | the mixer's signed step; `from_signed` decodes but does not verify the proof, which needs the statement |
| `kv` | a `(uint, value)` pair | record building |
| `has_shape` | a list has *N* rows of width *w* | rejects ragged or wrong-size inputs |
| `column` | one component of every row, from input or output, with its β or α side | the weighted sums need one column at a time |
| `msm`, `vmsm` | multi-scalar multiplication, constant-time and variable-time | the prover must not leak timing; the verifier needn't |
| `points_value`, `scalars_value`, `points_from`, `scalars_from`, `digest32`, `expect_version` | the codec helpers | strict decoding |

## Counting after decryption (§19.6)

The shuffle keeps the rows together, and only at the end is each row decrypted. Its counting rules are in the spec, and they are applied after decryption:

- empty slots (value 0) are not votes;
- an invalid slot value, or a filled slot repeated in one row, makes the whole row **invalid for this contest**;
- otherwise each filled slot adds one vote to its option (value − 1);
- in a multi contest, a row holding only null is a null vote, and a row with null and a candidate is invalid;
- in a link-group mix unit, each contest of the row is checked separately, and then a candidate that appears in two contests of the row invalidates every contest of that row (§7.5).

The verifier can't tell which machine a row came from, because the shuffle has removed that link. So a duplicate can be counted, but not pinned to a machine.

## Mix units and regions (§19.1)

A **mix unit** is a mixnet contest outside any link group, or a mixnet link group, together with a **region**. If the contest has the regional mixing flag, there is one unit per region, and otherwise one unit covering everything.

Regional mixing keeps each proof a manageable size. The spec's example: a single national shuffle of 150 million rows would make each proof about 19 GB. The region is also the anonymity set, so it is published.

The spec also merges small regions so each unit has at least `min_region_rows` rows: the smallest region is merged into its next neighbour in sorted order, wrapping around, with ties going to the earlier name. The merge is deterministic, so every verifier gets the same units. **That merge is not implemented in `eg-core` yet.** This file takes the rows of one unit as given.

The input rows are the cast ballots of the unit's region, in board order (`(board entry index, position in the package)`). A unit with zero rows is not mixed, and all its counts are zero (§19.1).

## Design choices

- **Terelius-Wikström, not a naive shuffle proof.** Its cost is linear in *N* and in *w*, and its soundness rests on the standard random-challenge argument. The spec follows Haenni et al.'s pseudo-code, written additively over Ristretto.
- **Rows move together.** A ballot's *w* slots are one row. Splitting a row would let a link group's slots drift apart, and the duplicate check would break.
- **Each step's proof is over the list it receives.** The `input_digest` of a `mix_output` names the list, and `list_digest` is the same function both sides use, so the chain is checkable step by step.
- **The witness is wiped, and the prover is constant-time.** The permutation is the secret that makes the mix unlinkable. It is zeroed on drop, and the prover uses constant-time arithmetic.
- **The verifier is not.** It handles only public data, so it uses the faster variable-time arithmetic. This is a deliberate split.
- **Fisher-Yates with rejection.** A uniform permutation needs uniform indices, and rejection sampling is the simple way to get them.

## Attacks each check prevents

| attack | what stops it |
|---|---|
| a mixer drops a row and duplicates another | the product check (the chain), and the weighted re-encryption check |
| a mixer changes a ciphertext's content | the re-encryption check: the weighted output would not match |
| a mixer swaps the two slots of one row | the rows are checked whole, so a swap changes the weighted sums |
| a proof replayed for another step, region or contest | the generators and the context both name the step, region and contest |
| a proof made under the wrong key | the verifier's β-side check uses *K*, the election key |
| a list that isn't *N* rows of width *w* | `has_shape` and the decoders reject it |
| a proof whose vectors have different lengths | strict decoding rejects it |
| a mixer that leaks its permutation | the proof says nothing about secrecy, and it doesn't need to: the step is still checked, and unlinking then rests on the other mixers, which is why `min_mixers` ≥ k matters |
| a single corrupt mixer unlinking rows | needs every mixer to be corrupt, which `min_mixers` ≥ k rules out |

## Tests (17)

- Shuffling keeps the rows and their multiset.
- A single-row shuffle is the identity permutation.
- Honest proofs verify.
- An identity witness with zero nonces still verifies (a boundary case).
- Tampering: an output ciphertext, a swap of components within a row, duplicating or dropping a row, and tampered proof scalars and points all fail.
- A wrong key fails; a wrong statement (contest, region or step) fails.
- A shape mismatch fails.
- Proof round trip; strict proof decoding.
- List round trip; ragged lists rejected; the list digest depends on content.
- A signed `mix_output` round trips, and tampering fails.
- `uniform_index` stays in range.

## Spec gaps relevant here

- **Spec issue 1 (generator label type):** §5.2 writes the label as text, but §19.3 uses the array `["shuffle", contest_index, region, step]`. The code hashes the CBOR of the array (`shuffle_gen`). The spec should allow any CBOR value.
- **Spec issue 2 (`c` in `u_j`):** the spec writes `c` in the hash for `u_j`, and the code uses the vector of permutation commitments `c_vec`. The spec should say so.
- **§19.1 region merge:** not implemented in `eg-core` yet (see above).
