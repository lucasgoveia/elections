# 05 · Zero-knowledge proofs: Schnorr and Chaum-Pedersen

**Code:** `crates/eg-core/src/proofs.rs` (`SchnorrProof`, `CpProof`, `prove_sum`, `verify_sum`, `prove_decryption_share`, `verify_decryption_share`). **Spec:** §11.1, §11.2, §11.4, §11.6.

## What a zero-knowledge proof is

A zero-knowledge proof convinces someone that a statement is true **without revealing the secret that makes it true**.

The classic analogy: you know the password to a door in the back of a circular cave. The verifier randomly shouts "come out the left!" or "come out the right!". If you know the password, you can always comply. If you don't, you get caught half the time. After 100 rounds the verifier is convinced, but **never heard the password**.

Every proof here has the same three steps:

1. **Commit:** fix something before seeing the challenge.
2. **Challenge:** an unpredictable number *c*.
3. **Response:** an answer that's only possible with the secret.

## Schnorr: "I know the secret key behind X" (§11.1)

Statement: I know *x* such that *X = x·B*.

```
1. Commit:    pick random u,  A = u·B
2. Challenge: c = HashToScalar("eg/v1/schnorr", ctx, X, A)      (Fiat-Shamir)
3. Response:  v = u + c·x
Proof sent:   (c, v)
```

**Verify:** compute `A' = v·B − c·X` and accept if `hash(ctx, X, A') == c`.

**Why an honest proof passes:** v·B − c·X = (u + c·x)·B − c·x·B = **u·B = A**.

**By hand on the 11-hour clock.** B = 3 and x = 4, so X = 12, which wraps to **1**.

- Commit: u = 5, so A = 15, which wraps to **4**.
- Challenge: suppose the hash gives c = 2.
- Response: v = 5 + 2·4 = 13, which wraps to **2**.
- Check: v·B − c·X = 2·3 − 2·1 = **4** = A ✓.

### The three properties

**1. Completeness.** Honest proofs pass; that's the substitution above.

**2. Soundness: you can't fake it without knowing *x*.** Suppose someone could answer **two different challenges** for the same *A*:

```
v₁ = u + c₁·x
v₂ = u + c₂·x
subtract:  v₁ − v₂ = (c₁ − c₂)·x   →   x = (v₁ − v₂) / (c₁ − c₂)
```

Anyone able to answer two challenges could compute *x*, so they already know it. Without *x*, the best a cheater can do is guess *c* in advance, and with *c* coming from a hash that's 1 chance in 2²⁵².

This is also **why *u* must be fresh and random every time.** If the same *u* were used for two proofs, those proofs would be exactly the pair above, and anyone could extract the secret key. Sony's PS3 signing key leaked exactly this way in 2010, through a reused ECDSA nonce. So the code draws *u* from `random_scalar` and **wipes it** (`u.zeroize()`) right after use.

**3. Zero knowledge: the proof reveals nothing about *x*.** *v = u + c·x* with *u* uniformly random, so *v* is uniformly random too, like a one-time pad over *x*. Even stronger: anyone can **produce a valid-looking transcript without knowing x** by working backwards. Pick *c* and *v* first, then set *A = v·B − c·X*. If fakes can be made from nothing, the real thing can't contain information. (This backwards trick is exactly what the 0-or-1 proof in file 06 uses.)

### What goes into the challenge, and why

- **A, the commitment.** The challenge must come *after* the commitment.
- **X, the statement.** This is the "strong" in *strong Fiat-Shamir*. Leaving the statement out ("weak Fiat-Shamir") lets an attacker pick the statement after making the proof. Helios, a real voting system, had this bug (Bernhard, Pereira and Warinschi, 2012).
- **ctx, the position**, for example `["sel", context_hash, ballot_id, contest, option]`. Without it, a valid proof could be **copied into another ballot or another election**. With it, a proof only verifies in its exact place.

**Compact form.** We send *(c, v)* instead of *(A, v)*. The verifier rebuilds *A* and compares the hash, so it's the same check with fewer bytes.

## Chaum-Pedersen: "the same secret is behind two points" (§11.2)

Statement: I know *x* with *X₁ = x·G₁* **and** *X₂ = x·G₂*.

This is Schnorr twice in lockstep, with **one u, one c and one v**:

```
Commit:    A₁ = u·G₁,  A₂ = u·G₂
Challenge: c = HashToScalar("eg/v1/cp", ctx, G₁, X₁, G₂, X₂, A₁, A₂)
Response:  v = u + c·x
Verify:    A₁' = v·G₁ − c·X₁,  A₂' = v·G₂ − c·X₂,  compare hash
```

A single *v* satisfies both equations only if both logs are the same *x*.

### Use 1: "these boxes add up to exactly L" (§11.4)

The 0-or-1 proof stops "5 votes in one box", but it doesn't stop "1 vote in **every** box". So we add the boxes and prove the sum encrypts exactly *L*. The sum is `(α, β) = (r·B, L·B + r·K)`, where *r* is the sum of the nonces:

```
α         = r·B
β − L·B   = r·K
```

That's Chaum-Pedersen with G₁ = B and G₂ = K. If the box held anything other than *L*, then *β − L·B* would equal r·K **plus** something extra, and no single *r* could fit both equations. The machine knows *r* (it chose every nonce), so it can make this proof without the election key.

### Use 2: "my decryption share is honest" (§11.6)

At tally time, trustee *j* publishes *M_j = z_j·α*. A corrupt trustee could publish garbage and change the result. So it proves:

```
Z_j = z_j·B     (my public key piece)
M_j = z_j·α     (my decryption share)
```

That's Chaum-Pedersen with G₁ = B and G₂ = α. A bad share fails, is discarded and reported (§20.3), and any *k* honest trustees still finish the tally.

## The code

| function | spec | notes |
|---|---|---|
| `SchnorrProof::prove(rng, ctx, x)` | §11.1 | **Computes X = x·B itself**, so no caller can prove a statement that doesn't match its witness. |
| `SchnorrProof::verify(ctx, X)` | §11.1 | Returns `bool`. |
| `CpProof::prove(rng, ctx, x, G₁, G₂)` / `verify(ctx, G₁, X₁, G₂, X₂)` | §11.2 | One private `cp_challenge` helper is shared by prove and verify, so the hash order can't drift between them. |
| `prove_sum(rng, ctx, K, r_sum)` / `verify_sum(proof, ctx, K, sum, L)` | §11.4 | The verifier uses X₂ = β_Σ − L·B. |
| `prove_decryption_share(rng, ctx, z_j, α)` / `verify_decryption_share(proof, ctx, Z_j, α, M_j)` | §11.6 | |
| `to_value` / `from_value` | | `[c, v]`: exactly 2 canonical scalars (private helper `two_scalars`). |

## Tests (10)

- **Schnorr:** an honest proof passes; it fails under a different ctx, a different X, or with c+1 or v+1; two proofs of the same statement differ but both pass; encoding round trip; malformed and non-canonical proofs rejected.
- **Chaum-Pedersen:** an honest proof passes; a different log fails; a different ctx fails.
- **Sum:** [0,1,0] passes with L = 1 and fails with L = 0 or 2; the cheating [1,1,0] fails with L = 1.
- **Decryption share:** an honest share passes; tampering with +B, using the wrong α, or the wrong trustee key all fail.
