# 06 · The 0-or-1 proof (Cramer-Damgård-Schoenmakers)

**Code:** `crates/eg-core/src/proofs.rs` (`Disj01Proof`, private `disj01_challenge`). **Spec:** §11.3.

## The problem

Each candidate gets its own locked box holding 1 (chosen) or 0 (not chosen). A cheating machine could put **5** in a box (five votes for its favourite) or **−1** (erasing a vote), and the box would look just as innocent. We need the machine to prove **"this box holds 0 or 1"** without revealing which, or the vote would leak.

## 1. The key fact: true vs false statements

Take one plain Chaum-Pedersen statement. The prover commits, receives a challenge *c*, and answers.

- **If the statement is true** and you know the secret, you can answer **every** challenge: `v = u + c·r` works for any *c*.
- **If the statement is false**, then whatever you commit to, **exactly one challenge** can be answered and every other one is impossible (shown with numbers in section 5).

So a cheater's only hope is to **choose the challenge in advance**. Knowing *c* before committing lets them build commitments around it. That's the backwards faking from file 05:

```
pick c and v first  →  compute A = v·B − c·X  (the commitment that makes it work)
```

In a normal proof that's impossible, because *c* is a hash of the commitments and so comes **after** them.

## 2. The OR trick in one sentence

> We give the prover **one** challenge *c* from the hash and let it **split it into two pieces**, `c = c₀ + c₁`, one per statement. The prover may choose **one** piece freely (and fake that statement). The other piece is then **forced**, and that statement must be answered for real.

**Exam analogy.** An exam has two questions: Q0 ("the box holds 0") and Q1 ("the box holds 1"). You must answer both. Before the exam you may rig the grading key of **one** question so your prepared answer is "correct". The other question is graded with a key decided after you hand in, so you have to actually know the answer.

- An honest voter can really answer one question (the true one) and rigs the other.
- A cheater with a box holding 2 can answer neither, can only rig one, and fails.
- The grader sees two correct answers and **can't tell which was rigged**.

## 3. The two statements

The box is `(α, β) = (r·B, b·B + r·K)`.

| | statement | true when |
|---|---|---|
| **Q0** | `α = r·B` and `β = r·K` | the box holds 0 |
| **Q1** | `α = r·B` and `β − B = r·K` | the box holds 1 |

Both say "the same *r* is behind both points". They differ only in whether one *B* is peeled off β first.

## 4. Worked example: an honest "yes" vote (b = 1)

On the 11-hour clock: B = 3, and the election secret is s = 4, so K = 12, which wraps to **1**.

**Encrypt** b = 1 with r = 2: α = 2·3 = **6**, and β = 1·3 + 2·1 = **5**.

- Q0: is (6, 5) = r·(3, 1)? With r = 2 you get (6, 2), and 2 ≠ 5, so **false**.
- Q1: is (6, 5−3) = (6, 2) = r·(3, 1)? With r = 2, **true**.

**Prover, step A: fake Q0 by picking its challenge first.** Choose **c₀ = 7** and **v₀ = 5** at random, then work backwards:

- A₀ = v₀·B − c₀·α = 15 − 42 = −27, which wraps to **6**
- D₀ = v₀·K − c₀·β = 5 − 35 = −30, which wraps to **3**

**Prover, step B: commit honestly to Q1.** Pick random **u = 8**:

- A₁ = u·B = 24, which wraps to **2**
- D₁ = u·K = **8**

**Hash:** c = hash(ctx, α, β, A₀, D₀, A₁, D₁). In the toy, say it comes out as **c = 4**. The prover couldn't know this before step A, because the hash includes A₀ and D₀.

**Prover, step C: Q1's challenge is forced, so answer it for real.**

- c₁ = c − c₀ = 4 − 7 = −3, which wraps to **8** (no choice here)
- v₁ = u + c₁·r = 8 + 16 = 24, which wraps to **2** (this needs the real *r*)

**Published proof:** (c₀, c₁, v₀, v₁) = (7, 8, 5, 2).

**Verifier:** rebuild all four commitments from the proof.

| | formula | numbers | result | committed |
|---|---|---|---|---|
| A₀ | v₀·B − c₀·α | 15 − 42 | 6 | 6 ✓ |
| D₀ | v₀·K − c₀·β | 5 − 35 | 3 | 3 ✓ |
| A₁ | v₁·B − c₁·α | 6 − 48 | 2 | 2 ✓ |
| D₁ | v₁·K − c₁·(β−B) | 2 − 16 | 8 | 8 ✓ |

The commitments match, so the hash recomputes to 4. And c₀ + c₁ = 15, which wraps to **4** ✓. **Accepted.**

The verifier saw only (7, 8, 5, 2). Nothing in those numbers says "Q0 was faked". For a vote of 0, the prover would have faked Q1 instead and produced four equally random numbers.

## 5. Worked example: a cheater puts 2 in the box

Encrypt b = 2 with r = 2: α = **6**, and β = 2·3 + 2 = **8**.

- Q0: (6, 8) = r·(3, 1) needs r = 2 and r = 8, so **false**.
- Q1: (6, 8−3) = (6, 5) = r·(3, 1) needs r = 2 and r = 5, so **false**.

The cheater fakes one branch, say Q0, by picking c₀ in advance; that part always works. But Q1's challenge `c₁ = c − c₀` is **forced**, and Q1 is false.

**How many c₁ values can be answered for Q1?** Whatever A₁ and D₁ were committed, a response *v₁* must satisfy:

```
v₁·3 − c₁·6 = A₁      (from α)
v₁·1 − c₁·5 = D₁      (from β − B)
```

The first equation gives v₁ = A₁/3 + 2·c₁. Putting that into the second gives A₁/3 + 2·c₁ − 5·c₁ = D₁, so **3·c₁ = A₁/3 − D₁**.

That's one equation in c₁ with **exactly one solution**. The coefficients 2 and 5 differ **because** the statement is false (two different logs). For a true statement they'd be equal, c₁ would cancel out, and every challenge would work.

So the cheater wins only if the hash lands on that one value: 1 chance in 11 on the toy clock, and **1 in 2²⁵²** in the real group. Faking both branches instead means choosing c₀ and c₁ in advance and hoping `hash = c₀ + c₁`, which has the same odds.

## 6. Why the branches look identical

In any valid proof:

- the faked branch has *c* and *v* picked uniformly at random;
- the real branch has *c* = hash − (a random number), which is uniform, and *v* = u + c·r with *u* uniform and secret, which is also uniform.

All four numbers are independent and uniform, subject only to c₀ + c₁ = hash, **whichever branch is real**. Votes for 0 and for 1 produce proofs from **exactly the same distribution**.

## 7. The implementation detail that matters most: no `if` on the vote

The obvious prover is:

```rust
if b == 0 { fake branch 1, real branch 0 } else { fake branch 0, real branch 1 }
```

That's **a leak**. The two paths run different code, so they differ in timing, branch-predictor state and memory access. Someone measuring the machine (power draw, electromagnetic emissions, timing) could learn the vote. This is a **side channel**. The spec text doesn't mention it; it's an implementation requirement.

So `Disj01Proof::prove` **never branches on b**:

1. It always draws the same three random values in the same order: `u` for the real branch, and `c_sim`, `v_sim` for the fake one.
2. It computes **both** versions of everything: the real commitments (`real_a = u·B`, `real_d = u·K`) and the fake ones for each branch (`sim_a`, `sim_d_0`, `sim_d_1`).
3. It places them with `conditional_select(a, b, choice)` from the `subtle` crate. This picks *a* or *b* by bit masking, with no `if`, so it runs the same instructions in the same time either way.

```rust
let choice = Choice::from(b);     // 1 if voted yes
let a0 = RistrettoPoint::conditional_select(&real_a, &sim_a, choice);  // b=0 → real, b=1 → fake
let a1 = RistrettoPoint::conditional_select(&sim_a, &real_a, choice);  // the opposite
```

The cost is computing both branches every time. The benefit is that there's no secret-dependent control flow anywhere.

## The code, mapped to the steps

| step | code in `Disj01Proof::prove` |
|---|---|
| encrypt the box | `Ciphertext::encrypt(b, r, k)`: the prover encrypts the box itself and returns `(ciphertext, proof)`, so a caller can't prove one box and publish another |
| pick c, v for the fake branch | `c_sim`, `v_sim = random_scalar(rng)` |
| fake commitments, computed backwards | `sim_a = v_sim·B − c_sim·α`, `sim_d_0`, `sim_d_1` |
| honest commitment | `real_a = u·B`, `real_d = u·K` |
| put real and fake in the right slots | `conditional_select(..., choice)` |
| hash | `c = disj01_challenge(ctx, ct, a0, d0, a1, d1)` |
| forced challenge, real answer | `c_real = c − c_sim`, `v_real = u + c_real·r`, then `u.zeroize()` |
| assemble (c₀, c₁, v₀, v₁) | four more `conditional_select`s |

`verify(ctx, K, ct)` is the table from section 4: rebuild A₀, D₀, A₁, D₁, rehash, and compare with c₀ + c₁. `to_value` / `from_value` encode `[c0, c1, v0, v1]` as exactly four canonical scalars. `prove` panics if b > 1 (a programming error) and returns `Error::ZeroNonce` if r = 0.

## Tests (10)

- b = 0 and b = 1 both verify;
- a box holding 2 fails;
- a proof for one box doesn't verify for another box;
- a different ctx fails;
- changing any of the four numbers by +1 fails, and swapping the two branches fails;
- encoding round trip; malformed proofs rejected; r = 0 rejected; b = 2 panics;
- proofs for b = 0 and b = 1 have identical structure.
