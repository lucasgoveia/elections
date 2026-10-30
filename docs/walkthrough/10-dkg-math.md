# 10 · DKG math: a key nobody knows

**Code:** `crates/eg-core/src/dkg.rs`. **Spec:** §8.1–§8.5.

## Where we are

Lagrange (file 02) says: if trustee *j* holds **P(j)** for a secret polynomial *P* with **P(0) = s**, then any *k* trustees can rebuild *s* (or use it without rebuilding it), and fewer than *k* learn nothing.

The open question is **who picks P**. Whoever picks it knows *s*, and becomes a single point of failure, exactly what §2.4 forbids.

## The trick: everyone picks a piece, and P is the sum

Each trustee *i* secretly picks **its own** polynomial *P_i*. The election polynomial is their sum:

```
P(x) = P₁(x) + P₂(x) + … + P_n(x)        so  s = P(0) = a₁,₀ + a₂,₀ + … + a_n,₀
```

Each trustee knows only its own *a_i,₀*. Knowing *s* would take **every** trustee's secret, so as long as one trustee is honest, nobody knows *s*.

Each trustee still needs its point P(j). Since P is a sum, so is P(j):

```
z_j = P(j) = P₁(j) + P₂(j) + … + P_n(j)
```

So trustee *i* computes **P_i(j)** for every other *j* and sends it, HPKE-encrypted (file 09). That's the share **p_{i→j}**. Trustee *j* adds up what it receives, plus its own P_j(j).

## Worked by hand: 11-hour clock, B = 3, three trustees, threshold 2

With k = 2, each polynomial is a line:

| trustee | secret polynomial | P_i(1) | P_i(2) | P_i(3) |
|---|---|---|---|---|
| 1 | 2 + 1x | 3 | 4 | 5 |
| 2 | 5 + 3x | 8 | 11, wraps to 0 | 14, wraps to 3 |
| 3 | 6 + 2x | 8 | 10 | 12, wraps to 1 |
| **sum** | **13 + 6x, wraps to 2 + 6x** | **z₁ = 19, wraps to 8** | **z₂ = 14, wraps to 3** | **z₃ = 9** |

- Each **column** is what one trustee receives. Trustee 2 gets 4 from trustee 1, 0 from itself and 10 from trustee 3, so z₂ = 3.
- The joint secret is **s = 2 + 5 + 6 = 13, which wraps to 2**. Trustee 1 knows only "2", trustee 2 only "5", and trustee 3 only "6". **Nobody has ever seen the number 2.**
- Lagrange check with {1,2}: λ₁ = 2 and λ₂ = −1, so 2·8 − 3 = 13, which wraps to **2** ✓.

The public key K = s·B can be computed **without s**, because points add the same way:

```
K = a₁,₀·B + a₂,₀·B + a₃,₀·B = C₁,₀ + C₂,₀ + C₃,₀
```

## Problem 1: a trustee sends a wrong share (Feldman commitments)

In round 1, each trustee publishes **every coefficient as a point**, C_i,t = a_i,t·B. This locks in the polynomial without revealing it. Anyone can then compute "P_i(j)·B" from the commitments alone:

```
P_i(j)·B = C₀ + j·C₁ + j²·C₂ + …
```

When trustee *j* receives share *p*, it checks **p·B == C₀ + j·C₁ + j²·C₂ + …**

Toy check: trustee 3 checks the share from trustee 1 (p = 5), with C₁,₀ = 6 and C₁,₁ = 3. The right side is 6 + 3·3 = 15, which wraps to 4. The left side is 5·3 = 15, which wraps to 4 ✓.

A wrong share fails this check, and trustee 3 complains publicly (file 11). The same commitments give each trustee's **verification key** for free: Z_j = z_j·B = Σ_i (C_i,₀ + j·C_i,₁ + …). That's the Z_j the decryption-share proof (file 05) checks against.

## Problem 2: the rogue-key attack (why each coefficient gets a Schnorr proof)

A dishonest trustee 3 could wait until it has seen C₁,₀ and C₂,₀, then publish:

```
C₃,₀ = X − C₁,₀ − C₂,₀       (X = x·B for some x it knows)
```

Then K = **X**, and **trustee 3 alone knows the election key**.

The catch is that trustee 3 **doesn't know the secret behind its own C₃,₀**, because it computed a point, not a scalar. So round 1 requires a **Schnorr proof of knowledge** for every coefficient, with ctx `["dkg-coef", manifest_hash, i, t]` so the proof can't be copied from another trustee, coefficient or election. A rogue C₃,₀ can't be proven.

Commitments equal to O are also rejected. A zero coefficient would make the polynomial lower-degree than promised, and could even make K = O.

**Key bias (spec note).** In Pedersen DKG a malicious trustee can slightly bias the *distribution* of K (Gennaro et al., 1999). That doesn't affect the security of ElGamal or threshold decryption, so v1 accepts it.

## The code

| function | does |
|---|---|
| `Polynomial::random(rng, k)` | k random **nonzero** coefficients (zeros are resampled). **Wiped on drop**, and `Debug` prints only `k`. |
| `Polynomial::from_coefficients` | explicit coefficients, for tests and vectors |
| `threshold()` | k |
| `eval(x)` | P(x) by Horner's rule: a₀ + x(a₁ + x(a₂ + …)) |
| `commitments()` | C_t = a_t·B |
| `prove_coefficients(rng, manifest_hash, i)` / `verify_coefficients(C, proofs, k, manifest_hash, i)` | anti-rogue-key proofs; the verifier also checks the length and that no C is O |
| `coefficient_ctx(manifest_hash, i, t)` | `["dkg-coef", manifest_hash, i, t]` |
| `eval_commitments(C, j)` / `verify_share(C, j, p)` | the Feldman check |
| `secret_share(own, j, received)` | z_j = P_j(j) + Σ received. **Panics if j = 0**: index 0 would combine the constant terms into s, which must never exist. |
| `joint_public_key(all)` | K = Σ C_i,₀; `None` if K = O or the input is empty |
| `verification_key(all, j)` | Z_j |

## Tests (9)

- Horner by hand: 3 + 5x + 7x² at x = 2 gives 41;
- shares match commitments; a wrong share or wrong index fails;
- coefficient proofs: the wrong trustee, wrong election, swapped proofs, a commitment equal to O, or the wrong length all fail;
- full simulated ceremonies (3,2) and (5,3): every Z_j = z_j·B, and K = s·B (the test cheats to know s);
- threshold decryption: subsets {1,2,3}, {1,4,5} and {2,3,5} decrypt a vote, and two trustees can't;
- a corrupted share is detected;
- `Debug` doesn't leak coefficients.
