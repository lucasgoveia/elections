# 02 · The group: points and scalars

**Code:** `crates/eg-core/src/group.rs`, `crates/eg-core/src/error.rs`. **Spec:** §5.1 (group), §5.2 (generators), §5.6 (randomness), §5.7 (Lagrange), §6.2 (encodings).

## Why the protocol needs a "group"

The goal is to put each vote in a locked box that:

- nobody can open alone;
- anyone can **add to other boxes without opening them**, so the sum of all votes ends up in one box;
- only the trustees, together, can open the final sum.

Adding locked values needs a special math object called a **group**. `group.rs` gives us that object, safely wrapped.

## A toy version you can compute by hand

Picture a clock with 11 hours (0 to 10). Adding wraps around: 8 + 5 = 13, which wraps to **2**.

- Pick a fixed starting element and call it **B** (the *generator*). Say B = 3.
- "x·B" means "add B to itself x times". So 4·B = 3+3+3+3 = 12, which wraps to **1**.

Two kinds of values show up:

| | toy | real protocol | used for |
|---|---|---|---|
| **scalar** | the count *x* | integer mod ℓ (ℓ ≈ 2²⁵²) | secrets, nonces, challenges, responses |
| **point** | the result *x·B* | a `RistrettoPoint` | public keys, ciphertexts, commitments |

In the toy you can easily go backwards: if you see 1, you can work out that x = 4. In the **real group**, going from *x·B* back to *x* is infeasible. That's the *discrete logarithm problem*, and the whole system rests on it:

- secret key *s* (a scalar), public key *K = s·B* (a point);
- publishing *K* reveals nothing usable about *s*.

The real group is **Ristretto255** (RFC 9496), built on Curve25519. Plain Curve25519 has a "cofactor" of 8, which creates small subgroups an attacker can use. Ristretto wraps it into a clean group of prime order ℓ: every encoding is a valid point, and each point has exactly one encoding. **We never implement curve arithmetic ourselves.** The audited `curve25519-dalek` library does it, as spec §5.1 requires.

## The code

### `B`

```rust
pub const B: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
```

The standard generator: the "3" of the toy. Every key and ciphertext is built from it.

### `point_to_value` / `point_from_value`

A point travels inside ballots and files as 32 bytes.

The problem is that **some 32-byte strings aren't points, and others are alternative spellings of a valid point** (think "7" vs "007"). If both spellings were accepted, the same ballot could be written two ways, and **its hash would change without its meaning changing**. That breaks tracking codes, signatures and the hash chain.

So `point_from_value` requires exactly 32 bytes and calls `decompress()`, which accepts **only the one canonical spelling**.

### `point_nonidentity_from_value`

Every group has a "zero", the identity *O*. In the toy that's 0 o'clock, and adding it changes nothing.

Encryption is `(α, β) = (r·B, vote·B + r·K)`. If someone used *r* = 0, then α = *O* and β = vote·B, so **the vote is exposed**. Wherever the spec marks a field "≠ O", it's decoded with this function, which returns `Error::IdentityPoint`.

### `scalar_to_value` / `scalar_from_value`

This is the same "one spelling" rule for scalars. Scalars wrap around at ℓ the way hours wrap at 11, so in the toy 4 and 15 are "the same" scalar. If both were accepted, one proof could be written two ways (malleability). Only values **below ℓ** are accepted: ℓ−1 passes and ℓ fails.

### `random_scalar`: 64 bytes, not 32

Nonces must be perfectly uniform. A toy example of the problem: you need a random number from 0 to 9, but you only have a 16-sided die (0–15). You roll and take the result mod 10. Rolls 0–9 give 0–9, and rolls 10–15 give 0–5, so **0–5 come up twice as often as 6–9**. That's biased.

32 random bytes reduced mod ℓ have the same problem, because 2²⁵⁶ isn't a multiple of ℓ. With **64 bytes** (a die with 2⁵¹² faces) the bias drops to about 2⁻²⁵⁰, which is effectively zero. Biased nonces have leaked real private keys in practice (known attacks on ECDSA).

### Where the randomness comes from: the OS RNG *is* a crypto RNG

"Crypto RNG" (CSPRNG) is a *property*: output nobody can predict, even after seeing earlier outputs. The **OS RNG** is a *source* that has this property: `getrandom()` on Linux, `/dev/urandom`, `BCryptGenRandom` on Windows. The kernel runs a CSPRNG (ChaCha20 on Linux) that it keeps reseeding from hardware entropy.

Why use the OS RNG rather than our own in-process CSPRNG? An in-process one (like `ChaCha20Rng`) is just as strong mathematically, but it has to be **seeded from the OS anyway**, and it adds failure modes:

- **fork or VM snapshot:** a cloned process, or a voting machine restored from a snapshot, keeps the same RNG state, so two ballots get the **same nonce** and the votes leak;
- **bad seeding** (from the clock or a counter) is a classic bug;
- it's more code to audit.

So spec §5.6 requires `getrandom` in production.

In the code, the signature is `random_scalar<R: RngCore + CryptoRng>(rng: &mut R)`. `CryptoRng` is a marker trait, so a weak generator **won't compile** here. Production passes `OsRng`. Tests pass `ChaCha20Rng::from_seed(...)`, which is a crypto RNG with a fixed seed, so results are reproducible.

**Known gap:** nothing yet stops production code from passing a seeded generator. The spec says production builds MUST NOT expose one. This will be enforced in the ballot API: public functions will use `OsRng` internally, and the seeded path will sit behind a test-vector feature flag.

### `gen(context_hash, label, i)`: generators nobody controls

Some proofs (the mixnet shuffle, §19.3) need extra generators besides B, say H. **Nobody may know h with H = h·B.**

Here's why. Take a commitment `C = m·B + r·H` that says "I commit to m". If I secretly knew H = h·B, then C = (m + r·h)·B, and I could later claim C hides a different m' by picking a matching r'. The commitment would bind me to nothing.

So we don't *pick* H. We hash a text and map the result to a point:

```
H = FromUniformBytes( SHA-512( CBOR(["eg/v1/gen", context_hash, label, i]) ) )
```

A hash output is unpredictable, so nobody (us included) can steer it to a point whose log they know. This is called "nothing up my sleeve". Including `context_hash` gives each election its own generators.

### `lagrange(set, j)`: k-of-n trustees

The election secret *s* **never exists in one place**. With 5 trustees and threshold 3:

- there's a secret polynomial *f* with *f(0) = s*;
- trustee *j* holds only *f(j)*;
- any 3 trustees can rebuild *f(0)*, and any 2 learn nothing.

Toy example on the 11-hour clock with threshold 2. Take *f(x) = 7 + 3x*, so the secret is *s* = 7:

- trustee 1 holds f(1) = 10;
- trustee 2 holds f(2) = 13, which wraps to **2**;
- trustee 3 holds f(3) = 16, which wraps to **5**.

The Lagrange coefficients are λⱼ = ∏ m/(m − j), over the other members m of the subset:

- **Trustees {1,2}:** λ₁ = 2/(2−1) = 2 and λ₂ = 1/(1−2) = −1. Then 2·10 − 1·2 = 18, which wraps to **7** ✓.
- **Trustees {2,3}:** λ₂ = 3/(3−2) = 3 and λ₃ = 2/(2−3) = −2. Then 3·2 − 2·5 = −4, which wraps to **7** ✓.

In the protocol this happens "inside points": each trustee publishes *f(j)·α*, and the weighted sum gives *s·α*, which is enough to decrypt **without ever computing s**.

The function rejects these inputs with `Error::InvalidIndexSet`:

- an empty set;
- index 0, because f(0) is the secret itself;
- repeated indices, because m − j = 0 has no inverse;
- a *j* that isn't in the set.

### `error.rs`

This is the crate's shared `Error` enum. It covers `Cbor`, `InvalidPoint`, `InvalidScalar`, `IdentityPoint`, `InvalidIndexSet`, plus later additions: `ZeroNonce`, `InvalidPublicKey`, `InvalidSignature`, `ShareDecryption` and `Ceremony`.

## Tests (10)

- point and scalar round trips;
- identity accepted by `point_from_value` and rejected by `point_nonidentity_from_value`;
- rejections: 31 and 33 bytes, `0xff…`, a "negative" field element, ℓ itself (with ℓ−1 accepted);
- random draws are nonzero and differ;
- `gen` is deterministic and changes when any input changes;
- Lagrange: a random degree-2 polynomial, shared at x = 1..5 and rebuilt from three different 3-subsets, both on scalars and in the exponent; plus the error cases.
