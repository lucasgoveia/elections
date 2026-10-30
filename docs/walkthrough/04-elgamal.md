# 04 · Exponential ElGamal: the locked box

**Code:** `crates/eg-core/src/elgamal.rs`. **Spec:** §10 (encryption), §20.4 (discrete-log recovery).

## The idea, without math

To lock a vote in a box:

1. Pick a **fresh random secret** *r* (the nonce), used for this ballot only.
2. Use *r* to make a **mask** that only the election key can remove.
3. The box holds two things:
   - **α**, a "hint" about *r* that reveals nothing on its own;
   - **β**, the **vote plus the mask**.

Whoever has the secret key *s* can rebuild the mask from α and subtract it. Nobody else can.

## The formulas

Public key *K = s·B*. To encrypt vote *m* with nonce *r*:

```
α = r·B             ← the hint
β = m·B + r·K       ← vote + mask
```

To decrypt (only possible with *s*):

```
s·α = s·r·B = r·(s·B) = r·K      ← the mask, rebuilt
β − s·α = m·B                    ← mask removed, vote left
```

*s·α* and *r·K* are the same point (both equal *s·r·B*), but computing it needs either *s* or *r*. The voting machine knows *r*, the trustees together "know" *s*, and everyone else knows neither.

## Worked by hand on the 11-hour clock

B = 3 and the secret is s = 4, so K = 4·3 = 12, which wraps to **1**.

| | vote | nonce | α = r·B | β = m·B + r·K |
|---|---|---|---|---|
| ballot 1 | m = 1 | r = 2 | 6 | 3 + 2 = **5** |
| ballot 2 | m = 0 | r = 5 | 15, wraps to **4** | 0 + 5 = **5** |

Both ballots have β = 5, so **you can't tell yes from no**.

**Add the boxes** component by component, with no key needed: α = 6 + 4 = **10** and β = 5 + 5 = **10**.

**Decrypt the sum** with s = 4: β − s·α = 10 − 40 = −30, which wraps to **3** = 1·B. So the total is **1 vote** (1 + 0).

No individual ballot was ever opened. That's the **homomorphic tally**: add up all the boxes, then open only the total.

## Why "exponential" ElGamal

Classic ElGamal encrypts *m* directly. We encrypt ***m·B***, putting the vote "in the exponent", and that's what makes addition work: m₁·B + m₂·B = (m₁+m₂)·B.

The price is that decryption gives back *m·B*, not *m*. Recovering *m* means answering "which m gives this point?" (`dlog_bounded`). That's infeasible in general, but **vote counts are small** (a section has a few hundred voters), so we simply try 0, 1, 2, … until one matches.

## The code

| function | what it does | why |
|---|---|---|
| `Ciphertext::encrypt(m, r, K)` | `(r·B, m·B + r·K)` | Locks one vote. **Rejects r = 0** with `Error::ZeroNonce`, because then α = O and β = m·B shows the vote in the clear. |
| `+`, `+=`, `.sum()` | component-wise addition | The homomorphic tally: `ballots.sum()` is the encrypted total. |
| `Ciphertext::zero()` | (O, O) | The "empty box" a sum starts from, like 0 when adding numbers. |
| `scale(k)` | `(k·α, k·β)`, which encrypts k·m | Used in §12.3, where a null vote counts *L* times in the "exactly L" check. |
| `reencrypt(r', K)` | `(α + r'·B, β + r'·K)` | For the **mixnet**: the box is repainted, so it holds the same vote but can't be recognised, and shuffled ballots can't be traced back to voters. |
| `decrypt_to_point(s)` | `β − s·α` | **Tests only.** In production *s* never exists; decryption is done with threshold shares. |
| `dlog_bounded(T, max)` | tries m = 0..max until m·B = T | Turns m·B back into a count. Returns `None` if no m ≤ max matches, which catches a tampered total (§20.4). |
| `to_value` / `from_value` | CBOR `[α, β]`, 64 bytes | Wire format. Identity points are allowed, because sums can contain O. |
| `ballot_from_value` | like `from_value`, but **rejects α = O** | A ballot ciphertext with α = O means r = 0, so the vote is exposed or forged. |

**Cost of `dlog_bounded`:** a linear walk, one point addition per step. For 500 votes that takes microseconds, and even 100,000 takes milliseconds. If pooled tallies ever get very large, we can switch to baby-step giant-step (about √N steps); the spec allows either.

## What ElGamal does not do

A cheating machine could encrypt **m = 5** (five votes for one candidate) or **m = −1** (erasing a vote), and the box would look just as innocent. Encryption hides the vote, but it **doesn't prove the vote is legal**. The proofs (files 05 and 06) close that gap.

## Tests (11)

- encrypt/decrypt round trip for m = 0, 1, 7, 1000;
- r = 0 rejected;
- **tally:** votes [1,0,1,1,0,1] encrypted, summed and decrypted to 4, and `+`, `+=` and `sum` agree;
- scale: Enc(3) scaled by 5 decrypts to 15;
- re-encryption changes both α and β but keeps the same plaintext;
- the same vote with different nonces gives different ciphertexts;
- encoding round trips; malformed arrays rejected; α = O rejected for ballots;
- `dlog` bounds: 10·B with max 9 gives `None`, and with max 10 gives 10.
