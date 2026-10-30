# 07 · Test vectors

**Code:** `crates/eg-core/tests/vectors.rs`. **Data:** `test-vectors/m1/*.cbor` and `*.json`. **Spec:** §27.

## What they're for

Our tests passing only shows that our code **agrees with itself**. The independence requirement (§2.4) says parties, universities or anyone else must be able to write **their own verifier**, in any language, without trusting ours. How can they know they match the protocol exactly? They compare against fixed answers:

> "With these exact inputs, the proof must be exactly these bytes."

If a Python implementation reproduces all the files, it's compatible. If one byte differs, something is wrong (theirs, ours, or an ambiguity in the spec), and we find out before an election rather than during one.

## The randomness problem

Proofs use random values (*u*, nonces). Real randomness makes every run different, so we fix it:

1. Each vector has a **seed**: `SHA-256("eg/v1/test-vector/" + name)`.
2. The seed feeds **ChaCha20**, a standard cipher that turns a seed into an endless stream of random-looking bytes. The same seed gives the same stream in every language.
3. Each `Random()` takes the next 64 bytes from the stream.
4. The file records the **order of the draws** (for example `"draws": "x, u (inside prove)"`), so other implementations consume the stream in the same order.

The test `chacha20_matches_rfc_keystream` checks that our ChaCha20 (from `rand_chacha`) produces the **standard keystream** (`76b8e0ad…` for a zero key), so a Python or JS ChaCha20 gives identical draws.

This seeded generator lives **only in tests**, never in production.

## Example: `schnorr.json`

```
seed          ded5ea34…                     ← source of all randomness
draws         "x, u (inside prove)"         ← 1st draw = secret x, 2nd = nonce u
inputs        x, ctx, context_hash
intermediates X = x·B, A = u·B, c
outputs       proof = [c, v]
```

The intermediates are there for **debugging another implementation**. If X differs, their point encoding is wrong. If A matches but c differs, their CBOR or hash input is wrong. If c matches but v differs, their scalar arithmetic is wrong.

Provers don't return their commitments, so the generator recomputes them exactly as a verifier would (for Schnorr, A = v·B − c·X).

## The nine vectors

| file | checks |
|---|---|
| `hash` | the exact CBOR transcript bytes plus both hash functions |
| `gen` | three "nothing up my sleeve" generators |
| `elgamal` | votes [0,1,1,0,1] encrypted, summed, decrypted to 3, plus a re-encryption |
| `schnorr` | proof of knowledge |
| `chaum-pedersen` | same log for two bases |
| `disj01-0`, `disj01-1` | the 0-or-1 proof for each bit, with A₀ D₀ A₁ D₁ |
| `sum` | bits [0,1,0,1] proven to sum to exactly 2 (and not 1) |
| `decryption` | 2-of-3 trustees: three shares with proofs, combined with Lagrange from {1,2} **and** {2,3}, giving the same result (vote = 1) |

In the `decryption` vector, a "dealer" picks the polynomial. That's a shortcut; the real key ceremony (files 10 and 11) has no dealer.

## How the test protects us

| function | role |
|---|---|
| `build_all()` | Builds every vector in memory. |
| `vectors_match_files()` | By default, compares each built vector **byte for byte** with the committed `.cbor` file and its `.json` rendering. Any change in output, even a "harmless" one, fails the test, because it's a protocol change and must be deliberate. With `EG_WRITE_VECTORS=1` it rewrites the files instead, so an intentional change shows up as a visible git diff. |
| `vector_files_are_canonical()` | Every `.cbor` file decodes and re-encodes to the same bytes. |
| `chacha20_matches_rfc_keystream()` | Interoperability of the random stream. |

The JSON key order looks odd ("outputs" before "intermediates"). That's because it follows the CBOR canonical order, where shorter keys sort first.

On a fresh checkout with no files, `vector_files_are_canonical` can race with the write step. Once the files are committed this can't happen.

## Still to do

The spec also asks for DKG vectors with (n, k) = (3, 2) and (5, 3); see file 11.
