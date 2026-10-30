# 03 · Hashes: fingerprints and challenges

**Code:** `crates/eg-core/src/hash.rs`. **Spec:** §5.3, Appendix A (tags).

## What a hash is

A hash function (SHA-256, SHA-512) takes any amount of data and returns a fixed-size fingerprint:

- the same input always gives the same output;
- change one bit of the input, and the output looks completely different;
- you can't work backwards from an output, and you can't find two inputs with the same output.

## The two functions

| function | output | used for |
|---|---|---|
| `digest(tag, items)` | 32 bytes (SHA-256) | **identifiers**: `manifest_hash`, `context_hash`, tracking codes, the pre-BU fingerprint |
| `hash_to_scalar(tag, items)` | a scalar (SHA-512 mod ℓ) | **numbers for curve math**, mainly proof challenges |

If anyone changes one character of the manifest, `manifest_hash` changes, and every signature and proof made over the old hash stops verifying.

### `hash_to_scalar` and Fiat-Shamir

An interactive zero-knowledge proof is a conversation:

1. Prover: "here is my commitment A."
2. Verifier: "here is a random challenge *c*."
3. Prover: "here is my answer *v*."

The prover can't cheat because they **don't know *c* before committing to A**. But a voting machine can't hold a conversation with every future verifier. **Fiat-Shamir** replaces the verifier with `c = hash_to_scalar(everything said so far)`. The hash is unpredictable, so it acts like a random challenge, and anyone can recompute it later. This is the most important use of this module.

It uses SHA-512 for the same reason `random_scalar` uses 64 bytes: reducing 32 bytes mod ℓ is biased, and 64 bytes makes the bias negligible.

## Detail 1: the tag (domain separation)

Every hash starts with a label such as `"eg/v1/schnorr"`, `"eg/v1/ballot"` or `"eg/v1/context"`:

```
digest("eg/v1/ballot", [x])    ≠    digest("eg/v1/code", [x])
```

Without tags, a hash computed for one purpose could be **reused for another**. For example, a proof challenge could equal a valid tracking code, or a signature on a slip could be passed off as one on a pre-BU. With tags, each purpose lives in its own separate world. The full list is in spec Appendix A.

`transcript` (private) `assert!`s that every tag starts with `eg/v1/`. Tags are constants in our own code, so a wrong tag is our bug, and the program stops immediately instead of hashing into a foreign domain. The `v1` also keeps a future v2 from ever colliding with v1 hashes.

## Detail 2: why hash CBOR rather than glued bytes

The naive approach is `SHA-256(tag + x1 + x2)`:

```
x1 = "ab",  x2 = "c"   →   "abc"
x1 = "a",   x2 = "bc"  →   "abc"     same hash, different data!
```

CBOR writes **each item's length in front of it**, so these become different byte strings: `[2:"ab", 1:"c"]` vs `[1:"a", 2:"bc"]`. That's why every hash input is `CBOR([tag, x1, …, xn])`, and why CBOR has to be deterministic: everyone must produce exactly the same bytes.

## The code

```rust
fn transcript(tag, items) -> Vec<u8> {
    assert!(tag.starts_with("eg/v1/"));
    CBOR([tag, items...])           // build the array, encode deterministically
}
digest         = SHA-256(transcript)
hash_to_scalar = SHA-512(transcript) mod ℓ   // Scalar::from_bytes_mod_order_wide
```

`TAG_PREFIX` is the public constant `"eg/v1/"`.

## Tests (7)

- **Hand-written bytes.** The test writes the expected CBOR byte by byte (`83 6a "eg/v1/test" 01 58 20 abab…`) without using our encoder, and checks both functions against it. This shows the code follows the spec, not just that it agrees with itself.
- **Domain separation:** the same items under different tags give different results.
- **Boundaries:** `["ab","c"]` and `["a","bc"]` hash differently.
- **Bad tag:** a tag without `eg/v1/` panics.
- **Determinism** with point and scalar items.
