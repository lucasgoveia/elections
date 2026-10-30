# 01 · Deterministic CBOR

**Code:** `crates/eg-core/src/cbor.rs`. **Spec:** §6.1 (deterministic CBOR), §6.2 (structures).

## What problem it solves

CBOR (RFC 8949) is a standard binary format, a bit like JSON but in bytes. It's compact, and it can carry raw byte strings directly, which matters because keys, points and signatures are bytes.

In eg/v1, CBOR is the byte format of the whole protocol. It isn't a feature of its own; it's the layer under everything else:

```
manifest, ballots, proofs, journal, pre-BU, board log ...   ← protocol objects
            │ serialized as
            ▼
      deterministic CBOR bytes                              ← cbor.rs
            │ fed into
            ▼
   SHA-256 / SHA-512 / Ed25519                               ← hash.rs, sign.rs
```

Every object in the spec is a CBOR map. For example, the election context (§9) is:

```
{0: "context", 1: 1, 2: manifest_hash, 3: transcript_hash, 4: K, 5: [Z_1..Z_n]}
```

CBOR gets used in three ways:

1. **Hashing.** `Digest(tag, x…) = SHA-256(CBOR([tag, x…]))`. Every Fiat-Shamir challenge in the proofs, the ballot tracking codes, the chain, `context_hash` and `manifest_hash` all hash CBOR bytes.
2. **Signing.** `Sign(sk, tag, obj) = Ed25519(CBOR([tag, obj]))`. This covers the zerésima, the pre-BU, packages, authorizations and observer certificates.
3. **Storage and transport.** The machine journal, export packages, the bulletin board and the WASM/FFI API all pass CBOR bytes around.

## Why "deterministic" matters

An independent verifier, written in Python or JavaScript by a political party, must recompute exactly the same hash from the same ballot. If one implementation wrote `{1:…, 0:…}` and another wrote `{0:…, 1:…}`, the hashes would differ and every proof would fail. Worse, an attacker could produce two encodings of "the same" ballot, with different hashes but the same meaning.

Deterministic CBOR leaves **exactly one valid byte sequence per value**. The encoder always produces it, and the decoder rejects every other encoding.

## The data model

The spec uses only five CBOR types, so the `Value` enum has exactly five variants:

```rust
Uint(u64), Bytes(Vec<u8>), Text(String), Array(Vec<Value>), Map(Vec<(Value, Value)>)
```

Negative integers, floats, tags and booleans can't be represented at all. If a type can't be constructed, it can't sneak into a hash.

### Byte strings are not text

"Byte string" is a misleading name. A CBOR **byte** string is a sequence of raw bytes, with no characters and no digits. A **text** string is something else:

| CBOR type | example | what's inside |
|---|---|---|
| text string | `"123"` | the characters `1`, `2`, `3` |
| byte string | `h'7b'` | one byte with value 123 |

We use byte strings for scalars and points because **they are too big for any integer type**. A scalar is a number up to ℓ ≈ 2²⁵² (about 76 decimal digits). The largest CPU integer, and the largest CBOR integer, is 2⁶⁴ (about 20 digits). So a scalar is stored the way every number is stored in memory: as bytes in base 256, here at a fixed size of 32 bytes.

```
scalar = b₀ + b₁·256 + b₂·256² + … + b₃₁·256³¹      (32 bytes, little-endian)
```

A point isn't a number at all. Internally it's a pair of curve coordinates, and Ristretto defines a unique 32-byte compressed form for it. The fixed 32-byte size also gives uniqueness (one encoding per value), matches the standards (RFC 9496, `curve25519-dalek`), and keeps every ciphertext and proof a constant size.

## How a CBOR item is laid out

Each item starts with a head byte. The top 3 bits are the **major type**, and the bottom 5 bits are the **info**:

- info 0–23: the value is the info itself;
- info 24, 25, 26 or 27: the value follows in 1, 2, 4 or 8 bytes.

For example, 5 is written as `0x05`, never as `0x18 0x05`.

## The code

| function | what it does |
|---|---|
| `encode(v)` / `encode_into(v, out)` | Writes the canonical bytes. Map entries are sorted by the bytes of their encoded keys (RFC 8949 §4.2.1). That's why the order is `10 < 100 < "z" < "aa"`: the type byte comes first, so all uints sort before all text. A duplicate key is a panic, because it's a bug in our code, not bad input. |
| `write_head` (private) | Always chooses the shortest form of a length or integer. |
| `decode(bytes)` | The strict decoder; rejection rules are listed below. |
| `Value::as_uint / as_bytes / as_text / as_array / as_map / get(key)` | Typed accessors. A wrong type gives `CborError::Schema`. |
| `record_fields(v, type_tag, n)` | Parses a spec record `{0: "type", 1: …, …}` strictly: keys must be exactly `0..n`, key 0 must equal the type name, and unknown keys are rejected (§6.2). Every record decoder goes through it. |

### What `decode` rejects, and why

- **Major types 1, 6 and 7** (negative integers, tags, floats and simple values), plus the reserved info values 28–30 and info 31 (indefinite length). We don't use these types, so accepting them would only create alternative encodings.
- **Non-shortest heads.** `0x18 0x05` fails with `NonCanonicalInt`, because 5 < 24 must use the one-byte form.
- **Lengths larger than the remaining input**, checked *before* allocating. Without this check, the 9 bytes `0x5b ff ff ff ff ff ff ff ff` would ask for an exabyte of memory. This is a denial-of-service guard.
- **Map keys out of order, or duplicated.** The decoder remembers the byte range of the previous key in the input. The earlier checks guarantee the input is canonical, so those raw bytes *are* the key's canonical encoding, and comparing them needs no re-encoding. Equal keys give `DuplicateKey`; a key smaller than the previous one gives `KeyOrder`.
- **Nesting deeper than 64**, which would otherwise overflow the stack on `[[[[…]]]]`.
- **Trailing bytes.** A byte string must decode to exactly one value.

The spec says implementations should "decode, re-encode and compare". This decoder enforces the same thing inline, which is equivalent and cheaper.

## Tests

There are 21 CBOR tests plus the `record_fields` tests:

- the RFC 8949 Appendix A examples, checked byte for byte;
- map sorting order;
- round trips;
- one rejection test per rule above (non-shortest integer, indefinite length, unsorted map, duplicate key, trailing byte, negative integer, tag, float, invalid UTF-8, truncated input, a huge length header, depth 65);
- `record_fields`: wrong tag, missing key, extra key, non-uint key, non-map.

Run with `cargo test -p eg-core cbor`.
