# 08 · Signatures

**Code:** `crates/eg-core/src/sign.rs`. **Spec:** §5.4, and the signed-record convention in §8.1.

## What a signature gives us

1. **Who wrote it:** only the holder of the secret key could have produced it.
2. **Was it changed:** changing one bit of the message invalidates the signature.
3. **Non-repudiation:** the signer can't deny it later. If trustee 3 sends a bad share in the ceremony, its signed message is public proof of who misbehaved (§8.4). Two different pre-BUs signed by the same machine are evidence of fraud (§16).

## Ed25519 is a Schnorr proof

| | Schnorr proof (file 05) | Ed25519 signature |
|---|---|---|
| secret | x | signing key *a* |
| public | X = x·B | verifying key A = a·B |
| commit | A = u·B | R = r·B |
| challenge | c = hash(**ctx**, X, A) | c = hash(R, A, **message**) |
| response | v = u + c·x | s = r + c·a |

A signature is literally "a proof that I know the secret key, bound to this message".

One difference matters. Ed25519 doesn't take its nonce *r* from the RNG. It derives *r* by **hashing the secret key together with the message**. The same message always gives the same *r*, and different messages give unrelated ones, so PS3-style nonce reuse is impossible **by construction**, even with a broken RNG. We use the audited `ed25519-dalek` library.

## What we sign: `CBOR([tag, obj])`

```rust
sign(sk, "eg/v1/sig/dkg1", &record)  →  Ed25519( CBOR(["eg/v1/sig/dkg1", record]) )
```

The tag works like the hash tags in file 03. A signature made for one purpose **can't be reused for another**. For example, a signature on a ceremony message can't double as a "polls open" announcement with the same bytes. The code panics if a tag doesn't start with `eg/v1/sig/`, because tags are constants and a wrong one is our bug.

## Why "strict" verification

Ed25519 has edge cases where lenient libraries disagree:

- **non-canonical *s*:** the same signature written two ways (*s* and *s* + ℓ);
- **small-order public keys:** degenerate keys for which one signature verifies for many messages.

If our verifier accepted something a party's Python verifier rejected, the two would **disagree about whether an election record is valid**, which is the worst possible outcome for a verifiable election. `verify_strict` rejects all of these, and the spec requires it.

## The signed-record convention

Every signed object is a map whose **last field** is the signature over **all the other fields**:

```
dkg_round1 = { 0: "dkg_round1", 1: 1, 2: manifest_hash, 3: i, 4: [...], 5: [...], 6: <signature> }
                └──────────────────── what is signed ───────────────────────┘   └ field 6 ┘
```

- **`sign_record(sk, tag, fields, 6)`** signs the map of fields and appends the signature as key 6. It panics if any field key is ≥ 6, since the signature must be last.
- **`verify_record(pk, tag, record, 6)`** takes field 6 out, checks that 6 was the **largest** key (so `{…, 6: sig, 7: extra}` is rejected), and checks the signature against what's left.

Why insist on "last"? If fields could follow the signature, someone could **append unsigned data** to a signed record (say "7: trustee 3 approves") and it would still look signed. With the check, every byte of a valid record is either signed or the signature itself.

## The code

| function | does |
|---|---|
| `sign(sk, tag, obj)` | Ed25519 over `CBOR([tag, obj])` |
| `verify(pk, tag, obj, sig)` | `verify_strict`; returns `bool` |
| `verifying_key_to_value` / `verifying_key_from_value` | 32 bytes; `InvalidPublicKey` on bad input |
| `signature_to_value` / `signature_from_value` | 64 bytes; `InvalidSignature` on bad length |
| `sign_record` / `verify_record` | the last-field convention above |
| `SIG_TAG_PREFIX` | `"eg/v1/sig/"` |

## Tests (16)

- round trip; the wrong tag, wrong object or wrong key fail;
- **byte layout:** the signature verifies against hand-written CBOR (`82 6b "eg/v1/sig/t" 05`);
- **RFC 8032 test vector 1:** our keys and signatures match the standard bit for bit;
- a small-order key never verifies;
- 31-byte keys and 63-byte signatures are rejected;
- records: valid; a tampered field fails; a missing signature fails; an extra field after the signature fails; a misordered signature key or a bad tag panics.
