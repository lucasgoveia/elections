# 09 · HPKE: sending secret shares

**Code:** `crates/eg-core/src/share_enc.rs`, plus `record_fields` in `cbor.rs`. **Spec:** §5.5, and `enc_share` in §8.2.

## The problem

In round 2 of the key ceremony, trustee 1 has to send trustee 3 a secret number (its share). The constraints:

- the only channel is **public** (the bulletin board, or files everyone sees);
- the two trustees have **never shared a password**;
- only trustee 3 may read the share, and nobody may change it unnoticed.

That's **public-key encryption**. Trustee 3 publishes a public key in the manifest; anyone can lock a message to it, and only trustee 3 can unlock it.

### Why not our ElGamal?

Our ElGamal locks **m·B**, and getting *m* back means trying 0, 1, 2… That works only because vote counts are small. A share is a random 252-bit number, and trying every value would take longer than the age of the universe. We need encryption that gives back arbitrary bytes, which is what HPKE does.

## How HPKE works (RFC 9180, base mode)

"Hybrid" means it combines two kinds of encryption:

**1. Key agreement (KEM: X25519).** The sender makes a throwaway key pair just for this message and combines it with the recipient's public key (Diffie-Hellman):

```
sender:    shared = e · PK_3        (e = throwaway secret; E = e·G is sent along as "enc")
trustee 3: shared = sk_3 · E        (the same value: e·sk_3·G both ways)
```

This is the same trick as ElGamal decryption (s·α = r·K). Both sides reach the same shared secret, and an eavesdropper with only E and PK_3 can't.

**2. Symmetric encryption (AEAD: ChaCha20-Poly1305).** HKDF (a hash-based key stretcher) turns the shared secret into a key, which encrypts the 32-byte share. Poly1305 adds a **tag**, a cryptographic checksum. If anyone flips one bit, decryption **refuses** instead of returning garbage.

The cipher suite is exactly what §5.5 specifies: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. We use the `hpke` crate, pinned at 0.12.0.

## The `info` string binds each share to its place

```
info = CBOR(["eg/v1/dkg-share", manifest_hash, sender, recipient])
```

`info` is mixed into the key derivation, so decryption only works with exactly the same info:

| attack | blocked by |
|---|---|
| reuse a share from **another election** | `manifest_hash` differs |
| claim the share came from a different trustee | `sender` differs |
| redirect a share meant for trustee 3 to trustee 4 | `recipient` differs |

The `aad` (additional authenticated data) is empty, as the spec requires.

## The code

| item | does |
|---|---|
| `hpke_keygen(rng)` | A trustee's receiving key pair. `HpkeSecretKey`'s `Debug` prints `HpkeSecretKey(..)`, so it never leaks into logs. |
| `HpkePublicKey::to_value` / `from_value` | 32 bytes. Also **rejects small-order X25519 points**: degenerate keys whose shared secret is always zero, which would make encryption fail and crash the program. The check multiplies by a multiple of 8, which collapses small-order points to zero. |
| `share_info(manifest_hash, sender, recipient)` | builds the `info` bytes |
| `encrypt_share(rng, pk, manifest_hash, i, j, share)` | seals the 32-byte share and returns an `EncShare`; the plaintext buffer is wiped |
| `decrypt_share(sk, manifest_hash, i, j, enc_share)` | returns the share, or `ShareDecryption` (wrong key, wrong info, tampering, or a recipient-index mismatch); then requires a **canonical scalar** (`InvalidScalar` otherwise); wipes buffers |
| `EncShare` | `{0:"enc_share", 1: j, 2: enc, 3: ciphertext}` |

### `record_fields` (in `cbor.rs`)

Spec §6.2 says unknown record keys **MUST be rejected**. Otherwise someone could add a field that some tools read and others ignore, and different verifiers would see different things. `record_fields(v, "enc_share", 4)` requires exactly keys 0..3 (none missing, none extra, none duplicated) and key 0 equal to the type name. Every record decoder uses it.

## Tests (18)

- round trip; the wrong recipient key fails;
- binding: a different manifest, a swapped sender or a different recipient fails;
- tampering: one flipped bit in the ciphertext or in `enc` fails;
- a non-canonical scalar inside a valid encryption is rejected;
- `info` matches hand-written bytes;
- encoding round trips; an extra key and a wrong type tag are rejected;
- `record_fields` rejection cases.

## Known gap

The `hpke` crate ships the official RFC 9180 known-answer tests, but they only run with features we don't enable. We should add our own known-answer test for this exact suite before release.
