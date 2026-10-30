# 11 · Ceremony records and the public ceremony verifier

**Code:** `crates/eg-core/src/ceremony.rs`. **Spec:** §7.1 (trustee_set), §8 (rounds, complaints, transcript), §9 (context).

File 10 covers *what* each trustee computes. This file covers *what they publish*, and how **anyone** can check afterwards that the ceremony was done correctly.

## The cast: `TrusteeSet` (from the manifest)

```
{0:"trustees", 1: n, 2: k, 3: [ {0:"trustee", 1: index, 2: organisation, 3: signing key, 4: HPKE key, 5: bloc}, … ]}
```

Each trustee has **two keys**: an Ed25519 key to sign its messages (file 08) and an HPKE key to receive shares (file 09). The decoder enforces 2 ≤ k ≤ n and indices exactly 1..n in order. `bloc` is the §2.4 label ("TSE", "party:13", "OAB", …), used later to check that no single bloc reaches *k* trustees.

## The messages

```
Round 1 (public)   each trustee i: commitments C_i,0..C_i,k-1 + Schnorr proofs        signed "eg/v1/sig/dkg1"
Round 2 (public)   each trustee i: n−1 HPKE-encrypted shares, sorted by recipient j   signed "eg/v1/sig/dkg2"
   ── each trustee j privately decrypts and checks its shares ──
   bad share?  Complaint (j accuses i)  →  i must publish a Reveal (the share in clear)
Round 3 (public)   each trustee j: "accept" + transcript_hash                          signed "eg/v1/sig/dkg3"
```

| element | without it… |
|---|---|
| a signature on every message | anyone could post "round 1 from trustee 3" and impersonate a trustee |
| `manifest_hash` in every message | messages from another election, or a test run, could be replayed |
| round-2 shares sorted by j, exactly n−1 | a trustee could "forget" to send someone a share, and that's caught publicly |
| complaint → reveal | see below |
| round 3 with `transcript_hash` | see below |

### Complaints: settling a dispute nobody else can see

Trustee 2 says "trustee 1 sent me a bad share". The share was encrypted for trustee 2, so nobody else can check it directly. So trustee 1 **must publish that share in plain** (a `Reveal`), and **everyone** checks it against trustee 1's public commitments:

- **valid:** trustee 1 was honest (or fixed it); trustee 2 uses the revealed share and the ceremony continues;
- **invalid, or no reveal:** trustee 1 is **disqualified**, and the signed records prove it.

Revealing one share is harmless: trustee 2 was meant to receive it anyway, and one share of one polynomial says nothing about *s*.

In v1, **any disqualification aborts the ceremony**. The EA publishes a new manifest and the ceremony restarts. It never quietly continues with a damaged set.

A trustee **can't complain about itself**. This check was added during review. A self-complaint has no meaning, and rejecting it removes an odd path through the verifier.

### The transcript hash: everyone saw the same ceremony

```
transcript_hash = Digest("eg/v1/dkg-transcript", manifest_hash, [all round 1], [all round 2])
```

A malicious board operator could show trustee 1 one version of round 1 and trustee 2 another (equivocation). In round 3, each trustee signs **the hash of everything it saw**. If all n match, they saw byte-identical rounds 1 and 2. If not, the verifier rejects the ceremony and names the trustee.

## The output: `Context` (§9)

```
context      = {0:"context", 1:1, 2: manifest_hash, 3: transcript_hash, 4: K, 5: [Z_1 … Z_n]}
context_hash = Digest("eg/v1/context", context)
```

K is the key every vote is encrypted under, and each Z_j lets anyone check trustee *j*'s decryption shares. `context_hash` goes into the `ctx` of every proof on every ballot, which binds every ballot to this election and this ceremony.

## The code

### Records

Each record type (`Round1`, `Round2`, `Round3`, `Complaint`, `Reveal`) has:

- `sign(&self, sk) -> Value`: builds the fields and calls `sign_record`;
- `from_signed(v, set) -> Result<Self, Error>`: strict decode through `record_fields`, version must be 1, the **author** (key 3) is looked up in the trustee set, and the signature is checked with that trustee's key.

Builders: `Round1::new(rng, manifest_hash, i, poly)` (commitments + proofs) and `Round2::new(rng, manifest_hash, i, poly, set)` (encrypts P_i(j) to every j ≠ i, sorted by j).

### Trustee side (private): `process_shares`

Trustee *j*, using its HPKE secret key, decrypts every share addressed to it and checks each against the sender's round-1 commitments. It returns either `ShareOutcome::Accept { z_j }` or `ShareOutcome::Complain { accused }`. A missing share or a decryption error counts as a bad sender. `Debug` never prints z_j.

### Public side: `verify_ceremony(manifest_hash, set, published)`

From public records only:

1. round 1: exactly one per trustee, signed, right election, valid commitments and proofs;
2. round 2: exactly one per trustee, signed, shares to every other trustee in order;
3. every complaint answered by a valid reveal (no self-complaints);
4. round 3: all n accept the **same** transcript hash;
5. K (rejected if O) and every Z_j; returns the `Context`.

Failures name the trustee, for example: `trustee 1 disqualified: invalid or missing reveal for complaint by 2`. This text goes into the public verifier report.

Other items: `transcript_hash(manifest_hash, round1, round2)`, `Context::{to_value, from_value, hash}`, `Published { round1, round2, round3, complaints, reveals }`.

## Tests (16)

- trustee set round trip; k = 1, k > n and out-of-order indices rejected;
- honest ceremonies (3,2) and (5,3) produce a valid context, and a vote encrypted under K decrypts with any 3 trustees;
- every record type round-trips;
- forged signature, wrong version, missing or duplicated round 1, and a missing share are rejected;
- a bad share leads to a complaint; a correct reveal resolves it; a wrong reveal or no reveal disqualifies the sender;
- one trustee with a different transcript is rejected.

## Known gaps

1. **DKG test vectors.** §27 requires vectors for (n, k) = (3, 2) and (5, 3).
2. **The complainer's share.** After a resolved complaint, trustee *j* must compute z_j using the **revealed** share. `process_shares` doesn't do that yet; a small helper is needed.
3. **HPKE known-answer test** (see file 09).
