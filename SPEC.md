# eg/v1: End-to-End Verifiable Election Protocol

Status: **Draft 0.4**, 2026-10-28. Not yet implemented. Every section is normative unless it is marked *informative*.

This document specifies the protocol, data formats and algorithms of the `eg` election library. It is detailed enough for an independent party to write a compatible verifier without reading the library's source code. Where the code and this document disagree, the disagreement is a bug, and this document wins until it is amended.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119.

---

## Table of contents

1. Scope and goals
2. Threat model and trust assumptions
3. Roles
4. Election lifecycle
5. Notation and primitives
6. Encoding
7. Election manifest and machine registry
8. Key ceremony (distributed key generation)
9. Election context
10. Encryption
11. Zero-knowledge proofs
12. Ballots
13. Tracking codes, slips and the per-machine chain
14. Benaloh audit-or-cast
15. Machine journal and zerésima
16. Export package and boletim de urna
17. Bulletin board log
18. Homomorphic tally
19. Mixnet tally
20. Threshold decryption
21. Results
22. Apportionment
23. Verification procedure
24. Software verifiability
25. Keystore interface (informative)
26. Adapter API (informative)
27. Test vectors
28. Security considerations
29. Open issues

---

## 1. Scope and goals

### 1.1 Goals

The protocol provides:

- **Ballot secrecy.** No coalition of fewer than *k* trustees, no board operator and no verifier can learn how an individual voter voted. The voting machine necessarily sees each plaintext while the voter is choosing. Secrecy against a *malicious* machine therefore rests on software verifiability (§24), attestation and physical controls, not on cryptography (§28.7, §28.8).
- **Receipt-freeness.** A voter cannot obtain anything that proves to a third party how they voted.
- **Cast-as-intended verifiability.** Voters and observers can check, statistically, that machines encrypt the voter's actual choices (Benaloh challenge, §14).
- **Recorded-as-cast verifiability.** A voter can check that their encrypted ballot is on the public board, unaltered (§13, §17).
- **Counted-as-recorded verifiability.** Anyone can check that the published result is the correct tally of exactly the valid cast ballots on the board (§18–§23).
- **Eligibility consistency.** Every cast ballot consumes an authorization signed by a poll worker of its section, and the cast count of each section is at most the number of voters the poll workers attest signed the voter roll (§15, §16.2).
- **Completeness.** Every registered section opens with a signed zerésima and closes with a signed pre-BU (the encrypted boletim de urna) handed to observers before transmission, so a missing, swapped or pre-loaded package is detectable (§15.5, §16.2, §17.7).
- **Verifiable section results.** Each section's result (the final BU) is opened by the trustees from the encrypted totals fixed on the paper pre-BU, and carries proofs that tie the numbers to that paper. No plaintext count exists on any machine. Groups too small to publish safely are pooled (§16.5, §18).
- **Software accountability.** Each machine package names the measured software it ran, and only approved, reproducibly built releases are accepted (§24).

### 1.2 Non-goals for v1

- Ranked-choice ballots and write-ins.
- Remote (internet) voting and anonymous voter credentials.
- Everlasting privacy (privacy against a future break of the discrete logarithm problem).
- Post-quantum security.
- Coercion resistance beyond a private voting booth.
- Network transport between trustees. Ceremonies exchange signed files (§8).

### 1.3 Supported contest kinds

| Kind | Voter selects | Counting methods |
|---|---|---|
| `single` | exactly one option (candidate, blank or null) | homomorphic or mixnet |
| `multi` | between 0 and *L* candidate options, or null | homomorphic or mixnet |
| `proportional` | exactly one option (candidate, party, blank or null) | homomorphic or mixnet |

The counting method is chosen per contest in the manifest (§7).

---

## 2. Threat model and trust assumptions

### 2.1 Adversaries

| Adversary | Controls | Must not be able to |
|---|---|---|
| Malicious voting machine | Its own software, its encryption randomness and its display | Change a vote without risking detection on audit; drop or insert ballots without detection; produce a ballot holding more than one vote per option; print a pre-BU that doesn't match its encrypted ballots without detection |
| Corrupt election authority (EA) | Manifest, machine registry, board server | Change the tally; add a machine or section after polls open; drop or swap a package undetected while observers hold its pre-BU; show different boards to different people without detection |
| Corrupt poll terminal or poll worker | Authorization signing for one section | Authorize more votes than the voters who signed the roll without the mismatch being visible on the paper pre-BU and to observers. The poll worker signatures alone prove little, because one compromised terminal holds them. Independent evidence comes from personal tokens (§25), observer devices and the paper copies (§28.16–§28.18). |
| Corrupt trustees, fewer than *k* | Their own key shares | Decrypt any individual ballot or bias the published result |
| Corrupt trustees, *k* or more | Enough shares to decrypt | Change the tally undetected. **Secrecy is lost in this case.** |
| Corrupt mixers, all but one | Their own shuffles | Link an input ballot to its output |
| Coercer or vote buyer | Can demand anything the voter can take out of the booth | Learn the voter's cast vote |
| Network attacker | Everything between machines, board and mirrors | Change any record undetected |

### 2.2 Assumptions

- The decisional Diffie-Hellman (DDH) problem is hard in the Ristretto255 group, which gives secrecy.
- The discrete logarithm problem is hard in the Ristretto255 group, which gives proof soundness and unforgeability.
- SHA-256 and SHA-512 are collision-resistant and behave as random oracles for Fiat-Shamir.
- Ed25519 is existentially unforgeable.
- At least one mixer per mixnet contest is honest (for mixnet secrecy).
- The voting machine erases each cast ballot's nonce seed (§14). This is required for receipt-freeness and secrecy against later compromise of the machine.
- The voter votes in a private booth and cannot be observed choosing CAST or SPOIL.
- At least one mirror is honest and compares signed tree heads with the board (§17).
- At each section, at least one poll worker or observer is honest: they check the zerésima before voting starts, check the voter-roll count on the pre-BU, and keep or publish a pre-BU copy (§15.5, §16.2).

### 2.3 What integrity does not depend on

The correctness of the published tally does not depend on any trustee, machine, EA, board operator or software being honest. It depends only on the assumptions in §2.2, on enough voters and observers performing audits (§14) and checking codes (§13), and on section observers checking the zerésima and the pre-BU (§15.5, §16.2). Without those observer checks, a corrupt EA could still register phantom sections or drop packages, and the only remaining evidence would be voters' slips.

### 2.4 Independence from the election authority

Many voters don't trust the election authority (in Brazil, the TSE). The protocol is designed so that **no result has to be accepted on the EA's word**.

**Integrity needs no trust in the EA.** Every check a voter, observer or verifier performs uses only public data, maths and their own tools:
- a voter checks their code on the board, through a mirror the EA doesn't run, and can audit a ballot (§13, §14),
- an observer holds the zerésima and the pre-BU on paper, and checks the final BU against them (§15.5, §16.2, §16.5),
- anyone runs a verifier written from this spec, not the EA's code (§23).

No EA key, server or software takes part in any of these checks. The EA's signature on the result is a convenience that verifiers ignore (§21).

**Where the EA still has power, it MUST share it.** The protocol enforces this where code can enforce it:

1. **Decryption key.** Every trustee carries a **bloc** label in the manifest (§7.1), such as `"TSE"`, `"party:13"`, `"OAB"` or `"university"`. No bloc may hold *k* or more shares (§7.2 rule 11). The EA and its allies therefore can't open any ballot without trustees from other blocs.
2. **Software approval.** Every release signer carries a bloc label. No bloc, and in particular not the EA's own bloc, may hold *k_r* or more signer keys (§7.2 rule 12). A release becomes approved only when people outside the EA have rebuilt it and signed it.
3. **Board.** The manifest lists at least two mirrors run outside the EA's bloc (§7.2 rule 13). Voter and observer apps MUST confirm the board's tree head with at least one of them (§17.5). A board that hid or altered entries would be caught by a mirror the EA doesn't control.
4. **Election-night decryption.** Each trustee runs its decryption service on its own infrastructure, never on infrastructure the EA hosts (§20.5).
5. **Verification apps.** The voter check, the observer app and the full verifier SHOULD be built and published by parties, universities or civil society from this spec and its test vectors (§27). A voter should never need an EA app to check the EA.

**Labels are claims, so they are public.** The EA writes the bloc labels, so it could mislabel an ally. Each label is therefore published next to the organisation's name and key fingerprint in the verifier report (§23 step 16), where anyone can challenge it. The organisations confirm their own keys through their own channels (§8).

**What can't be removed.** The voting machine sees each vote while the voter is choosing, and the EA has custody of the machines. This is true of any in-person electronic voting. It affects **secrecy, never the count**: a machine that cheats on the count is caught by audits and proofs. The remaining defences are:
- software anyone can rebuild, signed by people outside the EA (§24),
- hardware attestation (§24.5),
- **forensic sampling**: after the election, parties choose machines at random, with a public random draw, and inspect them against their attested software and their journals. This procedure is informative and is decided by electoral rules outside this protocol.

**The verifier states what rests on the EA's word.** Its independence report (§23 step 16) lists:
- sections whose zerésima and pre-BU carry no observer signature,
- trustees and release signers by bloc,
- mirrors by operator,
- any recommended independent party that didn't take part.

---

## 3. Roles

| Role | Identity key | Responsibilities |
|---|---|---|
| **Election authority (EA)** | Ed25519 | Publishes the manifest and the machine registry, and operates the board. |
| **Trustee** *i*, 1 ≤ *i* ≤ *n* | Ed25519 signing key and X25519 HPKE key | Takes part in the key ceremony, mixes, and decrypts tallies. |
| **Voting machine** | Ed25519 key, registered in the registry | Encrypts ballots, runs the Benaloh flow, keeps the journal, and exports a signed package. |
| **Poll terminal** (host application) | Ed25519 key of the poll worker (mesário) operating it, registered per section | Authorizes one vote at a time with a signed authorization, enters the voter-roll count, and signs the zerésima and pre-BU. Voter identity checks are outside the library. It MUST NOT send voter identity to the machine. |
| **Poll worker** (mesário) | Ed25519 on a personal token, registered per section | Runs the section, checks and signs the zerésima and the pre-BU. |
| **Party** | optional Ed25519 party key in the manifest | Certifies its own observers (§16.3), so the EA can't choose who observes for it. |
| **Observer** (fiscal) | Ed25519, certified by a party (§16.3) or registered by the EA for non-party observers | Checks and countersigns the zerésima and the pre-BU (usually by scanning their QR code), keeps paper copies, and publishes signed copies to the board or a mirror. |
| **Bulletin board** | Ed25519 board key | Keeps the append-only Merkle log and signs tree heads. |
| **Mirror** | Ed25519 key, listed in the manifest | Copies the board, checks consistency, and gossips tree heads. At least two are run outside the EA's bloc (§2.4). |
| **Verifier** | none | Runs §23 on a board dump. |
| **Release signer** | Ed25519 | Signs reproducible release records (§24). |
| **Voter** | none | Votes, optionally audits, and optionally checks their code. |

---

## 4. Election lifecycle

1. **Setup.** The EA publishes the manifest (§7) to the board, signed. Trustee identity keys are listed in the manifest.
2. **Key ceremony.** The trustees run the distributed key generation (§8). The transcript goes to the board. The election context (§9) is fixed.
3. **Registry.** The EA publishes the machine and section registry (§7.7), signed.
4. **Software.** The release records and the approved software list are on the board (§24).
5. **Polls open.** The EA appends a signed `polls_open` entry (§17.7). After it, the registry and software policy are frozen.
6. **Voting.** Each machine opens a session and prints the zerésima, which the poll workers and observers sign (§15.5). It then receives signed authorizations, encrypts ballots, and runs cast or spoil for each. Everything is journaled (§15).
7. **Export.** Each machine prints the pre-BU, which the poll workers and observers sign and keep before transmission (§16.2), then closes its session and produces a signed package (§16.1). The board ingests the package after validating it (§17.6).
8. **Tally cutoff.** The EA appends a signed `tally_cutoff` entry (§17.7). Only packages before it are tallied.
9. **Voter checks.** Voters look up their codes, and observers check spoiled ballots.
10. **Tally.** Section tallies and final BUs, which can start on election night as packages arrive (§18.1, §16.5). After the cutoff: the pool (§18.2), mixing (§19), threshold decryption (§20), results (§21) and apportionment (§22).
11. **Verification.** Anyone runs §23.

---

## 5. Notation and primitives

### 5.1 Group

The group is **Ristretto255** (RFC 9496), a prime-order group built from Curve25519.

- *ℓ* = 2^252 + 27742317777372353535851937790883648493 is the group order.
- Scalars are integers modulo *ℓ*. Lowercase letters (*r*, *s*, *u*) denote scalars.
- Group elements use uppercase letters (*A*, *K*, *M*). The group operation is written additively: *A* + *C*, and *x*·*A* is scalar multiplication.
- *B* is the standard Ristretto255 generator.
- *O* is the identity element.
- Implementations MUST use the `curve25519-dalek` crate (or an equivalent audited, constant-time implementation) and MUST NOT implement field or curve arithmetic themselves.

### 5.2 Independent generators

Some proofs need generators whose discrete logarithm relative to *B* is unknown to everyone.

```
Gen(label, i) = Ristretto255.FromUniformBytes( SHA-512( CBOR(["eg/v1/gen", context_hash, label, i]) ) )
```

`FromUniformBytes` is the one-way map of RFC 9496 §4.3.4, applied to 64 uniform bytes.

### 5.3 Hashes

All hash inputs are deterministic CBOR (§6) arrays whose first element is a domain-separation tag string beginning with `eg/v1/`.

```
Digest(tag, x1, ..., xn)       = SHA-256( CBOR([tag, x1, ..., xn]) )             → 32 bytes
HashToScalar(tag, x1, ..., xn) = SHA-512( CBOR([tag, x1, ..., xn]) ) mod ℓ       → scalar
```

`mod ℓ` interprets the 64-byte output as a little-endian integer and reduces it (wide reduction, `Scalar::from_bytes_mod_order_wide`). Each item is encoded with its own CDDL type: group elements and scalars as 32-byte byte strings, integers as CBOR unsigned integers, and structures as their CBOR maps.

Every tag used in this spec is listed in Appendix A. Two different purposes MUST NOT share both the tag and the first element of `ctx` (§11). The generic proof tags (`eg/v1/schnorr`, `eg/v1/cp`, `eg/v1/disj01`) are shared by several statements, which are told apart by the label that begins their `ctx`.

### 5.4 Signatures

Signatures are Ed25519 (RFC 8032, pure Ed25519).

```
Sign(sk, tag, obj)        = Ed25519.Sign(sk, CBOR([tag, obj]))
Verify(pk, tag, obj, sig) = Ed25519.VerifyStrict(pk, CBOR([tag, obj]), sig)
```

Verification MUST use strict verification, rejecting non-canonical encodings and small-order points (the `verify_strict` semantics of `ed25519-dalek`).

### 5.5 Public-key encryption between trustees

Shares in the key ceremony are encrypted with **HPKE** (RFC 9180), base mode, using:

- KEM: DHKEM(X25519, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: ChaCha20-Poly1305

`info` = `CBOR(["eg/v1/dkg-share", manifest_hash, sender_index, recipient_index])`, and `aad` is empty.

### 5.6 Randomness

Production code MUST draw randomness from the operating system's cryptographically secure generator (`getrandom`). Test vector generation uses ChaCha20 seeded as described in §27, and production builds MUST NOT expose a seeded generator.

`Random()` denotes a uniformly random scalar: 64 random bytes reduced mod *ℓ*.

### 5.7 Lagrange coefficients

For a set *S* of distinct trustee indices and *j* ∈ *S*:

```
λ_j(S) = ∏_{m ∈ S, m ≠ j}  m · (m − j)^(−1)   mod ℓ
```

---

## 6. Encoding

### 6.1 Deterministic CBOR

All structures are encoded as CBOR (RFC 8949) following the **core deterministic encoding requirements** of RFC 8949 §4.2.1:

- definite-length encoding only,
- integers in the shortest form,
- map keys sorted by the bytewise lexicographic order of their encodings,
- no duplicate map keys,
- no floating-point values anywhere,
- no CBOR tags, except where this spec defines one (it currently defines none).

Decoders MUST reject any input that is not in deterministic form. To check this, decode, re-encode, and compare the bytes. This makes every hash and signature reproducible across implementations.

### 6.2 Structures

Structures are CBOR maps with small unsigned integer keys. Key `0` is always the structure type tag, a short text string such as `"ballot"`. Unknown keys MUST be rejected in v1.

Field types (in CDDL, RFC 8610):

```cddl
point     = bstr .size 32      ; canonical Ristretto255 encoding
scalar    = bstr .size 32      ; little-endian, MUST be < ℓ
digest    = bstr .size 32
ed25519pk = bstr .size 32
ed25519sig= bstr .size 64
index     = uint               ; 1-based trustee index, 0-based option index
```

Decoders MUST reject:

- point encodings that are not canonical Ristretto255 encodings,
- scalar encodings that are ≥ *ℓ*,
- the identity element *O* wherever this spec forbids it (marked "≠ O").

### 6.3 Versioning

Every top-level record has key `1: version`, which is `1` for this spec. A verifier MUST reject versions it does not implement.

---

## 7. Election manifest and machine registry

### 7.1 Manifest

```cddl
manifest = {
  0: "manifest",
  1: 1,                        ; version
  2: tstr,                     ; election_id, unique, e.g. "BR-2026-SP-PILOT-01"
  3: tstr,                     ; title
  4: [+ contest],
  5: [* party],                ; may be empty if no proportional contests
  6: [* federation],
  7: trustee_set,
  8: ed25519pk,                ; EA key
  9: ed25519pk,                ; board key
  10: software_policy,         ; §24
  11: mix_policy,
  12: [* link_group],          ; contests that must not share a candidate, §7.5
  13: uint,                    ; min_section_ballots: sections with fewer counted ballots are pooled, not decrypted alone (§18)
  14: tstr,                    ; the EA's own bloc label, e.g. "TSE" (§2.4)
  15: [2* mirror],             ; mirrors, at least two outside the EA's bloc (§2.4)
}

mirror = {
  0: "mirror",
  1: tstr,                     ; operator organisation
  2: tstr,                     ; bloc
  3: tstr,                     ; URL
  4: ed25519pk,                ; mirror key (signs the tree heads it has checked)
}

link_group = {
  0: "link_group",
  1: uint,                     ; group_index, 0-based, equals its position in the array
  2: [2* uint],                ; contest indices, ascending, at least two
}

contest = {
  0: "contest",
  1: uint,                     ; contest_index, 0-based, equals its position in the array
  2: tstr,                     ; name, e.g. "Governador"
  3: "single" / "multi" / "proportional",
  4: "homomorphic" / "mixnet",
  5: uint,                     ; L: selection limit (1 for single and proportional)
  6: [+ option],
  ? 7: apportionment_rule,     ; required iff kind = "proportional"
  ? 8: uint,                   ; seats, required iff kind = "proportional"
  ? 9: true,                   ; mixnet only: mix separately per region (§19.1)
}

option = {
  0: "option",
  1: uint,                     ; option_index, 0-based within the contest
  2: tstr,                     ; display name
  3: "candidate" / "party" / "blank" / "null",
  ? 4: tstr,                   ; ballot number shown to voters, e.g. "4512"
  ? 5: uint,                   ; party_index (candidates in proportional contests)
  ? 6: uint,                   ; tiebreak_rank: lower wins ties (§22.5)
}

party = { 0: "party", 1: uint, 2: tstr, 3: tstr, ? 4: ed25519pk }   ; index, name, number, party key (certifies observers, §16.3; fingerprint published by the party, §8)
federation = { 0: "federation", 1: uint, 2: tstr, 3: [+ uint] }  ; index, name, party indices

trustee_set = {
  0: "trustees",
  1: uint,                     ; n
  2: uint,                     ; k, threshold, 2 ≤ k ≤ n (k SHOULD be < n, so decryption survives an absent trustee)
  3: [+ trustee_info],         ; exactly n entries, indices 1..n in order
}

trustee_info = {
  0: "trustee",
  1: uint,                     ; trustee index i, 1..n
  2: tstr,                     ; organisation name
  3: ed25519pk,                ; signing key
  4: bstr .size 32,            ; X25519 HPKE public key
  5: tstr,                     ; bloc (§2.4), e.g. "TSE", "party:13", "OAB", "university"
}

mix_policy = {
  0: "mix_policy",
  1: uint,                     ; min_mixers: minimum number of distinct trustees mixing each mix unit, MUST be ≥ k
  2: uint,                     ; min_region_rows: smaller regions are merged before mixing (§19.1)
}
```

### 7.2 Manifest rules

A manifest is **well-formed** if all of the following hold:

1. Contest indices are 0..C−1 in order, and option indices within each contest are 0..m−1 in order.
2. Option kinds are valid for the contest kind:
   - `single`: at least one `candidate`, at most one `blank`, at most one `null`, no `party`.
   - `multi`: at least one `candidate`, at most one `null`, no `party`, no `blank`, and 1 ≤ *L* ≤ the number of candidates. A blank vote is zero selections. A null vote selects the `null` option and nothing else.
   - `proportional`: any of `candidate`, `party`, `blank`, `null`. Each `candidate` and each `party` option has a `party_index` (field 5 of the option) that refers to an existing party in manifest field 5. Each party has at most one `party` option.
3. `single` and `proportional` contests have *L* = 1.
4. Each party belongs to at most one federation.
5. Display numbers (field 4) are unique within a contest.
6. The `mixnet` method requires the number of options plus 1 to be less than 2^20 (the lookup table bound, §19.5).
7. Link groups (§7.5): each contest belongs to at most one group. All contests in a group have the same kind (`single` or `multi`), the same method, and identical option lists: the same options, of the same option kinds, at the same option indices, with the same display numbers.
8. `mix_policy.min_mixers` ≥ *k* and ≤ *n*, and `mix_policy.min_region_rows` ≥ 1. This makes the assumption "at least one mixer is honest" follow from "fewer than *k* trustees are corrupt".
9. Contest field 9 (regional mixing) appears only on `mixnet` contests, and is the same for all contests of a link group.
10. `min_section_ballots` ≥ 1.
11. **Trustee independence.** For every bloc label *b*, the number of trustees with bloc *b* is less than *k*. In particular, the EA's bloc (field 14) holds fewer than *k* shares.
12. **Signer independence.** For every bloc label *b*, the number of release signers (§24.4) with bloc *b* is less than *k_r*.
13. **Mirror independence.** At least two mirrors have a bloc different from the EA's bloc.

### 7.3 Manifest hash and signature

```
manifest_hash = Digest("eg/v1/manifest", manifest)
```

The EA publishes `signed_manifest = { 0: "signed_manifest", 1: manifest, 2: Sign(ea_sk, "eg/v1/sig/manifest", manifest) }` as the first board entry.

### 7.4 Brazil mapping (informative)

- Governor, President, Senator (one seat): `single`, with candidates, `blank` and `null`. A typed number that doesn't exist maps to `null`.
- Senator (two seats in the same election): both models are supported, and the EA chooses one per election:
  - one `multi` contest with *L* = 2 and a `null` option. The voter picks up to two candidates, or none (blank), or null for the whole contest.
  - two `single` contests ("1st senator", "2nd senator") over the same candidates, each with its own `blank` and `null`, placed in one link group (§7.5). This matches the current Brazilian urna flow, where each of the two votes can independently be blank or null.
- Federal, state and municipal legislators: `proportional`. A typed two-digit party number alone maps to the `party` option (*voto de legenda*). These contests use the **`homomorphic`** method, so that every section gets a proven per-candidate result (its final BU, §16.5), as Brazilian law requires per section (Lei 9.504/1997 art. 68). The cost is real: a homomorphic ballot carries one ciphertext and one proof per option, which for about 1,500 candidates is roughly 300 KB and 1,500 proofs per contest. Machines must be sized for it (§28.19). The `mixnet` method stays available where per-section results aren't required.
- Zerésima and boletim de urna: §15.5 (zerésima), §16.2 (pre-BU, printed at the section) and §16.5 (final BU, opened by the trustees).

### 7.5 Link groups

A link group is a set of contests over the same candidates in which one voter may choose a given candidate **at most once in total**. It is enforced in two layers.

**Machine layer (honest software).**
- On each later contest of the group, the machine MUST remove or disable the candidates already chosen in earlier contests of the group.
- If the voter types the number of an already chosen candidate, the machine MUST warn that this vote will be null. On confirmation, it records the `null` option for that contest.
- The library's ballot encryption MUST refuse selections that repeat a candidate across a link group. Correct software therefore never produces such a ballot.

**Protocol layer (detecting misbehaving software).**
- Homomorphic groups: each ballot carries a link proof (§12.3a) for every candidate, showing that the candidate's boxes across the group add up to 0 or 1.
- Mixnet groups: the slots of all contests in the group travel through the shuffle as one row (§19.1), and duplicates are detected after decryption (§19.6).
- A ballot that violates a link group is the output of misbehaving software. Only **the contests of that group** on that ballot are excluded from the tally. The ballot's other contests still count, and the verifier reports the ballot as evidence against its machine (§23).

A machine offers either all contests of a link group or none of them (§7.7).

### 7.6 Machine identifiers

`machine_id` is a text string unique within the registry. `section_id` is a text string naming the polling section.

### 7.7 Machine registry

```cddl
registry = {
  0: "registry",
  1: 1,
  2: digest,                   ; manifest_hash
  3: uint,                     ; registry_version, starts at 1, increases by 1
  4: [+ machine_entry],
  5: [+ section_entry],
  6: [* observer_entry],
}

machine_entry = {
  0: "machine",
  1: tstr,                     ; machine_id
  2: tstr,                     ; section_id, MUST name a section in field 5, or "" for a reserve machine (below)
  3: ed25519pk,                ; machine signing key
  4: [+ uint],                 ; contest indices offered by this machine, ascending
}

section_entry = {
  0: "section",
  1: tstr,                     ; section_id, unique
  2: uint,                     ; eligible voters on the roll
  3: [+ ed25519pk],            ; poll worker (mesário) keys of this section
  4: uint,                     ; maximum sessions per machine of this section (≥ 1; e.g. 1, or 2 to allow a contingency machine)
  5: tstr,                     ; region (e.g. state or municipality), used for regional mixing (§19.1)
}

observer_entry = {
  0: "observer",
  1: tstr,                     ; organisation the observer represents (party, federation or civil body)
  2: ed25519pk,                ; observer (fiscal) key
}
```

Registry rules:

- Every contest index a machine offers exists, and a machine offers either all contests of a link group or none of them.
- Every section has at least one machine that isn't a reserve machine.

**Reserve machines.** A reserve machine (section_id `""`) is held for contingencies and bound to a section only on the day, when it replaces a failed machine:

- Its session's section is the `section_id` in its `session_open` and zerésima. Its zerésima, authorizations and pre-BU MUST be signed by poll worker keys of **that** section.
- All sessions of a reserve machine name the same section. A reserve machine serves at most one section per election.
- Its offered contests (field 4) MUST equal those of the regular machines of the section it serves.

Throughout this spec, **the session's section** means the registered section of a regular machine, or the section bound this way for a reserve machine.
- Observer keys and poll worker keys are disjoint from each other and from machine keys.

**Key generation.** Machine, poll worker and observer keys MUST be generated inside the device or token that uses them, and only the public key leaves it. The EA collects public keys and never holds the secret keys. An EA that provisioned the keys itself could forge a complete, validly signed package for a section, and only observers' independent copies would expose it (§28.18).

The EA publishes `signed_registry = { 0: "signed_registry", 1: registry, 2: Sign(ea_sk, "eg/v1/sig/registry", registry) }`. A later version replaces an earlier one. **No `signed_registry` may appear after the `polls_open` entry (§17.7).** The board MUST refuse one, and a verifier that finds one reports the board as misbehaving and ignores it. Every package is therefore evaluated against the single registry in force when the polls opened.

---

## 8. Key ceremony (distributed key generation)

The trustees run a Pedersen distributed key generation with Feldman verifiable secret sharing. Nobody, at any time, knows the joint secret key *s*.

The ceremony runs in three rounds. Each round's messages are signed by their author and appended to the board (or exchanged as files and appended afterwards). All messages carry `manifest_hash`.

**Trustee keys come from the trustees.** The EA writes the trustee keys into the manifest. An EA that substituted its own keys could run the whole ceremony alone and hold the full decryption key. Before Round 1, each trustee MUST check its own keys in the manifest. Each trustee organisation SHOULD publish the fingerprints of its keys through its own channels (its website, a public statement), and the verifier report lists the fingerprints (§23) so anyone can compare them. **The same applies to party keys** (manifest field 5). An EA that substituted a party's key could choose that party's observers, so each party SHOULD publish its key fingerprint through its own channels, and the verifier lists them too.

### 8.1 Round 1: commitments

Trustee *i*:

1. Picks a random polynomial of degree *k*−1: coefficients *a*_{i,0}, ..., *a*_{i,k−1}, each `Random()`. The polynomial is *P*_i(*x*) = Σ_t *a*_{i,t} · *x*^t mod ℓ.
2. Computes coefficient commitments *C*_{i,t} = *a*_{i,t} · *B* for *t* = 0..*k*−1. Each MUST be ≠ *O*. If one is *O*, resample that coefficient.
3. For each *t*, computes a Schnorr proof of knowledge of *a*_{i,t} (§11.1), with context `["dkg-coef", manifest_hash, i, t]`.

```cddl
dkg_round1 = {
  0: "dkg_round1", 1: 1,
  2: digest,                  ; manifest_hash
  3: uint,                    ; i
  4: [+ point],               ; C_{i,0..k-1}
  5: [+ schnorr_proof],       ; one per coefficient
  6: ed25519sig,              ; Sign(sk_i, "eg/v1/sig/dkg1", fields 0..5)
}
```

The signature covers the map without key 6. The same convention applies to every signed record in this spec: **field N, the last field, signs the map made of all the other fields.**

### 8.2 Round 2: encrypted shares

After every trustee has seen all *n* valid Round 1 messages, trustee *i* computes, for each *j* ≠ *i*, the share *p*_{i→j} = *P*_i(*j*) mod ℓ. It encrypts the share as HPKE(pk_hpke_j, 32-byte scalar) using the `info` from §5.5.

```cddl
dkg_round2 = {
  0: "dkg_round2", 1: 1,
  2: digest,                  ; manifest_hash
  3: uint,                    ; i (sender)
  4: [+ enc_share],           ; one per j ≠ i, sorted by j
  5: ed25519sig,
}
enc_share = { 0: "enc_share", 1: uint, 2: bstr, 3: bstr }   ; j, HPKE enc, ciphertext
```

### 8.3 Round 3: verification and acceptance

Trustee *j* decrypts each share *p*_{i→j} and checks:

```
p_{i→j} · B  ==  Σ_{t=0}^{k−1}  (j^t mod ℓ) · C_{i,t}
```

If every check passes, trustee *j* computes:

```
z_j = P_j(j) + Σ_{i ≠ j} p_{i→j}      mod ℓ        (secret share, never published)
```

It then publishes acceptance:

```cddl
dkg_round3 = {
  0: "dkg_round3", 1: 1,
  2: digest,                  ; manifest_hash
  3: uint,                    ; j
  4: digest,                  ; transcript_hash (§8.5)
  5: "accept",
  6: ed25519sig,
}
```

### 8.4 Complaints

If a share fails the check, trustee *j* publishes a complaint instead of acceptance:

```cddl
dkg_complaint = { 0: "dkg_complaint", 1: 1, 2: digest, 3: uint, 4: uint, 5: ed25519sig }  ; manifest_hash, j (complainer), i (accused)
```

The accused trustee *i* MUST answer by publishing *p*_{i→j} in clear:

```cddl
dkg_reveal = { 0: "dkg_reveal", 1: 1, 2: digest, 3: uint, 4: uint, 5: scalar, 6: ed25519sig }    ; manifest_hash, i, j, p_{i→j}
```

Everyone checks the revealed share against *C*_{i,·}:

- If it is valid, *j* uses it and the complaint is resolved.
- If it is invalid or missing, trustee *i* is disqualified.

In v1, **any disqualification aborts the ceremony.** The EA must publish a new manifest (for example with *i* removed or replaced) and the ceremony restarts from Round 1. Continuing with a qualified subset is left for a later version.

### 8.5 Transcript and outputs

```
transcript_hash = Digest("eg/v1/dkg-transcript", manifest_hash, [dkg_round1 for i = 1..n], [dkg_round2 for i = 1..n])
```

The ceremony is **complete** when all *n* trustees have published `dkg_round3` with the same `transcript_hash` and there are no unresolved complaints.

Public outputs, computable by anyone:

```
K   = Σ_{i=1}^{n} C_{i,0}                                    (joint public key, MUST be ≠ O)
Z_j = Σ_{i=1}^{n} Σ_{t=0}^{k−1} (j^t mod ℓ) · C_{i,t}         (verification key of trustee j, = z_j · B)
```

**Note on key bias.** In Pedersen DKG, a malicious trustee can slightly bias the distribution of *K* (Gennaro, Jarecki, Krawczyk and Rabin, 1999). That does not affect the security of ElGamal encryption or threshold decryption (Gennaro et al., 2003), so v1 accepts it.

---

## 9. Election context

Once the ceremony is complete, the election context is:

```cddl
context = {
  0: "context", 1: 1,
  2: digest,                  ; manifest_hash
  3: digest,                  ; transcript_hash
  4: point,                   ; K
  5: [+ point],               ; Z_1..Z_n
}
context_hash = Digest("eg/v1/context", context)
```

Every proof, ballot, chain and package in the election binds to `context_hash`.

---

## 10. Encryption

### 10.1 Exponential ElGamal

To encrypt an integer *m* with 0 ≤ *m* < 2^32, using nonce *r*:

```
Enc(m; r) = (α, β) = ( r·B ,  m·B + r·K )
```

Ballot ciphertexts MUST have *r* ≠ 0, which gives α ≠ *O*. Verifiers MUST reject a ballot ciphertext whose α = *O*.

### 10.2 Homomorphic addition

```
(α1, β1) ⊕ (α2, β2) = (α1 + α2, β1 + β2) = Enc(m1 + m2; r1 + r2)
```

### 10.3 Re-encryption

```
ReEnc((α, β); r') = (α + r'·B, β + r'·K)
```

The result encrypts the same *m* and is unlinkable to the input under DDH.

### 10.4 Decryption, with the full key (informative)

```
β − s·α = m·B
```

*m* is then recovered from *m*·*B* by a bounded discrete-log search (§20.4). In this protocol the full key *s* never exists. Decryption is always done with threshold shares (§20).

### 10.5 Plaintext encodings

- **Homomorphic contests:** *m* ∈ {0, 1} for each selection, and tallies are sums.
- **Mixnet contests:** *m* = option_index + 1 for a selected option, and *m* = 0 for an empty slot ("none"). Both methods therefore use the same encryption, and only the proofs and the counting differ.

---

## 11. Zero-knowledge proofs

All proofs are non-interactive Sigma protocols made non-interactive with **strong Fiat-Shamir**: the challenge hashes the full context, the full statement and all commitments. Proofs are sent in compact form, as (challenge, responses). The verifier recomputes the commitments from the responses and checks the challenge.

Each proof has a `ctx` value, a CBOR array that binds the proof to its exact position, for example `["sel", context_hash, ballot_id, contest_index, option_index]`. A proof MUST NOT verify under any other `ctx`.

### 11.1 Schnorr proof of knowledge

Statement: the prover knows *x* such that *X* = *x*·*B*.

```
Prove:   u ← Random();  A = u·B
         c = HashToScalar("eg/v1/schnorr", ctx, X, A)
         v = u + c·x
         proof = (c, v)

Verify:  A' = v·B − c·X
         accept iff c == HashToScalar("eg/v1/schnorr", ctx, X, A')
```

```cddl
schnorr_proof = [scalar, scalar]   ; (c, v)
```

### 11.2 Chaum-Pedersen proof of equal discrete logarithms

Statement: the prover knows *x* such that *X*1 = *x*·*G*1 and *X*2 = *x*·*G*2.

```
Prove:   u ← Random();  A1 = u·G1;  A2 = u·G2
         c = HashToScalar("eg/v1/cp", ctx, G1, X1, G2, X2, A1, A2)
         v = u + c·x
         proof = (c, v)

Verify:  A1' = v·G1 − c·X1;  A2' = v·G2 − c·X2
         accept iff c == HashToScalar("eg/v1/cp", ctx, G1, X1, G2, X2, A1', A2')
```

```cddl
cp_proof = [scalar, scalar]
```

### 11.3 Disjunctive proof that a ciphertext encrypts 0 or 1

This is the Cramer-Damgård-Schoenmakers OR-composition of two Chaum-Pedersen statements.

Statement: (α, β) = Enc(*b*; *r*) for some *b* ∈ {0, 1}. Equivalently, for some *b*, the pair (α, β − *b*·*B*) equals *r*·(*B*, *K*).

The prover knows *b* and *r*. Let *f* = 1 − *b*.

```
Prove:
  # simulate the false branch f
  c_f ← Random();  v_f ← Random()
  A_f = v_f·B − c_f·α
  D_f = v_f·K − c_f·(β − f·B)

  # real branch b
  u ← Random()
  A_b = u·B
  D_b = u·K

  c   = HashToScalar("eg/v1/disj01", ctx, α, β, A_0, D_0, A_1, D_1)
  c_b = c − c_f   mod ℓ
  v_b = u + c_b·r

  proof = (c_0, c_1, v_0, v_1)

Verify:
  for j in {0, 1}:
    A_j' = v_j·B − c_j·α
    D_j' = v_j·K − c_j·(β − j·B)
  accept iff c_0 + c_1 == HashToScalar("eg/v1/disj01", ctx, α, β, A_0', D_0', A_1', D_1')   (mod ℓ)
```

```cddl
disj01_proof = [scalar, scalar, scalar, scalar]   ; c0, c1, v0, v1
```

**Why it works.** The prover can choose one challenge freely, which lets it fake one branch. The hash fixes the sum of the two challenges, so it can't fake both. The verifier can't tell which branch is real.

### 11.4 Proof that a sum of ciphertexts encrypts exactly L

Statement: (α_Σ, β_Σ) = Enc(*L*; *r*_Σ), where *r*_Σ = Σ *r*. This is a Chaum-Pedersen proof (§11.2) with:

```
G1 = B,   X1 = α_Σ
G2 = K,   X2 = β_Σ − L·B
x  = r_Σ
```

### 11.5 Ciphertext proof of knowledge (mixnet slots)

Statement: the prover knows *r* with α = *r*·*B*. This is a Schnorr proof (§11.1) with *X* = α and `ctx` including β:

```
ctx = ["slot", context_hash, ballot_id, contest_index, slot_index, β]
```

This makes each mixnet slot ciphertext non-malleable and bound to its ballot. Copying another voter's ciphertext into a new ballot requires its nonce.

### 11.6 Decryption share proof

Trustee *j* proves that *M*_j = *z*_j · α was computed with the same *z*_j as its verification key *Z*_j. This is a Chaum-Pedersen proof (§11.2) with:

```
G1 = B,  X1 = Z_j
G2 = α,  X2 = M_j
x  = z_j
```

### 11.7 Shuffle proof

The shuffle proof is specified in §19.3.

---

## 12. Ballots

### 12.1 Ballot identifier

```cddl
ballot_id = [tstr, tstr, uint]   ; machine_id, session_id, sequence (1-based within the session)
```

### 12.2 Nonce derivation

Each ballot gets a fresh 32-byte **nonce seed** ρ drawn from the operating system generator. Every encryption nonce in the ballot is derived from it:

```
r(contest_index, position) = HashToScalar("eg/v1/nonce", context_hash, ballot_id, ρ, contest_index, position)
```

`position` is the option index or placeholder index (homomorphic contests) or the slot index (mixnet contests).

If a derived *r* = 0, the machine MUST draw a new ρ and restart the ballot. This has negligible probability.

Revealing ρ (on spoil) reveals every nonce, so anyone can re-derive the ballot. Erasing ρ (on cast) makes the ballot permanently unopenable except through threshold decryption. Proof randomness (*u*, *c*_f, *v*_f) MUST come from fresh `Random()` calls and never from ρ.

### 12.3 Homomorphic contest encoding

Let the contest have *m* options and selection limit *L*.

- `single` and `proportional`: there are *m* selection ciphertexts. Exactly one encrypts 1, and the rest encrypt 0. There are no placeholders.
- `multi`: there are *m* selection ciphertexts (candidates, plus the `null` option if present) and *L* **placeholder** ciphertexts. Placeholders are never tallied.
  - The voter selects *q* ≤ *L* candidates: those candidates encrypt 1, exactly *L* − *q* placeholders encrypt 1 (the lowest-positioned ones), and `null` encrypts 0.
  - The voter selects null: `null` encrypts 1, and every candidate and placeholder encrypts 0.
  - The **weighted sum** used by the sum proof counts the `null` ciphertext *L* times:
    ```
    (α_Σ, β_Σ) = ⊕ candidates ⊕ placeholders ⊕ L·(α_null, β_null)
    r_Σ        = Σ candidate and placeholder nonces + L·r_null
    ```
    where *L*·(α, β) = (*L*·α, *L*·β). The weighted sum must be exactly *L*. Each ciphertext is proven to be 0 or 1, so a null vote of 1 forces every other ciphertext to 0. A null cannot be combined with candidate votes.

For each ciphertext (option or placeholder):

```
(α, β) = Enc(b; r(contest_index, position))
proof  = disj01 proof (§11.3), ctx = ["sel", context_hash, ballot_id, contest_index, position]
```

Positions 0..*m*−1 are options, and positions *m*..*m*+*L*−1 are placeholders.

Contest sum proof:

```
single, proportional:  (α_Σ, β_Σ) = ⊕ of all m ciphertexts,        r_Σ = Σ of their nonces,  L_target = 1
multi:                 (α_Σ, β_Σ) = the weighted sum above,         r_Σ = the weighted nonce, L_target = L
proof = §11.4 with L_target, ctx = ["sum", context_hash, ballot_id, contest_index]
```

A `multi` contest without a `null` option uses the same formula with no null term.

### 12.3a Link proofs (homomorphic link groups)

For each homomorphic link group and each `candidate` option index *x* (blank and null excluded):

```
(α_x, β_x) = ⊕_{contests c in the group} (α, β)_{c,x}
r_x        = Σ_{c} r(c, x)
proof      = disj01 (§11.3) on (α_x, β_x) with witness (b = 0 or 1, r_x),
             ctx = ["link", context_hash, ballot_id, group_index, x]
```

### 12.4 Mixnet contest encoding

There are *L* slots. A selected option fills a slot with *m* = option_index + 1, unused slots hold *m* = 0, and filled slots come first in ascending order of option index.

```
(α, β) = Enc(m; r(contest_index, slot))
proof  = §11.5
```

No validity proof is attached. Validity is enforced after decryption (§19.6), which is safe because a single ciphertext can carry at most one vote.

### 12.5 Ballot structure

```cddl
ballot = {
  0: "ballot", 1: 1,
  2: digest,                      ; context_hash
  3: ballot_id,
  4: [+ contest_ballot],          ; one per contest offered by the machine, ascending contest_index
  5: [* link_proof],              ; one per homomorphic link group whose contests are all offered, ascending group_index
}

link_proof = [uint, [+ disj01_proof]]   ; group_index, one proof per candidate option, ascending option index

contest_ballot = hom_contest / mix_contest

hom_contest = {
  0: "hom", 1: uint,              ; contest_index
  2: [+ selection],               ; m + (L if multi) entries, in position order
  3: cp_proof,                    ; sum proof
}
selection = [point, point, disj01_proof]    ; α, β, proof

mix_contest = {
  0: "mix", 1: uint,              ; contest_index
  2: [+ slot],                    ; exactly L entries
}
slot = [point, point, schnorr_proof]        ; α, β, proof
```

### 12.6 Ballot validity

Validity is judged per contest, so that one faulty contest doesn't discard the voter's other votes.

A ballot is **well-formed** if:

1. `context_hash` matches the election context.
2. The contest indices are exactly those offered by the machine in the registry, in ascending order, and each contest has the structure of its kind and method (number of selections or slots).
3. Field 5 has exactly one link proof per homomorphic link group whose contests the machine offers, with one proof per candidate.
4. Every α ≠ *O*.

A ballot that isn't well-formed is excluded entirely.

In a well-formed ballot, a contest is **counted** if:

- **homomorphic:** every disj01 proof and the sum proof verify, and, if the contest is in a link group, every link proof of that group verifies.
- **mixnet:** every slot proof verifies. Link-group duplicates are handled after decryption (§19.6).
- **uniqueness:** none of the contest's α values was already *reserved* (below).

A contest that isn't counted is excluded from the tally. If it belongs to a link group, every contest of that group on that ballot is excluded with it. Each exclusion is reported as evidence against the machine (§23).

**α reservation (replay and duplicate defence).** Ballots are processed in board order, then in package order. When a contest of a **cast** ballot passes its proof checks, each of its α values becomes reserved. A later contest whose proofs pass but which contains a reserved α is not counted. Ballots whose proofs fail, and spoiled or abandoned ballots, reserve nothing. An attacker therefore can't get an honest ballot excluded by appending an earlier package that copies its ciphertexts with invalid proofs. A copy with *valid* proofs is impossible without the nonce, because every proof binds `ballot_id` (§11). Two valid contests sharing an α mean that a machine reused a nonce, and both are reported.

---

## 13. Tracking codes, slips and the per-machine chain

### 13.1 Chain

Each machine session keeps a hash chain. Its initial head is:

```
head_0 = Digest("eg/v1/chain-start", context_hash, machine_id, session_id, software_measurement, opening_challenge)
```

For each ballot, in sequence order:

```
code_s = Digest("eg/v1/code", head_{s−1}, Digest("eg/v1/ballot", ballot_s))
```

The machine displays `code_s` to the voter **before** offering CAST or SPOIL. After the decision:

```
head_s = Digest("eg/v1/chain", code_s, status_s, reveal_digest_s)
```

Here `status_s` is `"cast"`, `"spoiled"` or `"abandoned"` (§15.4), and `reveal_digest_s` is `Digest("eg/v1/reveal", reveal_s)` for spoiled ballots and 32 zero bytes otherwise.

Because each code depends on the head before it, removing, reordering or altering any ballot changes every later code. Two voters can't receive the same code from the same machine, and `machine_id` keeps codes distinct across machines. Together these rule out clash attacks, where a machine gives two voters with the same choices the same ballot.

### 13.2 Display form

The short code is the first 100 bits of `code_s`, encoded in Crockford base32 as 20 characters and displayed in groups of 4, for example `K7QD-3XMA-9PRT-2BHW-6YCN`. The full 32-byte code goes into a QR code on the slip.

### 13.3 Slip

```cddl
slip = {
  0: "slip", 1: 1,
  2: digest,          ; context_hash
  3: tstr,            ; machine_id
  4: digest,          ; code
  5: ed25519sig,      ; Sign(machine_sk, "eg/v1/sig/slip", fields 0..4)
}
```

The slip contains no selections, no sequence number and no time. A signed slip whose code is missing from the board, or present with a different status than the voter chose, is **proof of misbehaviour** by the machine or the board.

---

## 14. Benaloh audit-or-cast

### 14.1 States

```
          encrypt()                 cast()
Selected ──────────► Committed ─────────────► Cast       (ρ erased)
                         │
                         │ spoil()
                         └──────────────────► Spoiled    (ρ and plaintext revealed)
```

1. **encrypt(selections)**: the machine draws ρ, builds the ballot (§12), computes `code_s`, journals the ballot (§15) and displays and prints the code. From this point the ballot is fixed.
2. **cast()**: the machine journals `cast`, **securely erases ρ**, signs and prints the slip, and consumes one authorization.
3. **spoil()**: the machine journals the reveal record below and prints a **spoil receipt**. The ballot is never tallied, the authorization isn't consumed, and the voter votes again.

```cddl
reveal = {
  0: "reveal", 1: 1,
  2: ballot_id,
  3: bstr .size 32,           ; ρ
  4: [+ contest_plain],       ; the selections the machine claims it encrypted
}
contest_plain = [uint, [* uint]]   ; contest_index, selected option indices (ascending)

spoil_receipt = {
  0: "spoil_receipt", 1: 1,
  2: digest,                  ; context_hash
  3: tstr,                    ; machine_id
  4: digest,                  ; code
  5: reveal,
  6: ed25519sig,              ; Sign(machine_sk, "eg/v1/sig/spoil", fields 0..5)
}
```

The spoil receipt is printed as a QR code, together with the claimed selections in human-readable form. It is safe to take home, because the spoiled ballot is never counted. It is also clearly marked as **not** a vote, unlike the cast slip.

### 14.2 Checking a spoiled ballot

The ballot's proofs use fresh randomness (§12.2), so the ballot can't be rebuilt from ρ alone. The check therefore needs the committed ballot from the published package, and can run only after the package is on the board.

Given a spoil receipt, a checker:

1. verifies the receipt signature, fetches the package containing `code` with its inclusion proof (§17.5), and checks the code's status is `spoiled` with a reveal equal to the receipt's,
2. re-derives every nonce *r* from ρ (§12.2),
3. re-encrypts the claimed selections using the encoding in §12.3 or §12.4 (placeholders: the first *L* − *q* placeholders encrypt 1, or none of them for a null vote),
4. checks every (α, β) is byte-for-byte equal to the ballot's,
5. shows the claimed selections to the voter or observer, who compares them with the choices actually made.

The check MUST run on a device independent of the voting machine, such as the voter's phone, an observer's laptop or a public verifier. The voting machine MUST NOT be the device that tells the voter whether the check passed, because a cheating machine would simply show the expected choices.

Any mismatch is cryptographic evidence against the machine. The ballot, the reveal, the spoil receipt and the signed package (§16) are all signed or chained by that machine.

### 14.3 Detection probability (informative)

If a machine changes *k* ballots and each voter independently spoils with probability *p*, the chance that no changed ballot is audited is (1 − *p*)^*k*. Hosts SHOULD let observers run audit-only sessions throughout the day and SHOULD prompt randomly selected voters to audit, so that a machine can't tell which voters are likely to audit.

A voter who spoils usually spoils their real choice, and the spoiled reveal is published in the chain directly before that voter's cast ballot. Voters MUST be told that spoiled choices become public. Hosts SHOULD favour observer audit-only sessions, which carry no privacy cost, over voter audits (§28.13).

---

## 15. Machine journal and zerésima

### 15.1 Format

The journal is an append-only file of framed records:

```
frame = u32_be(length) || CBOR(record) || Digest("eg/v1/journal", prev_frame_digest, CBOR(record))
```

The first frame's `prev_frame_digest` is 32 zero bytes. The frame digest chains every record, including authorizations.

The machine MUST `fsync` (or the platform equivalent) the journal after each record and before showing anything to the voter that depends on it. In particular the code is synced before it is displayed, and the cast record is synced before the slip is printed.

### 15.2 Records

```cddl
journal_record = session_open / zeresima_signed / authorization / ballot_committed / ballot_cast
               / ballot_spoiled / ballot_abandoned / authorization_cancelled / checkpoint
               / pre_bu_signed / session_close

session_open = { 0: "session_open", 1: 1, 2: digest, 3: tstr, 4: tstr, 5: tstr, 6: software_measurement, 7: uint, 8: bstr .size 16, ? 9: attestation }
  ; context_hash, machine_id, section_id, session_id, measurement, opened_at (Unix seconds),
  ; opening_challenge (16 random bytes from the poll terminal, §15.5), attestation (§24.5)
zeresima_signed = { 0: "zeresima_signed", 1: 1, 2: zeresima, 3: [+ section_sig] }   ; §15.5
authorization = { 0: "auth", 1: 1, 2: uint, 3: ed25519pk, 4: ed25519sig }
  ; auth_seq (1, 2, 3, ... within the session), poll worker key, signature (below). NO voter data and NO time.
ballot_committed = { 0: "committed", 1: 1, 2: ballot, 3: digest }   ; ballot, code
ballot_cast = { 0: "cast", 1: 1, 2: digest }          ; code
ballot_spoiled = { 0: "spoiled", 1: 1, 2: digest, 3: reveal }       ; code, reveal
ballot_abandoned = { 0: "abandoned", 1: 1, 2: digest }              ; code
authorization_cancelled = { 0: "auth_cancel", 1: 1, 2: uint, 3: ed25519pk, 4: ed25519sig }
  ; auth_seq being cancelled, poll worker key, signature (below)
checkpoint = { 0: "checkpoint", 1: 1, 2: uint, 3: digest, 4: digest, 5: ed25519sig }
  ; number of records before this one, frame digest of the previous record, current chain head,
  ; Sign(machine_sk, "eg/v1/sig/checkpoint", [context_hash, machine_id, session_id, fields 2..4])
session_close = { 0: "session_close", 1: 1, 2: uint, 3: uint, 4: uint, 5: uint, 6: digest, 7: uint, ? 8: attestation }
  ; authorizations, cast, spoiled, abandoned, final chain head, closed_at, closing attestation (§24.5)
```

The machine appends a `checkpoint` immediately after every `zeresima_signed`, `cast`, `spoiled`, `abandoned` and `pre_bu_signed` record, and syncs it before printing the slip or the spoil receipt. A journal recovered from a dead machine can therefore be verified up to its last checkpoint without the machine (§16.4).

Authorizations and cancellations are signed by a poll worker key of the session's section (§7.7), on the poll terminal:

```
authorization signature = Sign(pw_sk, "eg/v1/sig/auth",        [context_hash, machine_id, session_id, auth_seq])
cancellation signature  = Sign(pw_sk, "eg/v1/sig/auth-cancel", [context_hash, machine_id, session_id, auth_seq])
```

A machine therefore can't create authorizations for itself, and it can't cancel an authorization to hide a dropped ballot. Ed25519 signatures are deterministic and the signed message contains only a counter, so the signature reveals nothing about the voter.

### 15.3 Privacy rules

- Records other than `session_open`, `zeresima_signed` (which repeats the opening time) and `session_close` MUST NOT contain time.
- `authorization` MUST NOT contain anything identifying the voter.
- Hosts (poll terminals) MUST NOT record the order or time in which voters were authorized. This obligation falls on the host, and the spec states it so integrators know.

### 15.4 Invariants and recovery

- The journal begins with `session_open` followed by `zeresima_signed`. No `authorization` may precede `zeresima_signed`.
- `auth_seq` values are 1, 2, 3, ... with no gaps or repeats, and each authorization and cancellation signature verifies under a poll worker key of the session's section (§7.7).
- Each `cast` MUST be preceded by an unused `authorization`. Each `auth_cancel` names an authorization that is unused at that point.
- At most one authorization is unused at any time. A new `authorization` MUST NOT be journaled until the previous one has been consumed by a `cast` or cancelled. This limits a machine that records a voter's CAST as "spoiled" to using the freed authorization before the next voter arrives, and the voter's signed slip then proves the relabelling (§28.20).
- A `checkpoint` follows every `zeresima_signed`, `cast`, `spoiled`, `abandoned` and `pre_bu_signed` record, with correct record count, frame digest and chain head.
- The journal ends with `pre_bu_signed`, its checkpoint and `session_close`. The pre-BU's counts, frame digest and chain head match the journal, its fingerprint matches the section tally recomputed from the journal and its imports (§18.1), and it carries at least one valid poll worker signature of the section.
- At `session_close`: authorizations = cast + `auth_cancel` count.
- A machine has at most `max_sessions` sessions (§7.7) on the board.
- On restart, the machine replays the journal and verifies the frame chain:
  - A truncated **final** frame (a torn write) is discarded.
  - A `cast`, `spoiled` or `abandoned` record with no checkpoint after it (a crash in between) gets its checkpoint appended now. For a `cast`, the slip was never printed, so the machine prints it now, marked as a reprint. The signed slip is byte-identical to the original, since Ed25519 signatures are deterministic.
  - Any other damage is fatal, and the machine MUST refuse to continue the session.
  - A `committed` ballot with no following `cast` or `spoiled` record becomes **abandoned**. The machine erases ρ without revealing it, because the voter may have meant to cast it. It then appends `ballot_abandoned` and records the status `"abandoned"` in the chain (§13.1). An abandoned ballot is never tallied and does not consume an authorization. `session_close` counts it in field 5.
  - After an abandoned ballot, the poll worker decides whether the voter votes again under the same authorization or whether to cancel it with a signed `auth_cancel`. The machine MUST NOT cancel on its own.

### 15.5 Zerésima

Before the first authorization of a session, the machine proves in front of the section that it starts empty.

1. The poll terminal sends 16 fresh random bytes, the `opening_challenge`, which the machine records in `session_open`. Because the challenge is unpredictable, an attestation quote (§24.5) and the zerésima can't be prepared in advance.
2. The machine prints the zerésima: the human-readable list of every offered contest and option with zero votes, plus a QR code carrying the `zeresima` record below.
3. At least one poll worker of the section signs it on the poll terminal. Those signatures are journaled in `zeresima_signed`. Observers MAY countersign by scanning the QR code and publishing a `section_attestation` (§16.3). Everyone present signs the paper copy by hand.

```cddl
zeresima = {
  0: "zeresima", 1: 1,
  2: digest,                  ; context_hash
  3: tstr,                    ; machine_id
  4: tstr,                    ; section_id
  5: tstr,                    ; session_id
  6: software_measurement,
  7: digest,                  ; head_0 (§13.1)
  8: digest,                  ; RecordId(session_open record)
  9: uint,                    ; opened_at
  10: ed25519sig,             ; Sign(machine_sk, "eg/v1/sig/zeresima", fields 0..9)
}

section_sig = [ed25519pk, ed25519sig]   ; signer key, Sign(sk, "eg/v1/sig/section", RecordId(signed record))
```

`RecordId(x) = Digest("eg/v1/record-id", x)` names any record, including its own signature field.

**What it proves.**
- *Freshness.* `head_0` includes the poll terminal's random `opening_challenge`, so it can't be computed before the zerésima ceremony. Every tracking code of the session chains from it, so no ballot of this session can have been encrypted before that moment.
- *No pre-loaded votes.* What stops ballots from being added before voting starts is the rule that every `cast` needs a poll worker authorization journaled after `zeresima_signed` (§15.4). The zerésima makes the starting point public and witnessed.
- *Presence.* A machine registered by the EA but never opened in front of a real section has no zerésima carrying an observer's independent signature and no observer copy. Poll worker signatures alone don't prove presence, because the EA registered those keys (§28.18).

A package whose head doesn't match its signed zerésima is rejected.

Mesários and fiscais SHOULD check the QR code with an independent device, such as the observer app, which shows the machine ID, section, software measurement and opening time.

---

## 16. Export package and boletim de urna

### 16.1 Package

At `session_close`, the machine produces:

```cddl
package = {
  0: "package", 1: 1,
  2: package_header,
  3: [+ journal_record],         ; the full journal, in order, without framing
  4: ed25519sig,                 ; Sign(machine_sk, "eg/v1/sig/package", fields 0..3)
}

package_header = {
  0: "package_header", 1: 1,
  2: digest,                     ; context_hash
  3: tstr,                       ; machine_id
  4: tstr,                       ; section_id
  5: tstr,                       ; session_id
  6: software_measurement,
  ? 7: attestation,
  8: uint,                       ; record count
  9: digest,                     ; final journal frame digest
  10: digest,                    ; final chain head
}
```

The package is written to and read from any byte stream (file, removable media, pipe or socket). Because the software measurement sits in the signed header, a package always names the software that produced it. The machine SHOULD keep the journal on two independent media, so that a failed machine still yields its package.

### 16.2 Pre-BU (the encrypted boletim de urna)

The pre-BU is the section's boletim de urna. It is printed at the close, **before anything is transmitted**, and it carries **no per-candidate numbers**. Instead it fixes the section's *encrypted* subtotal, which the trustees open later with proofs (§16.5, §18, §20).

The voting machine therefore never keeps a plaintext count. At the close it only adds locked boxes together, which needs no key. No per-candidate count exists on the machine, in the journal or on paper at any time, so nobody can learn individual votes by comparing counts taken at different moments. The machine still sees each vote while the voter is choosing (§1.1).

1. A poll worker enters the **voter-roll count** on the poll terminal: the number of voters who signed the roll (*caderno de votação*) or were identified biometrically, counted independently of the machine. It is the count for the **whole section** so far, including voters served by an earlier machine of the section.
2. The machine computes the section's encrypted subtotal and its fingerprint (§18.1). It covers its own cast ballots and those of any recovered package it imported (§16.4).
3. The machine builds the `pre_bu` record and prints several copies. Each copy shows the counts, the fingerprint in groups of four characters, and a QR code carrying the record.
4. At least one poll worker signs it on the poll terminal. The pre-BU and those signatures are journaled together in `pre_bu_signed`, followed by a checkpoint. Before signing, the poll terminal MUST check that field 13 equals the voter-roll count it sent. Observers countersign by scanning the QR code (§16.3). Everyone present signs the paper copies by hand. One copy is posted at the section, and observers keep copies.
5. The machine then closes the session and builds the package (§16.1). The package therefore contains the pre-BU and its poll worker signatures.

```cddl
pre_bu = {
  0: "pre_bu", 1: 1,
  2: digest,                  ; context_hash
  3: tstr,                    ; machine_id
  4: tstr,                    ; section_id
  5: tstr,                    ; session_id
  6: [* imported],            ; each recovered package imported (§16.4)
  7: digest,                  ; journal frame digest of the record just before this pre-BU
  8: digest,                  ; chain head at this point (= the session's final chain head)
  9: uint,                    ; authorizations
  10: uint,                   ; cast
  11: uint,                   ; spoiled
  12: uint,                   ; abandoned
  13: uint,                   ; voter-roll count, entered by the poll worker
  14: digest,                 ; subtotal fingerprint (§18.1)
  15: [* uint],               ; homomorphic contests pooled because they have fewer than min_section_ballots counted ballots
  16: ed25519sig,             ; Sign(machine_sk, "eg/v1/sig/pre-bu", fields 0..15)
}

pre_bu_signed = { 0: "pre_bu_signed", 1: 1, 2: pre_bu, 3: [+ section_sig] }
imported = [digest, uint, digest]   ; RecordId(recovered_package), its cast count, its last chain head
```

Counts in fields 9–12 are for this session only. Imported ballots are counted in their recovered packages, and each import's cast count and last chain head are printed on the pre-BU so that the mesários and fiscais sign them too.

A machine has exactly one pre-BU per session, the one journaled in its package. A paper or attested copy that differs from it, or two different machine-signed pre-BUs for the same session, is proof of misbehaviour by the machine (§23 step 7).

**What it proves.**
- Fields 7 and 8 pin every ballot of the session. A package that never reaches the board, or arrives altered, is proven by any paper or QR copy.
- Field 14 pins the encrypted section totals. The final BU's numbers are proven against it (§16.5), so the paper copy in observers' hands fixes the section's result before anyone can decrypt it.
- A section cast total above the voter-roll count is visible at the section, on paper, before anything leaves it.

### 16.3 Section attestations

**Observer certificates.** A party certifies its own observers with its party key (manifest field 5), so the EA can't choose who observes for a party or leave a party out:

```cddl
observer_cert = {
  0: "observer_cert", 1: 1,
  2: digest,                  ; context_hash
  3: uint,                    ; party_index
  4: ed25519pk,               ; observer key
  5: ed25519sig,              ; Sign(party_sk, "eg/v1/sig/observer-cert", fields 0..4)
}
```

The board MUST accept any `observer_cert` that verifies under a party key and arrives **before `polls_open`**. A certificate issued later can't count, because a party colluding with the EA could otherwise certify keys after the election and use them to "witness" sections that never existed.

A lost or stolen observer device is revoked by its party:

```cddl
observer_revoke = {
  0: "observer_revoke", 1: 1,
  2: digest,                  ; context_hash
  3: uint,                    ; party_index
  4: ed25519pk,               ; observer key revoked
  5: ed25519sig,              ; Sign(party_sk, "eg/v1/sig/observer-revoke", fields 0..4)
}
```

The board MUST accept a revocation at any time before `tally_cutoff`. Attestations by a revoked key that appear on the board after its revocation are ignored, and earlier ones stay valid. Observers who are not party delegates, such as civil-society or international observers, are registered by the EA (§7.7).

**Attestations.** Observers who countersign outside the journal publish the **full signed record**, not only its hash. A copy of a pre-BU whose package never arrives then shows which machine, section, counts and chain head are missing.

```cddl
section_attestation = {
  0: "section_attestation", 1: 1,
  2: zeresima / pre_bu,       ; the full record, with the machine's signature
  3: ed25519pk,               ; observer (certified or registered) or poll worker key
  4: ed25519sig,              ; Sign(sk, "eg/v1/sig/section", RecordId(field 2))
}
```

The signed bytes are the same as in a `section_sig`, so a signature collected on the poll terminal and one sent from an observer app are interchangeable. The board MUST accept any section attestation whose record carries a valid machine signature and whose key is a poll worker key of that section or an observer key, even when it has no matching package. That is exactly the evidence of a missing package. Observers SHOULD also send their attestations to at least one mirror, so that a board refusing them is caught. The board MAY rate-limit attestations per key, as an operational rule against flooding, but MUST NOT refuse the first attestation by a key for a given record.

### 16.4 Recovered packages

When a machine dies, the journal on its second medium (§16.1) is recovered on another device under the poll workers' supervision. The dead machine can't sign a package, so the recovered journal is published as:

```cddl
recovered_package = {
  0: "recovered_package", 1: 1,
  2: package_header,             ; built from the journal; field 9 is the frame digest at the last checkpoint
  3: [+ journal_record],         ; the journal up to and including its last checkpoint
  4: uint,                       ; voter-roll count at the time of failure
  5: [+ section_sig],            ; poll workers (and observers) of the section, over RecordId of fields 0..4
}
```

- The records are authenticated by the last `checkpoint`, which the dead machine signed. Anything after the last checkpoint is discarded. That is at most one ballot in progress, which was never cast and printed no slip.
- Every `committed` ballot without a final status before the last checkpoint is treated as abandoned.
- No `pre_bu_signed` or `session_close` exists, so the §15.4 count invariant is checked only up to the checkpoint, and authorizations left unused are counted as cancelled.
- The session counts against the machine's `max_sessions`, and the replacement machine opens its own session with its own zerésima.
- **Use every surviving medium.** The recovery reads every medium that survived, and uses the **longest** journal whose checkpoints verify. If two media disagree beyond their common prefix, the longer valid one wins, and the disagreement is reported.
- **Truncation is detectable.** Publishing a journal cut at an earlier checkpoint would silently drop later votes. It shows up in three ways:
  1. the section's cast total, A's import plus B's own, falls short of the voter-roll count on the paper pre-BU, which is visible at the section,
  2. A's voters after the cut hold signed slips whose codes are missing from the board,
  3. a medium that turns up later with a further valid checkpoint proves the cut.
- **Import.** The replacement machine imports the recovered package, verifies its last checkpoint, and lists it in its pre-BU field 6. The section's encrypted subtotal then covers both machines, and **one pre-BU covers the whole section**. This is the encrypted counterpart of moving today's memory card to the contingency urna. No plaintext is needed, because the boxes are added while locked.
- A recovered package that no pre-BU imports is still counted. Its cast ballots go into the pool (§18.2), and the verifier reports it.

### 16.5 Final BU

Once the trustees have opened a section tally (§18.1, §20), anyone can assemble the **final BU**, which is the section's result with its proof attached:

```cddl
final_bu = {
  0: "final_bu", 1: 1,
  2: digest,                      ; context_hash
  3: digest,                      ; RecordId(pre_bu)
  4: digest,                      ; RecordId(section_tally)
  5: [* [uint, uint, [+ uint]]],  ; per contest not pooled: index, ballots counted, votes per option
  6: [+ decryption_share_set],    ; partial openings of the section tally by at least k trustees (§20.1)
}
```

The final BU carries no signature. Its authority comes from the proofs, not from whoever publishes it.

**Checking a final BU** (for example, a fiscal's app holding the paper pre-BU):

1. Read the pre-BU from its QR code.
2. Recompute the section tally from the packages on the board (§18.1), or fetch it and spot-check it, and check that its fingerprint equals pre-BU field 14.
3. Verify every share set's proofs (§11.6) against the trustees' verification keys *Z*_j in the election context.
4. Combine *k* valid share sets (§20.2), recover each number (§20.4), and check that they equal field 5.

| Attempt | Caught by |
|---|---|
| Publish different numbers | They don't equal what the share proofs force |
| Decrypt a different set of boxes | Its fingerprint doesn't match the paper pre-BU |
| Swap or alter the package | The chain head and frame digest don't match the paper pre-BU |
| A trustee lies in its partial opening | Its proof fails against its *Z*_j. It is discarded and reported |
| *k* or more trustees collude | They still can't produce a false number with valid proofs. They could open individual ballots instead, which is the secrecy risk of §2.1 |

**Timing.** A section tally can be opened as soon as its packages are on the board, so final BUs can appear on election night if the trustees' decryption services are online, or after `tally_cutoff` if not. The proofs are the same either way.


---

## 17. Bulletin board log

### 17.1 Entries

The board is an append-only sequence of entries. Each entry is a CBOR structure from this spec: `signed_manifest`, `dkg_*`, `signed_registry`, `software_policy_update` (§24.4), `polls_open` and `tally_cutoff` (§17.7), `package`, `recovered_package`, `observer_cert`, `observer_revoke`, `section_attestation`, `final_bu` (§16), `rejection` (§17.6), `section_tally`, `pool_tally`, `encrypted_tally` (§18), `mix_output` (§19), `decryption_share_set` (§20) and `result` (§21). Release records live in the separate release log (§24.3).

### 17.2 Merkle tree

The tree follows the structure of RFC 9162 (Certificate Transparency v2), with this spec's hashes:

```
leaf_hash(entry)  = Digest("eg/v1/leaf", entry)
node_hash(L, R)   = Digest("eg/v1/node", L, R)
MTH({})           = Digest("eg/v1/empty")
MTH({d0})         = leaf_hash(d0)
MTH(D[n]), n > 1  = node_hash(MTH(D[0:k]), MTH(D[k:n]))  where k is the largest power of 2 less than n
```

Inclusion proofs and consistency proofs are produced and verified with the algorithms of RFC 9162 §2.1.3 and §2.1.4, using `node_hash` above.

### 17.3 Signed tree head

```cddl
sth = {
  0: "sth", 1: 1,
  2: digest,                 ; manifest_hash
  3: uint,                   ; tree size
  4: digest,                 ; root
  5: uint,                   ; timestamp, Unix seconds
  6: ed25519sig,             ; Sign(board_sk, "eg/v1/sig/sth", fields 0..5)
}
```

### 17.4 Equivocation

Two valid STHs signed by the board with the same tree size and different roots, or an STH that fails a consistency proof against an earlier STH, are **proof of board misbehaviour**. Mirrors MUST fetch every STH, verify consistency with the previous one, and exchange STHs with other mirrors.

### 17.5 Voter lookup

A voter's client (the WASM build, or any implementation) takes a slip code and:

1. fetches an STH from at least two independent sources, the board and at least one manifest mirror outside the EA's bloc (§2.4), and checks they agree or are consistent,
2. finds the package entry containing the code and fetches its inclusion proof,
3. verifies the inclusion proof against the STH,
4. checks that in that package the code is followed by the status the voter chose (`cast`) and that the slip signature verifies,
5. verifies the ballot's proofs and α reservations (§12.6), and reports every contest of the ballot that is **not counted**. A machine that knows the plaintext could otherwise attach bad proofs only to votes for one candidate, and the voter's code would still look fine.

To find the package, the client SHOULD download the whole section's package (or a mirror's index of all codes) rather than send the code to the board. A board that learns which codes are looked up learns which voters check, and a dishonest machine and board together could target the voters who don't.

### 17.6 Package ingestion rules

The board MUST validate each package before appending it, and verifiers re-check these rules (§23):

1. The `polls_open` entry is on the board, and the package arrives before the `tally_cutoff` entry.
2. The signature verifies under the registered key of `machine_id`, in the registry frozen at `polls_open`.
3. The context hash matches.
4. The software measurement is on the approved list (§24.4). If the policy requires attestation, the opening and closing attestations verify (§24.5).
5. The journal frames re-chain to the header's frame digest, and the tracking-code chain re-computes to the header's chain head.
6. The zerésima in `zeresima_signed` is signed by the machine, names this session and its `head_0`, and carries at least one valid poll worker signature of the session's section (§7.7, §15.5).
7. The invariants of §15.4 hold, including the poll worker signatures on every authorization and cancellation.
8. Ballot proof failures (§12.6) do **not** reject the package. They exclude the affected ballot or contests and are reported, because rejecting the package would discard every honest voter's ballot on that machine. The package itself is evidence against the machine.
9. No `(machine_id, session_id)` pair is already on the board, and the machine has no more than `max_sessions` packages.

A board that rejects a package MUST publish the rejection reason as a signed `rejection` entry, so that a dropped package is visible:

```cddl
rejection = { 0: "rejection", 1: 1, 2: digest, 3: tstr, 4: ed25519sig }   ; RecordId(package), reason, Sign(board_sk, "eg/v1/sig/rejection", fields 0..3)
```

A pre-BU published by observers in a `section_attestation` whose package never appears before `tally_cutoff`, or appears rejected or different, is reported by the verifier (§23).

A `recovered_package` is ingested under rules 1, 3, 4 and 7–9 above, plus:
- the last record is a `checkpoint` whose signature verifies under the registered machine key, and whose record count, frame digest and chain head match the journal before it,
- the frames and the chain re-compute up to that checkpoint,
- `zeresima_signed` is present and valid (rule 6),
- at least one `section_sig` verifies under a poll worker key of the section,
- no `package` exists for the same `(machine_id, session_id)`. If the machine's own package later appears, it wins and the recovered package is reported as superseded.

### 17.7 Polls open and tally cutoff

```cddl
polls_open = {
  0: "polls_open", 1: 1,
  2: digest,                  ; context_hash
  3: digest,                  ; RecordId(signed_registry) in force
  4: uint,                    ; time, Unix seconds
  5: ed25519sig,              ; Sign(ea_sk, "eg/v1/sig/polls-open", fields 0..4)
}

tally_cutoff = {
  0: "tally_cutoff", 1: 1,
  2: digest,                  ; context_hash
  3: uint,                    ; time, Unix seconds
  4: ed25519sig,              ; Sign(ea_sk, "eg/v1/sig/tally-cutoff", fields 0..3)
}
```

- `polls_open` freezes the registry and the software policy. The board MUST refuse any `signed_registry` or `software_policy_update` after it.
- `tally_cutoff` fixes the set of packages to be tallied: exactly the packages accepted before it. Tallies and mix input lists (§18, §19.1) are computed at the tree size just before `tally_cutoff`, and the verifier rejects any tally computed at another size.
- At the cutoff, the verifier lists each registered section and machine with no accepted package, and each pre-BU attestation whose package is missing. The EA cannot quietly choose which packages count.

---

## 18. Homomorphic tally

No plaintext count exists until the trustees open a sum. Sums are opened per pre-BU (section tallies), plus one pool for groups too small to publish. The election total is the sum of all of them.

### 18.1 Section tally

Each pre-BU defines a **section tally**. It covers the cast ballots of the pre-BU's own session and of the recovered packages listed in its field 6. For each homomorphic contest *c* and option *o* (placeholders excluded), the encrypted subtotal is computed over those ballots for which contest *c* is counted (§12.6):

```
(A_{c,o}, Β_{c,o}) = ⊕_{covered cast ballots} (α, β)_{c,o}
```

A contest with fewer than `min_section_ballots` counted ballots in this tally is **pooled**. It is left out of the section tally and added to the pool (§18.2), so that a small group's votes are never published on their own.

```cddl
section_tally = {
  0: "section_tally", 1: 1,
  2: digest,                      ; context_hash
  3: digest,                      ; RecordId(pre_bu)
  4: tstr,                        ; section_id
  5: [+ digest],                  ; RecordId of the pre-BU's package, then of each imported recovered package
  6: [* [uint, uint, [+ [point, point]]]],   ; contests not pooled, ascending: index, ballots counted, per option (A, Β)
  7: [* uint],                    ; pooled contest indices, ascending
}

fingerprint = Digest("eg/v1/subtotal", context_hash, machine_id, session_id, pre_bu field 6, section_tally field 6, section_tally field 7)
```

The fingerprint can't name the pre-BU's own package, because that package contains the pre-BU. It names the session instead, and the pre-BU's fields 7 and 8 pin the session's contents.

The machine computes the section tally at the close, and its fingerprint goes on the pre-BU. Anyone recomputes it from the board, byte for byte. A section tally can be computed and opened as soon as its packages are on the board. It doesn't wait for `tally_cutoff`.

**Mismatch.** If the section tally recomputed from the board doesn't match the pre-BU fingerprint, the section is reported as `mismatch` against its machine. This happens when the machine claimed something other than what it encrypted, or included a contest that fails its proofs. The tally recomputed from the board is the one that is opened, so the valid votes still count under §12.6.

### 18.2 Pool

After `tally_cutoff`, the pool sums, per homomorphic contest:

- the pooled contests of every section tally,
- the cast ballots of accepted packages and recovered packages that no pre-BU covers.

```cddl
pool_tally = {
  0: "pool_tally", 1: 1,
  2: digest,                      ; context_hash
  3: uint,                        ; tree size: the entry index of tally_cutoff (§17.7)
  4: [* [uint, uint, [+ [point, point]]]],   ; per homomorphic contest: index, ballots counted, per option (A, Β)
}
```

A pool contest with zero counted ballots is listed with the empty sum (*O*, *O*). It is not decrypted, and its total is 0 by definition.

### 18.3 Encrypted tally index

```cddl
encrypted_tally = {
  0: "encrypted_tally", 1: 1,
  2: digest,                      ; context_hash
  3: digest,                      ; STH root at tally_cutoff
  4: uint,                        ; tree size: the entry index of tally_cutoff
  5: [* digest],                  ; RecordId(section_tally) of every pre-BU in accepted packages, board order
  6: digest,                      ; RecordId(pool_tally)
}
```

Anyone recomputes all of it from the board at the stated tree size and MUST get byte-identical results.

**Privacy (informative).** Because no per-candidate count is printed anywhere, no published number can be subtracted from another to isolate a small group, except one: the pool equals the election total minus all section results. A pool with fewer than `min_section_ballots` ballots is therefore exposed, and the verifier warns when that happens. In a real election, small sections and failures add up to far more than the threshold. The EA SHOULD avoid sections with fewer than `min_section_ballots` eligible voters. Per-section results match Brazilian practice, but a section where every voter chose the same candidate still reveals every vote.

---

## 19. Mixnet tally

### 19.1 Input list

A **mix unit** is a mixnet contest outside any link group, or a mixnet link group, together with a **region**:

- if the contest has field 9 (regional mixing), there is one mix unit per region of the registry (§7.7), covering that region's sections only,
- otherwise there is a single mix unit with the region `""` (all sections).

**Small regions.** Before mixing, regions are merged so that every mix unit has at least `min_region_rows` rows. Regions are sorted by name. While some region has fewer rows than the minimum and more than one region remains, the smallest is merged into its next neighbour in sorted order, wrapping around from the last to the first (ties go to the earlier name). A merged region is named by joining its parts' names with `+`. The EA SHOULD name regions so that sorted neighbours are geographic neighbours. The merge is deterministic, so every verifier reproduces it.

A mix unit is identified by its lowest contest index and its region, which are the `contest_index` and `region` used in §19.2 and §19.3. Regional mixing keeps each shuffle proof a manageable size: a single national shuffle of 150 million rows would make every proof about 19 GB. The region is also the voter's anonymity set, and it is published.

For each mix unit, the input list *E*^(0) holds one **row** per cast ballot in the unit's region, from packages and recovered packages accepted before `tally_cutoff` (§17.7), whose contests in the unit are all counted (§12.6). A mix unit with zero rows is not mixed, and all its counts are 0. Each row is the tuple of that ballot's slot ciphertexts for every contest in the unit, contests ascending and slots ascending. Rows are ordered by (board entry index, position in the package).

Width *w* = Σ *L* over the unit's contests. All slots of one ballot move together through every shuffle, so that duplicates within a ballot and across linked contests can be detected after decryption (§19.6).

### 19.2 Shuffle

Mixer *t* takes the list *E* of *N* rows. It picks a uniformly random permutation π of {1..*N*} and re-encryption nonces *r̃*_{i,k} ← `Random()`, and outputs:

```
Ẽ_i[k] = ReEnc(E_{π(i)}[k]; r̃_{i,k})     for i = 1..N, k = 1..w
```

The mixers are trustees, acting in ascending index order. Each trustee mixes a given unit at most once, and at least `mix_policy.min_mixers` (≥ *k*) **distinct** trustees must mix it. Since fewer than *k* trustees are assumed corrupt, at least one shuffle is honest. A trustee that doesn't take part is skipped. Each output becomes the next mixer's input.

```cddl
mix_output = {
  0: "mix_output", 1: 1,
  2: digest,                 ; context_hash
  3: uint,                   ; contest_index
  4: uint,                   ; mixer trustee index
  5: uint,                   ; step number, 1-based
  6: digest,                 ; Digest("eg/v1/mix-list", input list)
  7: [+ [+ [point, point]]], ; output list: N rows of w ciphertexts
  8: shuffle_proof,
  9: tstr,                   ; region of the mix unit ("" if not regional)
  10: ed25519sig,
}
```

### 19.3 Shuffle proof (Terelius-Wikström)

This is the Terelius-Wikström proof of a shuffle, following the structure of Haenni, Locher, Koenig and Dubuis, "Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets" (2017). It is written here additively, over Ristretto255, and generalised to rows of width *w*.

**Generators.** With `label` = `["shuffle", contest_index, region, step]`, set *H* = Gen(label, 0) and *H*_i = Gen(label, *i*) for *i* = 1..*N*. Each mix step therefore uses its own generators.

**Statement.** The input rows are *E*_1..*E*_N and the output rows are *Ẽ*_1..*Ẽ*_N. There exist π and *r̃* such that *Ẽ*_i = ReEnc(*E*_{π(i)}; *r̃*_i), componentwise.

**Prover.**

1. *Permutation commitment.* For *i* = 1..*N*: draw *ρ*_{π(i)} ← `Random()` and set
   ```
   c_{π(i)} = ρ_{π(i)}·B + H_i
   ```
2. *Challenges.* For *j* = 1..*N*:
   ```
   u_j = HashToScalar("eg/v1/shuffle-u", ctx, E, Ẽ, c, j)
   ```
   Set *u'*_i = *u*_{π(i)}.
3. *Commitment chain.* Set ĉ_0 = *H*. For *i* = 1..*N*: draw *ρ̂*_i ← `Random()` and set
   ```
   ĉ_i = ρ̂_i·B + u'_i·ĉ_{i−1}
   ```
4. *Derived witnesses.*
   ```
   v_N = 1;  v_i = u'_{i+1}·v_{i+1}   for i = N−1 down to 1
   ρ̄    = Σ_j ρ_j
   ρ̂    = Σ_i ρ̂_i·v_i
   ρ'   = Σ_j ρ_j·u_j
   r̃[k] = Σ_i r̃_{i,k}·u'_i            for k = 1..w
   ```
5. *Commitments.* Draw ω_1, ω_2, ω_3, ω_4[1..w], ω̂_1..ω̂_N, ω'_1..ω'_N ← `Random()`, and compute
   ```
   T1    = ω_1·B
   T2    = ω_2·B
   T3    = ω_3·B + Σ_i ω'_i·H_i
   T4α[k] = −ω_4[k]·B + Σ_i ω'_i·α̃_i[k]
   T4β[k] = −ω_4[k]·K + Σ_i ω'_i·β̃_i[k]
   T̂_i   = ω̂_i·B + ω'_i·ĉ_{i−1}
   ```
6. *Challenge.*
   ```
   c = HashToScalar("eg/v1/shuffle", ctx, E, Ẽ, c_vec, ĉ_vec, T1, T2, T3, T4α, T4β, T̂)
   ```
7. *Responses.*
   ```
   s1 = ω_1 + c·ρ̄
   s2 = ω_2 + c·ρ̂
   s3 = ω_3 + c·ρ'
   s4[k] = ω_4[k] + c·r̃[k]
   ŝ_i = ω̂_i + c·ρ̂_i
   s'_i = ω'_i + c·u'_i
   ```

```cddl
shuffle_proof = {
  0: "shuffle_proof", 1: 1,
  2: [+ point],     ; c_1..c_N
  3: [+ point],     ; ĉ_1..ĉ_N
  4: scalar,        ; c
  5: scalar, 6: scalar, 7: scalar,   ; s1, s2, s3
  8: [+ scalar],    ; s4[1..w]
  9: [+ scalar],    ; ŝ_1..ŝ_N
  10: [+ scalar],   ; s'_1..s'_N
}
ctx = ["shuffle", context_hash, contest_index, region, step]
```

**Verifier.**

1. Recompute *u*_j as in prover step 2.
2. Compute:
   ```
   c̄    = Σ_j c_j − Σ_i H_i
   ĉ    = ĉ_N − (∏_j u_j)·H
   c'   = Σ_j u_j·c_j
   α'[k] = Σ_j u_j·α_j[k]
   β'[k] = Σ_j u_j·β_j[k]
   ```
3. Recompute the commitments (ĉ_0 = *H*):
   ```
   T1'    = s1·B − c·c̄
   T2'    = s2·B − c·ĉ
   T3'    = s3·B + Σ_i s'_i·H_i − c·c'
   T4α'[k] = −s4[k]·B + Σ_i s'_i·α̃_i[k] − c·α'[k]
   T4β'[k] = −s4[k]·K + Σ_i s'_i·β̃_i[k] − c·β'[k]
   T̂_i'   = ŝ_i·B + s'_i·ĉ_{i−1} − c·ĉ_i
   ```
4. Accept iff *c* == HashToScalar("eg/v1/shuffle", ctx, *E*, *Ẽ*, c_vec, ĉ_vec, T1', T2', T3', T4α', T4β', T̂').

**Why it works (informative).**
- T1 shows the committed matrix has exactly one 1 in each row. This is the "sum" condition: Σ *c*_j commits to Σ *H*_i.
- T2 and the chain T̂ show ∏ *u'*_i = ∏ *u*_i.
- T3 shows *c'* commits to the vector *u'* with the same responses *s'* used in T4.
- By the Terelius-Wikström lemma, for random *u* these conditions imply the commitment is to a permutation matrix.
- T4 shows that the output, weighted by *u'*, equals the input weighted by *u*, up to a re-encryption, which means the output is a re-encrypted permutation of the input.

The complete algebra for each check appears in Appendix B.

Implementations MUST use multi-scalar multiplication (`vartime_multiscalar_mul` is acceptable in the **verifier only**, which handles no secrets).

### 19.4 Decryption of the final list

After the last mix step, every ciphertext in the final list is threshold-decrypted (§20). Each decrypted value *M* = *m*·*B*.

### 19.5 Lookup table

The decoder maps *M* to *m* through a precomputed table {*m*·*B* : 0 ≤ *m* ≤ number of options}. A value not in the table is **invalid**.

### 19.6 Counting rules

For each decrypted row:

- Slots equal to 0 are empty.
- If any slot is invalid, or a non-empty index appears twice in the row, the whole row is counted as **invalid** for this contest.
- Otherwise each non-empty slot adds one vote to option (*m* − 1).
- A row with only empty slots is a blank vote in `multi` contests. In `single` and `proportional` contests, a machine always fills the slot, so an all-empty row is counted invalid.
- In `multi` contests, a row holding the `null` option and nothing else is a null vote. A row holding `null` together with any candidate is counted invalid.
- In a link-group mix unit, the row is first split into its contests and each contest is checked by the rules above. Then, if any candidate option index appears in more than one contest of the row, **every contest of the row** is counted invalid. Honest machines turn a repeated choice into null before encryption (§7.5), so a duplicate here can only come from misbehaving software. The verifier can't attribute an anonymous row to a machine, so it reports only the count.

---

## 20. Threshold decryption

### 20.1 Decryption share

For a ciphertext (α, β), trustee *j* computes *M*_j = *z*_j·α and a proof (§11.6) with:

```
ctx = ["dec", context_hash, target_digest, item_index]
```

`target_digest` is `RecordId` of the `section_tally`, of the `pool_tally` or of the final `mix_output`, and `item_index` is the position of the ciphertext in canonical order within that target.

```cddl
decryption_share_set = {
  0: "decryption_shares", 1: 1,
  2: digest,                     ; context_hash
  3: digest,                     ; target_digest
  4: uint,                       ; trustee index j
  5: [+ [point, cp_proof]],      ; (M_j, proof) per ciphertext, canonical order
  6: ed25519sig,
}
```

Canonical order for a `section_tally`: contests in the order of field 6, then options ascending. For a `pool_tally`: contests ascending, then options ascending, skipping contests with zero counted ballots. For a mix list: rows ascending, then slots ascending.

### 20.2 Combination

With a set *S* of at least *k* trustees whose share sets all verify:

```
M = Σ_{j ∈ S} λ_j(S)·M_j        ( = s·α )
T = β − M                       ( = m·B )
```

The result does not depend on which *S* is used. Verifiers MAY use any *k* valid share sets.

### 20.3 Partial participation

The verifier MUST check every published share set. A share set that fails is **discarded and reported** as misbehaviour by that trustee. It does not block the decryption. The combination uses the *k* lowest indices among the share sets that verify. If fewer than *k* verify, decryption is incomplete and the trustees publish again.

### 20.4 Discrete log recovery

For homomorphic subtotals, *m* is in [0, *N*_p] where *N*_p is the number of ballots counted for that contest in that section tally or pool (§18). Implementations use a precomputed table or baby-step giant-step, and MUST fail if no *m* ≤ *N*_p matches.

### 20.5 What a trustee agrees to decrypt

A trustee's decryption shares can open any ciphertext, so an honest trustee MUST check the target itself before producing shares:

- **`section_tally`:** the trustee checks that the pre-BU is inside an accepted package on the board, that every imported recovered package is accepted, and that the section tally recomputed from them is byte-identical, including which contests are pooled. It never opens a pooled contest. This check doesn't need `tally_cutoff`, so section tallies can be opened on election night.
- **`pool_tally`:** only after `tally_cutoff`. The trustee recomputes it from the board at that tree size (§18.2) and checks it is byte-identical.
- **Final mix list:** the trustee checks that the first input list was built per §19.1, that every step's proof verifies and each step's input is the previous output, and that at least `min_mixers` distinct trustees mixed the unit. It never decrypts an input list or an intermediate list.

Each trustee runs its checks and its decryption service on its own infrastructure, never on infrastructure the EA hosts (§2.4).

Without this rule, a corrupt EA could hand the trustees a "tally" that is really one voter's ballot. The `ShareHolder` interface (§25) enforces it by taking the board dump, not bare ciphertexts.

---

## 21. Results

```cddl
result = {
  0: "result", 1: 1,
  2: digest,                     ; context_hash
  3: uint,                       ; tree size the tally covers (tally_cutoff)
  4: [+ contest_result],
  5: [* section_result],         ; one per pre-BU in accepted packages, board order
  6: [* [uint, uint, [+ uint]]], ; pool: per homomorphic contest, index, ballots counted, votes per option
  7: ed25519sig,                 ; Sign(ea_sk, "eg/v1/sig/result", fields 0..6). Verifiers recompute everything anyway.
}

contest_result = {
  0: "contest_result", 1: uint,  ; contest_index
  2: [+ uint],                   ; votes per option (homomorphic: sum of the final BUs and the pool)
  3: uint,                       ; ballots counted
  4: uint,                       ; invalid (mixnet only, else 0)
  5: uint,                       ; ballots excluded under §12.6 (not counted)
  ? 6: [+ [uint, uint]],         ; proportional: party_index, party total (§22.1)
  ? 7: seat_allocation,          ; proportional: §22
}

section_result = {
  0: "section_result",
  1: tstr,                       ; section_id
  2: digest,                     ; RecordId(pre_bu)
  3: digest,                     ; RecordId(final_bu)
  4: [* [uint, uint, [+ uint]]], ; homomorphic contests not pooled: index, ballots counted, votes per option (= final BU)
  5: [* [uint, uint]],           ; every offered contest: index, ballots excluded under §12.6
  6: "match" / "mismatch",       ; does the pre-BU fingerprint match the section tally recomputed from the board (§18.1)
}
```

Excluded ballots are reported per section, not hidden in a total. Whether a number of exclusions in a section requires annulment or a re-vote is a legal decision outside this protocol. The protocol guarantees that the number is public, attributable to a machine, and impossible to suppress.

---

## 22. Apportionment

Apportionment is a pure, deterministic function from the verified totals and the manifest to seats. It uses **integer arithmetic only**. To compare fractions *a*/*b* and *c*/*d*, compare *a*·*d* with *c*·*b* in 128-bit (or arbitrary-precision) integers.

### 22.1 Party totals

For a proportional contest, a **list** is a federation, or a party that is not in any federation:

```
party_total(p) = votes(party option of p) + Σ_{candidates x with party p} votes(x)
list_total(F)  = Σ_{p ∈ F} party_total(p)
valid_votes V  = Σ_{lists} list_total              (blank and null excluded)
```

### 22.2 Rule `dhondt`

```cddl
apportionment_rule = dhondt_rule / brazil_rule
dhondt_rule = { 0: "dhondt", ? 1: uint }    ; optional threshold in basis points of V (e.g. 500 = 5%)
```

1. Lists below the threshold are excluded.
2. Seats are given out one at a time, *seats* times. Each seat goes to the list with the highest `list_total / (seats_won + 1)` among lists that still have an unseated candidate.
3. Within a list, seats go to its candidates in descending order of individual votes.
4. If no list has an unseated candidate, the remaining seats stay unfilled and are reported in the `seat_allocation`.

Ties are resolved by §22.5.

### 22.3 Rule `brazil-2021`

> **LEGAL REVIEW REQUIRED.** This rule encodes the reading of Código Eleitoral arts. 106–112 as amended by Lei 14.211/2021, plus the STF ruling on ADIs 7228, 7263 and 7325 (2024) on the final distribution phase. Before any real use, an electoral lawyer must confirm each step and parameter. Parameters are explicit so the rule can be updated without changing code.

```cddl
brazil_rule = {
  0: "brazil-2021",
  1: uint,     ; candidate minimum for quotient seats, in basis points of QE (default 1000 = 10%)
  2: uint,     ; list minimum for remainder seats, in basis points of QE (default 8000 = 80%)
  3: uint,     ; candidate minimum for remainder seats, in basis points of QE (default 2000 = 20%)
  4: bool,     ; final phase open to all lists, without thresholds (default true, per the STF 2024 reading)
}
```

1. **Electoral quotient.** *q* = *V* div *seats*, and *rem* = *V* mod *seats*. QE = *q* + 1 if 2·*rem* > *seats*, else *q*. (The fraction is dropped if it is ½ or less, and rounded up otherwise.)
2. **No list reaches QE.** If no list has `list_total ≥ QE`, the most-voted candidates are elected, regardless of list, until all seats are filled (Código Eleitoral art. 111), and the rule ends. *(Legal review: confirm the current wording of art. 111 and whether the 2021 amendments or the STF ruling change this case.)*
3. **Party quotient.** QP(*F*) = `list_total(F) div QE`.
4. **Quotient seats.** Each list *F* receives up to QP(*F*) seats, filled by its candidates with individual votes ≥ (param 1 / 10000)·QE, in descending order of votes. If it has fewer eligible candidates than QP(*F*), the unused places go into the remainder pool.
5. **Remainder seats (highest averages).** While remainder seats remain:
   - eligible lists have `list_total ≥ (param 2 / 10000)·QE` and at least one unseated candidate with votes ≥ (param 3 / 10000)·QE,
   - the seat goes to the eligible list with the highest `list_total / (seats_won + 1)`, and within it to the unseated eligible candidate with the most votes.
6. **Final phase.** If seats remain and no list is eligible under step 5:
   - if param 4 is true, continue the highest-averages procedure with every list, and every unseated candidate eligible regardless of votes,
   - otherwise, do the same among lists with `list_total ≥ QE`, ignoring candidate thresholds.
7. Federations are treated as single lists throughout, and their seats go to their candidates by individual votes.

All threshold comparisons use integers: `votes · 10000 ≥ bp · QE`.

```cddl
seat_allocation = {
  0: "seats", 1: tstr,          ; rule name
  2: [+ [uint, uint]],          ; list index, seats won
  3: [+ uint],                  ; elected candidate option indices, in award order
  ? 4: uint,                    ; QE (brazil rule)
}
```

### 22.4 List indices

Federations come first, in manifest order, followed by the parties that are in no federation, in manifest order.

### 22.5 Tie-breaking

Ties between lists: the list with the higher `list_total` wins. If still tied, the list containing the candidate with the lowest `tiebreak_rank` wins.

Ties between candidates: the lower `tiebreak_rank` wins. The EA sets `tiebreak_rank` from the legal criterion (in Brazil, the oldest candidate, art. 110). A proportional manifest MUST give every candidate a distinct `tiebreak_rank`.

---

## 23. Verification procedure

A verifier takes a board dump plus at least one STH, and outputs PASS or a list of failures. It MUST perform every check below. Each failure is reported with the entry index and the section of this spec it violates.

1. **Board.** Recompute the Merkle root and check the STH signature. Check consistency between every pair of STHs given.
2. **Manifest.** Check the signature (§7.3) and well-formedness (§7.2).
3. **Key ceremony.** Check all Round 1 proofs and signatures (§8.1). Check Round 3 acceptance by all *n* trustees with the same transcript hash. Check every complaint has a valid reveal. Recompute *K* and *Z*_j, and check *K* ≠ *O*. List every trustee's organisation and key fingerprints, and every party key fingerprint, so they can be compared with what the trustees and parties published themselves (§8).
4. **Context.** Recompute `context_hash`.
5. **Registry, software and freeze.** Check the registry signatures and rules (§7.7), the release records and signatures (§24), and the `polls_open` and `tally_cutoff` entries (§17.7). Report any `signed_registry` or `software_policy_update` after `polls_open` as board misbehaviour.
6. **Packages.** Apply every rule in §17.6 to every package and recovered package, including the zerésima, the checkpoints and the poll worker signatures on authorizations. Check every `observer_cert` against its party key. Check every `rejection` entry names a package that actually fails a rule. For each ballot, apply §12.6 (including α reservation), and list every excluded ballot and contest with its machine_id and the failing check.
7. **Completeness.** List every registered section and machine with no accepted package before `tally_cutoff`. List every pre-BU in a `section_attestation` whose package is missing, rejected or different (chain head or frame digest mismatch), every pair of different machine-signed pre-BUs for one session, every recovered package that no pre-BU imports, and every disagreement between recovered media. Check that each reserve machine serves one section only, with that section's poll worker keys and contests. For each section, check that its total cast ballots are at most the largest voter-roll count among its pre-BUs and recovered packages, and at most its eligible voters, and report every section where they aren't. Report, per section, whether any zerésima or pre-BU carries an observer signature, since sections without one rest only on EA-registered keys (§28.18).
8. **Spoiled ballots.** Check every reveal (§14.2) matches its ballot. Report mismatches with the machine ID.
9. **Homomorphic tally.** Recompute every `section_tally`, the `pool_tally` and the `encrypted_tally` at the `tally_cutoff` tree size, and compare them byte for byte. For each pre-BU, compare its fingerprint (field 14) with the recomputed section tally and report `match` or `mismatch`. Warn if the pool holds fewer than `min_section_ballots` ballots in any contest (§18.3).
10. **Mixnet.** For each mix unit (contest or link group, and region), check that the first input list is built per §19.1, that each mix step's input list equals the previous output, that every shuffle proof verifies, and that at least `min_mixers` distinct trustees mixed it.
11. **Decryption.** Verify every share set (§20.1), discard and report the ones that fail (§20.3), recombine from valid sets (§20.2), and recover each *m* (§20.4, §19.5).
12. **Final BUs.** Check every `final_bu` per §16.5: its section tally, the share proofs, the combined numbers, and its link to the pre-BU.
13. **Counts.** Recompute each contest's counts: homomorphic as the sum of the final BUs and the pool, mixnet per §19.6 summed over regions.
14. **Apportionment.** Recompute party totals and seats (§22).
15. **Result.** Compare the recomputed values with the published `result`.
16. **Independence report (§2.4).** Report what rests on the EA's word alone:
    - trustees, release signers and mirrors, each with organisation, bloc and key fingerprint, and the result of §7.2 rules 11–13,
    - sections whose zerésima and pre-BU carry no observer signature,
    - recommended independent parties that published nothing (no observer certificate, mirror tree head or trustee message).

The verifier crate MUST NOT depend on code used to produce ballots, packages or tallies. It implements this procedure from this document alone.

---

## 24. Software verifiability

### 24.1 Reproducible builds

Every release artifact MUST be reproducible: building the tagged source with the pinned toolchain produces byte-identical output. The reference build is the Nix flake in the repository. Releases MUST NOT be published until at least two independent builders report matching hashes.

### 24.2 Release record

```cddl
release = {
  0: "release", 1: 1,
  2: tstr,                       ; version, e.g. "0.1.0"
  3: tstr,                       ; source revision (git commit hash, hex)
  4: [+ artifact],
}
artifact = {
  0: "artifact",
  1: tstr,                       ; role: "machine" / "board" / "verifier" / "cli" / "wasm" / "ffi"
  2: tstr,                       ; target triple
  3: bstr .size 32,              ; SHA-256 of the artifact file bytes
}

release_signature = { 0: "release_sig", 1: 1, 2: digest, 3: ed25519pk, 4: ed25519sig }
  ; Digest("eg/v1/release", release), signer key, Sign(signer_sk, "eg/v1/sig/release", release)
```

### 24.3 Release log

Release records and signatures are appended to a **release log**. It has the same Merkle structure as §17.2 and its own signed tree heads, signed by the release log key. The release log is independent of any one election. The equivocation and mirror rules of §17.4 apply to it unchanged: mirrors fetch every release log STH, check consistency, and gossip. A release log showing different views to different parties would otherwise let a secret release slip through.

### 24.4 Software policy

```cddl
software_policy = {
  0: "software_policy",
  1: [+ release_signer],         ; release signers
  2: uint,                       ; k_r: signatures required on a release
  3: ed25519pk,                  ; release log key
  4: [+ bstr .size 32],          ; approved machine artifact hashes
  5: bool,                       ; attestation required
}

software_measurement = { 0: "measurement", 1: "sha256", 2: bstr .size 32 }
```

```cddl
release_signer = [ed25519pk, tstr, tstr]   ; key, organisation, bloc (§2.4)
```

A machine artifact hash is **approved** if it appears in field 4, or in a `software_policy_update` before `polls_open`, **and** the release log contains a release record listing it, carrying at least *k_r* valid signatures from distinct signers in field 1. The verifier needs an STH and inclusion proofs from the release log.

A bug-fix release must not force a new manifest and a new key ceremony, so the EA MAY add approved hashes before polls open:

```cddl
software_policy_update = {
  0: "software_policy_update", 1: 1,
  2: digest,                     ; context_hash
  3: [+ bstr .size 32],          ; additional approved machine artifact hashes
  4: [* bstr .size 32],          ; hashes withdrawn (no longer approved)
  5: ed25519sig,                 ; Sign(ea_sk, "eg/v1/sig/policy-update", fields 0..4)
}
```

Updates can only add releases that already carry *k_r* signatures in the release log, so the EA can't approve software on its own. No update is accepted after `polls_open` (§17.7).

### 24.5 Attestation

```cddl
attestation = {
  0: "attestation",
  1: "tpm2-quote",
  2: bstr,           ; TPMS_ATTEST quote
  3: bstr,           ; signature by the attestation key
  4: [+ [uint, bstr]],   ; PCR index, value
  5: bstr,           ; attestation key certificate chain (DER, concatenated)
  6: digest,         ; nonce, below
}
```

```
opening nonce = Digest("eg/v1/attest-nonce", context_hash, machine_id, session_id, opening_challenge)
closing nonce = Digest("eg/v1/attest-nonce-close", context_hash, machine_id, session_id, final chain head)
```

The opening nonce includes the poll terminal's random `opening_challenge` (§15.5). A quote therefore can't be obtained in advance, for example by booting honest software, quoting, and then rebooting into malicious software. The closing quote covers the whole session, so software swapped during voting is also caught.

v1 defines this format and how it is bound to packages (§16), but does not require it. If `software_policy.5` is true, verifiers MUST validate attestation and reject packages without it. The verification rules for TPM quotes (PCR policy and key certificate roots) will be specified with the TPM backend.

### 24.6 What this does and does not guarantee (informative)

- Reproducible builds plus *k_r* release signatures plus the log mean that the approved binary is the audited source, approved by several parties, and that no secret release exists.
- The measurement in the package says *which* binary the machine claims it ran. Only hardware attestation (TPM-sealed keys plus quotes) makes that claim trustworthy against compromised software.
- Integrity of the tally never depends on this section (§2.3). This section protects secrecy and helps catch problems early.
- Release signers come from several blocs, and none can approve alone (§7.2 rule 12), so software approval doesn't rest on the EA.

---

## 25. Keystore interface (informative)

Secret material sits behind interfaces, so that hardware backends can replace software ones.

- **Signer**: `public_key()`, `sign(tag, message)`. Used by machines, trustees, the EA, the board and release signers.
- **ShareHolder**: `index()`, `verification_key()`, `decryption_shares(board_dump, target)` checks the target per §20.5 and returns shares with proofs. It never accepts bare ciphertexts. The share *z*_j never leaves the implementation.
- **PollWorker**: `public_key()`, `sign_authorization(machine_id, session_id, auth_seq)`, `sign_cancellation(...)`, `sign_section_record(record_id)`. It runs on the poll terminal, never on the voting machine. Each poll worker's key SHOULD live on a personal token (smartcard or security key) that the poll worker brings and keeps, so that one compromised terminal can't sign as every poll worker.
- **Observer**: the same signing interface, on the observer's own device (an app that scans QR codes). It MUST show the decoded record before signing.
- All keys are generated inside the keystore that uses them (§7.7). Only public keys are exported.
- **DkgParticipant**: holds polynomial coefficients during the ceremony and erases them afterwards.
- **NonceVault**: `new_seed()` returns a handle, `derive(handle, contest, position)` returns *r*, `reveal(handle)` returns ρ (spoil), `erase(handle)` (cast or abandon). Erasure MUST overwrite the memory (`zeroize`).

The v1 software keystore stores keys in a file encrypted with a key derived from a passphrase (Argon2id, then ChaCha20-Poly1305). Its format is internal to the library and is not part of this protocol.

---

## 26. Adapter API (informative)

The C ABI and WASM adapters expose the same functions. Every function takes and returns deterministic CBOR byte strings. Secret material is held behind opaque handles (keystores, nonce vaults, journals). Errors are returned as `{ 0: "error", 1: tstr code, 2: tstr message }`.

| Function | Input | Output |
|---|---|---|
| `manifest_validate` | manifest | ok / error |
| `dkg_round1` / `dkg_round2` / `dkg_round3` | keystore handle, prior messages | message |
| `context_build` | manifest, ceremony messages | context |
| `ballot_encrypt` | context, machine state, selections | ballot, code |
| `session_open` / `zeresima` | machine state, opening challenge, poll worker signatures | zeresima record |
| `authorize` / `cancel_authorization` | machine state, signed authorization | ok / error |
| `ballot_cast` / `ballot_spoil` | machine state | slip / spoil receipt |
| `journal_open` / `journal_recover` | path or stream | handle |
| `package_build` | journal handle, keystore | package |
| `pre_bu_build` | journal handle, voter-roll count, imported recovered packages | pre_bu |
| `section_tally` / `pool_tally` | board dump, pre-BU or cutoff | section_tally / pool_tally |
| `section_sign` | record, poll worker or observer keystore | section_attestation |
| `observer_certify` | observer public key, party keystore | observer_cert |
| `journal_recover_package` | recovered journal, voter-roll count, poll worker signatures | recovered_package |
| `board_append` / `board_sth` / `board_inclusion` / `board_consistency` | board state | entries, proofs |
| `tally_homomorphic` | board dump | encrypted_tally |
| `mix_step` | input list, keystore | mix_output |
| `decrypt_shares` | board dump, target (section tally, pool or final mix list), keystore | decryption_share_set |
| `combine` | target, share sets | result |
| `apportion` | manifest, totals | seat_allocation |
| `verify_election` | board dump, STHs | report |
| `verify_inclusion` | code, STH, proof | ok / error |
| `check_spoiled` | spoil receipt, package, inclusion proof | claimed selections or mismatch |
| `check_final_bu` | pre-BU, final BU, packages or board dump | match / mismatch, with the failing check |

---

## 27. Test vectors

- Vectors live in `test-vectors/<area>/<name>.cbor`, with a JSON rendering next to each one for humans.
- All randomness is drawn from ChaCha20, seeded with `SHA-256("eg/v1/test-vector/" || name)`.
- In test-vector builds only, `Random()`, ρ and OS randomness are replaced by this generator.
- Each vector records its inputs, every intermediate value (commitments, challenges, responses) and its outputs.
- At minimum there are vectors for: manifest independence rules (accepted and rejected), zerésima, signed authorizations, checkpoints, slip reprint, reserve machine, recovered package and import (including a truncated one), observer revocation, region merging, pre-BU, section tally, final BU, observer certificate, section pooling, regional mix units, Schnorr, Chaum-Pedersen, disj01, sum proof, slot proof, shuffle proof (*N* = 1, 2, 5 and *w* = 1, 3), DKG with (*n*, *k*) = (3, 2) and (5, 3), ballot encryption for each contest kind and method, tracking code chain, journal framing, package, Merkle inclusion and consistency, decryption and combination, D'Hondt, and brazil-2021 (including the no-list-reaches-QE case and the final phase).
- An independent implementation is compatible if it reproduces every vector byte for byte.

---

## 28. Security considerations

1. **Weak Fiat-Shamir.** Every challenge MUST hash the full statement and context, as specified. Omitting any part allows forged proofs (Bernhard, Pereira and Warinschi, 2012, against Helios).
2. **Nonce reuse.** Proof nonces MUST be fresh. Two proofs with the same *u* and different challenges reveal the witness.
3. **Ballot copying and replay.** Ballot-bound proof contexts (§11) and α reservation (§12.6) stop an attacker from copying a voter's ciphertext to learn their vote through the tally (Cortier and Smyth, 2011).
4. **Clash attacks.** Chained codes that are unique per machine (§13.1) stop a machine from giving two voters the same receipt and stuffing the freed ballot.
5. **Constant time.** Code that handles secrets (encryption, proofs, shares) MUST use constant-time scalar multiplication. Variable-time multi-scalar multiplication is allowed only on public data in verification.
6. **Order linkage.** Ballots appear on the board in machine order. Secrecy relies on encryption plus the host rule that voter order and times are not recorded (§15.3). If *k* trustees collude, or the discrete log problem is broken in the future, order plus ciphertext could reveal votes. Everlasting privacy is out of scope for v1.
7. **Kleptographic machines.** A malicious machine can choose its "random" values so that they leak the vote to someone who knows a secret, for example by biasing ρ. Benaloh audits do not detect this. Mitigations include certified hardware random generators, attestation, and (in a future version) randomness contributed by an independent device. This is an acknowledged open risk.
8. **Covert channels.** A malicious machine could leak votes through timing, radio or storage outside the journal. These are physical and procedural controls, outside this protocol.
9. **Identity element and invalid points.** All decoders reject non-canonical encodings, and α = *O* is rejected (§10.1). Ristretto255 has prime order, so there are no small-subgroup attacks.
10. **Denial of service.** A malicious trustee can abort the key ceremony (§8.4) or refuse to decrypt. The threshold *k* < *n* tolerates *n* − *k* absent trustees at decryption time.
11. **Discrete log bound.** Tallies are bounded by the number of counted ballots (§20.4). A failed search signals a bug or an attack and MUST stop the process.
12. **Quantum computers.** A large quantum computer would break secrecy for every published ciphertext, retroactively, and would break the soundness of future proofs. Integrity of past elections, already verified, is unaffected.
13. **Spoiled ballots next to cast ballots.** A spoiled reveal sits in the chain directly before the same voter's cast ballot, and voters often audit their real choice. Anyone who knows which voter took extra time at the booth can guess that voter's vote. Voters must be told that spoiled choices become public, and observer audit-only sessions are preferred (§14.3).
14. **Pattern voting in mixnet rows.** Mixnet rows are decrypted one by one. In a wide mix unit (large *L*, or a link group over many candidates), a coercer can demand an unusual combination of choices and look for it in the output (the "Italian attack"). Keep mix units narrow. For Brazil (one `single` contest, or two linked senator contests), the number of combinations is small compared with the number of voters.
15. **Selective invalidation.** A machine knows each plaintext, so it can attach bad proofs only to votes for one candidate. Those contests are excluded (§12.6), but the exclusion is public per section (§21), attributable to the machine, visible to the affected voter's lookup (§17.5), and makes the section's pre-BU fingerprint mismatch the section tally recomputed from the board (§18.1).
16. **Human attestation.** The zerésima and pre-BU protections rely on at least one honest poll worker or observer per section who checks the QR code with an independent device and keeps a copy. A section where every poll worker colludes with the EA and no observer is present can fake its voter-roll count, up to the section's registered eligible voters.
17. **Poll terminal compromise.** Authorization keys are used on the poll terminal. A compromised terminal colluding with a malicious machine can authorize extra ballots, but the cast count then exceeds the voter-roll count on the paper pre-BU, unless the poll worker entering that count also colludes. Personal tokens (§25) limit what a compromised terminal can sign.
18. **EA-provisioned keys.** If the EA generated or kept the machine and poll worker keys, it could forge a complete, validly signed package, zerésima and pre-BU for a section. Key generation inside devices (§7.7) prevents this by construction. Party-certified observer signatures (§16.3) and paper copies detect it otherwise. The verifier reports which sections carry an observer signature (§23 step 7).
19. **Cost of homomorphic proportional contests.** A proportional contest with *m* options costs *m* encryptions and *m* disj01 proofs per ballot (about 1,500 for a large state's deputies). It also costs *m* decryptions per section and *k* share proofs for each of them, across about 470,000 sections nationally. Machines must be benchmarked for ballot encryption time, and batched decryption proofs (§29) are a priority for national scale.
20. **CAST relabelled as spoiled.** A machine could record a voter's CAST as `spoiled`. That publishes the voter's choice and frees the authorization, which the machine can use for a fake ballot before the next voter is authorized (§15.4). The voter's signed slip, together with the code lookup that reports the status `spoiled`, is proof of misbehaviour (§13.3, §17.5). This attack is detected only if voters check their codes.

---

## 29. Open issues

- Continuing the key ceremony with a qualified subset after a disqualification (§8.4).
- Batched decryption proofs, using random linear combinations, for large mixnet lists and for per-section homomorphic subtotals. This is a priority for national scale (§28.19).
- Choice of the default `min_section_ballots` and of the regions used for mixing, with their privacy trade-offs (§18, §19.1).
- Verification rules for TPM quotes (§24.5).
- Everlasting privacy, using commitment-based publication.
- Legal review of the `brazil-2021` rule (§22.3), including the art. 111 case.
- Legal review of the zerésima, pre-BU and final BU mapping (§15.5, §16.2, §16.5) against current TSE resolutions. In particular, the paper printed at the section carries no per-candidate numbers, and per-section results appear only as final BUs on the board. Also: what number of excluded ballots in a section triggers annulment (§21).
- Trustee decryption services for election-night final BUs: operation, HSM requirements and rate limits (§16.5, §20.5).

---

## Appendix A: Domain-separation tags

| Tag | Used in |
|---|---|
| `eg/v1/gen` | §5.2 |
| `eg/v1/manifest` | §7.3 |
| `eg/v1/sig/manifest`, `eg/v1/sig/registry` | §7.3, §7.7 |
| `eg/v1/record-id` | §15.5 |
| `eg/v1/dkg-share` | §5.5 |
| `eg/v1/sig/dkg1`, `eg/v1/sig/dkg2`, `eg/v1/sig/dkg3`, `eg/v1/sig/dkg-complaint`, `eg/v1/sig/dkg-reveal` | §8 |
| `eg/v1/dkg-transcript` | §8.5 |
| `eg/v1/context` | §9 |
| `eg/v1/schnorr`, `eg/v1/cp`, `eg/v1/disj01` | §11 |
| `eg/v1/nonce` | §12.2 |
| `eg/v1/ballot`, `eg/v1/code`, `eg/v1/chain`, `eg/v1/chain-start`, `eg/v1/reveal` | §13 |
| `eg/v1/sig/slip` | §13.3 |
| `eg/v1/journal`, `eg/v1/sig/auth`, `eg/v1/sig/auth-cancel` | §15 |
| `eg/v1/sig/zeresima`, `eg/v1/sig/section`, `eg/v1/sig/checkpoint` | §15, §16.3 |
| `eg/v1/sig/observer-cert`, `eg/v1/sig/observer-revoke` | §16.3 |
| `eg/v1/sig/spoil` | §14.1 |
| `eg/v1/sig/package`, `eg/v1/sig/pre-bu` | §16 |
| `eg/v1/subtotal` | §18.1 |
| `eg/v1/leaf`, `eg/v1/node`, `eg/v1/empty`, `eg/v1/sig/sth` | §17 |
| `eg/v1/sig/rejection` | §17.6 |
| `eg/v1/sig/polls-open`, `eg/v1/sig/tally-cutoff` | §17.7 |
| `eg/v1/shuffle-u`, `eg/v1/shuffle`, `eg/v1/mix-list`, `eg/v1/sig/mix` | §19 |
| `eg/v1/sig/shares` | §20 |
| `eg/v1/sig/result` | §21 |
| `eg/v1/release`, `eg/v1/sig/release` | §24.2 |
| `eg/v1/sig/policy-update` | §24.4 |
| `eg/v1/attest-nonce`, `eg/v1/attest-nonce-close` | §24.5 |
| `eg/v1/test-vector/` | §27 |

## Appendix B: Shuffle proof algebra

Using the definitions of §19.3, with an honest prover:

**T1.**
```
Σ_j c_j − Σ_i H_i = Σ_i (ρ_{π(i)}·B + H_i) − Σ_i H_i = ρ̄·B = c̄
s1·B − c·c̄ = (ω_1 + c·ρ̄)·B − c·ρ̄·B = ω_1·B = T1
```

**Chain.** By induction, ĉ_N = ρ̂·B + (∏_i u'_i)·H, with ρ̂ = Σ_i ρ̂_i·v_i. Since π is a permutation, ∏ u'_i = ∏ u_j, so ĉ = ĉ_N − (∏ u_j)·H = ρ̂·B, and:
```
s2·B − c·ĉ = ω_2·B = T2
```

**T3.**
```
c' = Σ_j u_j·c_j = Σ_i u'_i·(ρ_{π(i)}·B + H_i) = ρ'·B + Σ_i u'_i·H_i
s3·B + Σ_i s'_i·H_i − c·c' = ω_3·B + Σ_i ω'_i·H_i = T3
```

**T4** (component *k*, α side; the β side is identical with *K* in place of *B*).
```
Σ_i u'_i·α̃_i[k] = Σ_i u'_i·(α_{π(i)}[k] + r̃_{i,k}·B) = α'[k] + r̃[k]·B
−s4[k]·B + Σ_i s'_i·α̃_i[k] − c·α'[k]
  = −ω_4[k]·B + Σ_i ω'_i·α̃_i[k] + c·( −r̃[k]·B + Σ_i u'_i·α̃_i[k] − α'[k] )
  = T4α[k] + 0
```

**T̂_i.**
```
ŝ_i·B + s'_i·ĉ_{i−1} − c·ĉ_i
  = ω̂_i·B + ω'_i·ĉ_{i−1} + c·( ρ̂_i·B + u'_i·ĉ_{i−1} − ĉ_i )
  = T̂_i + 0
```

Soundness (that an accepting proof implies a valid shuffle, with overwhelming probability) is proved in Terelius and Wikström, "Proofs of Restricted Shuffles" (AFRICACRYPT 2010), and in Wikström, "A Commitment-Consistent Proof of a Shuffle" (ACISP 2009).

## Appendix C: References

- RFC 2119, RFC 8032 (Ed25519), RFC 8610 (CDDL), RFC 8949 (CBOR), RFC 9162 (Certificate Transparency v2), RFC 9180 (HPKE), RFC 9496 (Ristretto255).
- ElectionGuard Design Specification v2.0, Microsoft (structure and ballot design reference).
- J. Benaloh, "Simple Verifiable Elections" (EVT 2006) and "Ballot Casting Assurance via Voter-Initiated Poll Station Auditing" (EVT 2007).
- R. Cramer, I. Damgård, B. Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols" (CRYPTO 1994).
- D. Chaum, T. Pedersen, "Wallet Databases with Observers" (CRYPTO 1992).
- T. Pedersen, "A Threshold Cryptosystem without a Trusted Party" (EUROCRYPT 1991); P. Feldman, "A Practical Scheme for Non-interactive Verifiable Secret Sharing" (FOCS 1987).
- R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin, "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems" (EUROCRYPT 1999; J. Cryptology 2007), and "Secure Applications of Pedersen's Distributed Key Generation Protocol" (CT-RSA 2003).
- B. Terelius, D. Wikström, "Proofs of Restricted Shuffles" (AFRICACRYPT 2010).
- R. Haenni, P. Locher, R. Koenig, E. Dubuis, "Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets" (FC 2017 Workshops).
- D. Bernhard, O. Pereira, B. Warinschi, "How Not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios" (ASIACRYPT 2012).
- V. Cortier, B. Smyth, "Attacking and Fixing Helios: An Analysis of Ballot Secrecy" (CSF 2011).
- R. Küsters, T. Truderung, A. Vogt, "Clash Attacks on the Verifiability of E-Voting Systems" (IEEE S&P 2012).
- Brazil: Código Eleitoral (Lei 4.737/1965) arts. 106–112; Lei 14.211/2021; STF ADIs 7228, 7263, 7325.
