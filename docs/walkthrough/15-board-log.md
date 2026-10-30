# 15 · The bulletin board log: Merkle trees, signed tree heads and the signed board records

**Code:** `crates/eg-core/src/board.rs`. **Spec:** §17 (bulletin board: entries, Merkle tree, signed tree head, equivocation, voter lookup, package ingestion, polls open and tally cutoff). §15.5 names records with `RecordId`. §23 is the verifier that checks all of this.

**Scope of this file.** `board.rs` gives the primitives: the log, the proofs, the signed tree head, the equivocation check, and the three small signed records (`polls_open`, `tally_cutoff`, `rejection`). It does **not** decide which packages to accept (§17.6) or enforce the cutoff size (§17.7). Those belong to the board service and the verifier, and neither is in `eg-core` yet. This file says what the primitives can prove, and the spec sections say what the rest must do with them.

## The problem

The bulletin board is the public log of the election. Every manifest, registry, package (one machine's record of a voting session), tally and result is an entry, in order. Three properties matter:

1. **Anyone can check that an entry is in the log**, without downloading the whole log. A voter should be able to check their own ballot's package against a short summary.
2. **Anyone can check that the log only grows.** The board must not be able to rewrite or remove an entry it published earlier.
3. **Everyone sees the same log.** The board must not show one version to the voter and another to the observers.

A **Merkle tree** gives (1) and (2) with a single short fingerprint of the whole log. A **signed tree head** lets the board commit to that fingerprint. **Mirrors** (independent copies run outside the EA's bloc, file 12) give (3).

## Merkle trees, from scratch

Start with four entries, `d0`, `d1`, `d2`, `d3`. (The spec names them *entries*, which are CBOR records.)

**Step 1: hash each entry as a leaf.** The leaf hash is `leaf_hash(d) = Digest("eg/v1/leaf", d)`. Call these `h0`, `h1`, `h2`, `h3`.

**Step 2: pair the leaves, and hash the pairs.** A node is `node_hash(L, R) = Digest("eg/v1/node", L, R)`, which keeps left and right apart.

```
n01 = node(h0, h1)          n23 = node(h2, h3)
```

**Step 3: hash the two pairs.**

```
root = node(n01, n23)
```

Picture it as a tree:

```
                 root
               /      \
            n01        n23
           /   \      /   \
          h0   h1    h2   h3
          |    |     |    |
          d0   d1    d2   d3
```

The **root** is 32 bytes. It depends on every entry and on their order. Change `d1`, and `h1`, `n01` and the root all change. Swap `d0` and `d1`, and the root changes too.

For a log of any size *n*, the spec uses the RFC 9162 shape (Certificate Transparency v2). Split *n* entries at the largest power of two *k* below *n*, hash each side, and combine the two results. With three entries, `k` = 2:

```
root3 = node( node(h0, h1), h2 )
```

With five entries, `k` = 4, the first four form a complete tree, and the fifth sits alone at the right. This shape is what makes the log grow without rebuilding old subtrees, which is what consistency proofs rely on.

The empty log has a fixed root, `Digest("eg/v1/empty")`, and a one-entry log has the root `leaf_hash(d0)`.

## Inclusion proofs (§17.2, RFC 9162 §2.1.3)

**The question.** Is entry `d2` in this log of four entries, with root `R`?

**The proof.** The prover gives the verifier the hashes of the siblings along the path from `h2` to the root. For `d2`, the siblings are `h3` (its neighbour) and `n01` (the other half). That is two hashes, `[h3, n01]`.

**The check.** The verifier starts from `h2`, which it computes itself from `d2`:

```
r = h2
r = node(r, h3) = n23         (h3 is h2's neighbour, on the right)
r = node(n01, r) = root       (n01 is the left half, so it goes on the left)
accept iff r == R
```

The verifier never needs the other entries. The proof is about `log₂ n` hashes long. For 150 million entries that is about 28 hashes, roughly 900 bytes.

The verifier in `verify_inclusion` works from the proof, the leaf hash, the index, the size and the root alone. It never rebuilds the tree.

### The size matters

`inclusion_wrong_size_can_collide` (in the tests) shows a subtle point. The three-entry log's proof for entry 0 also verifies against a size-4 root computation. The proof itself does not bind the tree size, so **the verifier must take the size from the signed tree head** (below), never from the proof. A proof of "entry 0 is in a log of size 3" is only meaningful with size 3.

## Consistency proofs (§17.2, RFC 9162 §2.1.4): why "append-only" can be checked

**The question.** The board showed the verifier a signed tree head with size 2 and root `R2`. Later it shows size 4 with root `R4`. Did it only add entries, or did it rewrite the first two?

**The proof.** For the old tree of two entries, the root is `n01`. The new tree of four has the same left half, `n01`, followed by `n23`. The consistency proof from size 2 to size 4 is just `[n23]`.

**The check.** The verifier takes the old signed root `R2` (which is `n01`), combines it with the proof value `n23`, and asks whether the result is the new signed root:

```
node(R2, n23) == R4          accept
```

Here is the point. If the board had changed `d0` after publishing `R2`, then `n01` would be different. The old root `R2` would no longer be the left half of any tree that the board could show with the same `n23`. To get a consistent-looking proof, the board would need two different leaf sets that hash to the same node, which means finding a hash collision.

So "append-only" is not a promise. It is a claim the verifier can check against signed roots.

`verify_consistency` implements the RFC 9162 algorithm, including its special case: when the old size is an exact power of two, the old root is put at the front of the proof.

## Signed tree heads (§17.3)

A **signed tree head** (STH) is the board's signed statement of the log's state:

```
sth = { 0: "sth", 1: 1, 2: manifest_hash, 3: size, 4: root, 5: timestamp, 6: Sign(board_sk, "eg/v1/sig/sth", fields 0..5) }
```

It names the election (`manifest_hash`), how many entries the log has (`size`), the root, and a time. The signature is by the board key (`board_pk` in the manifest, file 12).

**The lookup in practice (§17.5).** A voter's client fetches the STH from the board **and** from at least one mirror outside the EA's bloc, checks they agree (or are consistent), then fetches the inclusion proof for its package, and checks it against the STH's size and root. It never needs the whole log.

## Equivocation (§17.4)

**Equivocation** is the board showing two different versions of the log. Two cases:

1. **Same size, different roots.** Two valid STHs signed by the board say "there are 10 entries" but give different roots. That is a fork, and both signatures are the board's.
2. **Inconsistent.** Two STHs of different sizes, with no valid consistency proof between them. The later one cannot contain the earlier one.

Either one is **proof of misbehaviour**, because the board signed both. `check_sth_pair` returns `SameSizeDifferentRoots` or `Inconsistent` in these cases, and `None` if the pair is consistent. It does not check the signatures; the caller passes STHs that came through `Sth::from_signed`.

Mirrors must fetch every STH, check consistency with the previous one, and swap STHs with other mirrors (§17.4). A fork is only visible if somebody holds both versions. Mirrors are the people who do.

## Signed records: `RecordId`, `polls_open`, `tally_cutoff`, `rejection`

### `RecordId` and the leaf hash

Two different hashes of the same record, with different tags:

- `leaf_hash(entry) = Digest("eg/v1/leaf", entry)` is what the tree stores.
- `record_id(record) = Digest("eg/v1/record-id", record)` is the name other records use. It covers the whole record, including its signature field (§15.5).

The two tags keep them apart. A record's name is never confused with its position in the tree. The test `record_id_differs_from_leaf_hash` checks this.

### `polls_open` (§17.7, signed by the EA)

```
polls_open = { 0: "polls_open", 1: 1, 2: context_hash, 3: registry_id, 4: time, 5: Sign(ea_sk, "eg/v1/sig/polls-open", …) }
```

It freezes the **registry** in force: `registry_id` is the `RecordId` of the `signed_registry`. After it, the board must refuse any new `signed_registry` or `software_policy_update`. Without this freeze the EA could add a machine, or a poll worker key, while voting was underway. Every package is then judged against the one registry in force when polls opened.

### `tally_cutoff` (§17.7, signed by the EA)

```
tally_cutoff = { 0: "tally_cutoff", 1: 1, 2: context_hash, 3: time, 4: Sign(ea_sk, "eg/v1/sig/tally-cutoff", …) }
```

It fixes the **set of packages to be tallied**: exactly those accepted before it. The tallies are computed at the tree size just before the cutoff, and a verifier rejects any tally computed at another size. (The tally records that size as `tree_size` in `tally.rs`, which is outside this set of walkthroughs.)

This is why the cutoff must be a point in the log, not a time on a clock. Without it, the EA could count the packages it likes best, or add packages after seeing partial results. With it, the set is fixed and public.

At the cutoff, the verifier lists every registered section and machine with no accepted package, and every pre-BU attestation whose package is missing (§17.7). The EA can't quietly choose which packages count.

### `rejection` (§17.6, signed by the board)

```
rejection = { 0: "rejection", 1: 1, 2: package_id, 3: reason, 4: Sign(board_sk, "eg/v1/sig/rejection", …) }
```

A board that refuses a package must publish this record with the reason. `package_id` is the `RecordId` of the refused package. The point is that **a dropped package is visible**. Without the rule, a board could silently refuse a voter's package and nobody would know why. The verifier then compares pre-BU attestations (observers' copies of the section's results) against what the board accepted, and reports any package that is missing, rejected or different.

## Why the package rules are not in this file

Section 17.6 lists nine rules a board must check before appending a package: the order against `polls_open` and `tally_cutoff`, the machine's signature under the frozen registry, the context hash, the software measurement, the journal framing, the zerésima, the invariants of §15.4, the rule that ballot-proof failures do **not** reject a package, and the session limit. These are checks on package content, and they are the job of the board service and the verifier. `board.rs` has the signed records they use, but none of the rules themselves.

One rule is worth noting here. Ballot-proof failures do **not** reject a package (§17.6 rule 8). Rejecting it would throw away every honest voter's ballot on that machine. The package stays, the bad ballots are excluded, and the package is evidence against the machine (file 13).

## The code, function by function

| function | what it does | why |
|---|---|---|
| `fields` | turns `(key, value)` pairs into the list `sign_record` takes | keeps each signed record's layout in one place |
| `record_id` | `Digest("eg/v1/record-id", record)` | names a record, including its signature |
| `leaf_hash` | `Digest("eg/v1/leaf", entry)` | the tree's leaves |
| `node_hash` | `Digest("eg/v1/node", L, R)` | the tree's interior nodes; order matters |
| `empty_root` | `Digest("eg/v1/empty")` | the root of an empty log |
| `largest_pow2_below` | the largest power of two strictly below *n* | the RFC 9162 split point |
| `mth` | the tree hash of a list of leaves (recursive) | the root and every subtree |
| `path` | the inclusion proof for leaf *m* (RFC 9162 PATH) | builds `inclusion_proof` |
| `subproof` | the consistency proof (RFC 9162 SUBPROOF) | builds `consistency_proof` |
| `Log` (`new`, `append`, `len`, `is_empty`, `entry`, `entries`) | the in-memory log: each entry and its leaf hash | the board's storage, for tests and reference use |
| `Log::root_at` | the root of the first *size* entries; panics if *size* is larger than the log | the root of any earlier state, for consistency checks |
| `Log::root` | the root of the whole log | the current state |
| `Log::inclusion_proof` | the proof for entry *index* in a tree of *size*; `None` if out of range | what a voter fetches |
| `Log::consistency_proof` | the proof from *old_size* to *new_size*; `None` if out of range | what a mirror fetches |
| `lsb` | is the least significant bit set | used by the RFC 9162 verifier |
| `verify_inclusion` | checks an inclusion proof from the proof alone (RFC 9162 §2.1.3.2) | the voter's check; never rebuilds the tree |
| `verify_consistency` | checks a consistency proof from the proof and the two roots (RFC 9162 §2.1.4.2) | the mirror's check, and the basis of "append-only" |
| `Sth::sign`, `Sth::from_signed` | the §17.3 record; `from_signed` verifies the board's signature | the board's commitment |
| `check_sth_pair` | same size with different roots, or no valid consistency proof, is equivocation | the mirror's cross-check (§17.4) |
| `PollsOpen::sign`, `from_signed` | the §17.7 record, signed by the EA | freezes the registry |
| `TallyCutoff::sign`, `from_signed` | the §17.7 record, signed by the EA | fixes the tallied packages |
| `Rejection::sign`, `from_signed` | the §17.6 record, signed by the board | makes a refused package visible |

Two notes on the design of `Log`. It stores every entry, and each call to `root_at` recomputes the tree from the leaves, so it is a reference implementation for correctness, not a storage design. And the proofs are built from the stored leaves, so they are only correct for the log they were built from.

## Design choices

- **RFC 9162, not a new Merkle design.** Certificate Transparency's tree has been studied and deployed, and its proofs have known, tested verification algorithms. The spec reuses them, with this spec's hash tags.
- **Verification uses the proof alone.** The verifier never needs the other entries. A voter checking one ballot downloads a few hundred bytes, not the log.
- **Domain tags on every hash.** `leaf`, `node`, `empty`, `record-id`, `sth`, and the signature tags are all distinct. A leaf hash can't be mistaken for an interior node, and a signed STH can't be replayed as a signed rejection.
- **Size is taken from the signed head.** The proof doesn't carry its size, so the verifier takes it from the STH (see the collision test above).
- **Signed records are small and fixed.** `polls_open`, `tally_cutoff` and `rejection` each have a handful of fields and one signature. Each is checked by one key, the EA's or the board's, so the reader knows who is answerable.
- **Cutoff is a log position.** `tally_cutoff` is an entry in the log, not a time. It fixes the set by position, so no one can argue about which packages arrived in time.
- **Freeze before voting, not after.** Refusing `signed_registry` after `polls_open` means the registry can't move during voting.

## Attacks each check prevents

| attack | what stops it |
|---|---|
| board rewrites an earlier entry | a consistency proof fails against the signed root |
| board shows different logs to different people | two STHs with the same size and different roots: equivocation |
| board shows an inconsistent later log | no valid consistency proof: equivocation |
| board hides an entry from a voter | the voter's inclusion proof fails, and the mirror's STH disagrees |
| board silently refuses a package | `rejection` must be published; observers' pre-BU reveals a missing package |
| EA changes the registry during voting | `polls_open` freezes it; later `signed_registry` is refused |
| EA picks which packages count after seeing results | `tally_cutoff` fixes the set by log position |
| a proof for one log used on a different size | the verifier takes the size from the signed STH |
| a leaf hash passed off as a record name (or the reverse) | different domain tags for `leaf` and `record-id` |
| a record signed as one type and presented as another | separate signature tags for each record type |

## Tests (21)

- **Merkle basics:** the empty root matches its definition; one leaf's root is its leaf hash; a three-leaf root computed by hand.
- **Inclusion:** proofs verify for every size and index (up to 20 entries); the wrong size can collide (see above); an out-of-range index or size gives `None`.
- **Consistency:** proofs verify for every pair of sizes; power-of-two old sizes take the special path; the edge cases (equal sizes, empty old log).
- **Prefix roots:** `root_at` matches the root of a shorter log; asking beyond the length panics.
- **Signed tree head:** sign and verify; a wrong key fails; a tampered root fails.
- **Equivocation:** same size with different roots is detected; a consistent pair is not equivocation; an inconsistent pair is.
- **Signed records:** `polls_open`, `tally_cutoff` and `rejection` each round-trip, and a wrong key fails.
- **`record_id` vs leaf hash:** the two differ, as required.

## Spec gaps relevant here

- **§17.2 and the test above:** the spec doesn't say that inclusion verification needs the size from the signed head. The code's test documents it, and callers must follow it.
- **§17.6 and §17.7:** the ingestion rules and the cutoff size check are the board service's and verifier's job. Nothing in `eg-core` implements them yet.
- **Spec issue 9 (verifier independence):** §23 wants a verifier that doesn't share code with the producers. The verifier that reuses the primitives in this file depends on those primitives being right, which is why their tests check the RFC 9162 cases one by one.
