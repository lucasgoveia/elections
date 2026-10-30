# 12 · The manifest, the machine registry and the sample election

**Code:** `crates/eg-core/src/manifest.rs`, `crates/eg-core/src/registry.rs`, `crates/eg-core/src/fixtures.rs`. **Spec:** §7 (manifest, rules, registry), §2.4 (independence from the election authority).

## The problem

Before a single vote is cast, everyone has to agree on four things:

1. **What the election is**: which contests exist, what options are on each, how many seats, which counting method.
2. **Who holds the decryption key**: which trustees, how many of them are needed, and whether any single group of them could open ballots alone.
3. **Who can sign what**: which people can approve software, and which keys belong to the voting machines, poll workers and observers.
4. **Which machine serves which section**: a voter in section S1 must not be able to vote on a machine that the registry doesn't list for S1.

The **manifest** (§7.1) is the public rulebook for (1) and (2). The **machine registry** (§7.7) is the public list for (3) and (4). The election authority (EA) signs both. Every later record names them by hash, so nothing can quietly be swapped.

The main risk is that the EA is the party with the most power. Section 2.4 of the spec says that where code can enforce a rule, it must. So each rule below is a check that a program runs, not a sentence in a policy document.

## The idea, without math

- The **manifest** is the ballot paper written as data, plus rules about what a valid ballot paper looks like.
- The **manifest hash** is its fingerprint. Ballots, tree heads and tallies all carry it, so a result computed for one manifest can't be presented as the result of another.
- **Validation** is a yes-or-no function over the manifest. When it says no, it names the first rule broken, for example `rule 11: bloc "TSE" holds 2 trustee shares, k = 2`.
- The **registry** says which machines exist, which section each one serves, and which poll worker and observer keys are allowed. It can be replaced by a later version, but only until polls open (§7.7 and §17.7). After that the registry is frozen.

## The manifest rules (§7.2)

The spec numbers the rules 1 to 13. The code keeps those numbers in its error messages. The function column shows where each rule is checked.

| rule | requirement | checked in |
|---|---|---|
| 1 | contest indices are 0..C−1 in order, option indices 0..m−1 in order | `check_contest` |
| 2 | option kinds fit the contest kind: single has a candidate and at most one blank and one null, no party; multi has a candidate, at most one null, no party or blank, and 1 ≤ L ≤ candidates; proportional has `party_index` on every candidate and party option, and at most one party option per party | `check_option_kinds` |
| 3 | single and proportional contests have L = 1 | `check_contest` |
| 4 | each party is in at most one federation | `check_parties_and_federations` |
| 5 | display numbers are unique within a contest | `check_contest` |
| 6 | a mixnet contest has options + 1 < 2²⁰ (the lookup-table bound, §19.5) | `check_contest`, `mixnet_size_ok` |
| 7 | a link group's contests are single or multi, share kind, method and option list, and each contest is in at most one group | `check_link_groups` |
| 8 | k ≤ `min_mixers` ≤ n, and `min_region_rows` ≥ 1 | `check_mix_policy` |
| 9 | regional mixing only on mixnet contests, and the same inside a link group | `check_contest`, `check_link_groups` |
| 10 | `min_section_ballots` ≥ 1 | `validate` |
| 11 | for every bloc, fewer than k trustees; trustee signing keys and HPKE keys each used once | `check_trustee_independence` |
| 12 | 1 ≤ k_r ≤ number of signers; signer keys distinct; fewer than k_r signers per bloc | `check_signer_independence` |
| 13 | at least two mirrors have a bloc different from the EA's bloc | `validate` |

The code also checks some structural rules the spec states without a number: at least one contest, at least two mirrors, 2 ≤ k ≤ n, trustee indices 1..n in order, party and federation indices equal their positions, and, for proportional contests, a distinct `tiebreak_rank` per candidate (§22.5). The last one matters because ties in seat allocation are settled by these ranks, so two candidates sharing a rank would make the result undefined.

## The registry rules (§7.7)

`Registry::validate` checks these against the manifest:

- `manifest_hash` is the hash of this manifest, and `registry_version` ≥ 1;
- machine ids are unique; section ids are unique and not empty (`""` is reserved for reserve machines);
- every machine's section exists, or is `""` (a reserve machine);
- every machine offers at least one contest, in strictly ascending order, each one a real contest of the manifest;
- a machine offers **all or none** of each link group (§7.5);
- every section has at least one machine that isn't a reserve machine;
- `max_sessions` ≥ 1;
- machine keys, poll worker keys and observer keys are pairwise disjoint, and no key appears twice.

Reserve machines are only partly checked here. Their offered contests must equal those of the section they will serve, but the binding happens on polling day, so that check runs at package ingestion (spec issue 10).

## Why bloc labels (§2.4)

Many voters don't trust the election authority. In Brazil that is the TSE, which also runs the election. The decryption key is split among trustees (file 10). If the EA could gather enough trustees to decrypt on its own, it could read ballots, so the protocol needs a rule about who sits on the trustee set.

Each trustee carries a **bloc** label: a text tag such as `"TSE"`, `"OAB"`, `"university"` or `"party:13"`. Rule 11 says that no bloc may hold *k* or more trustees.

**Toy example.** Take n = 3 trustees and threshold k = 2, so any 2 trustees can decrypt.

| trustee blocs | valid? | why |
|---|---|---|
| TSE, OAB, university | yes | each bloc has 1 < 2 |
| TSE, TSE, OAB | no | TSE has 2 = k, so the TSE alone can decrypt |

With k = 2, the test "fewer than k per bloc" means that no single bloc can decrypt alone. Decryption needs trustees from at least two blocs. That is the whole point of the label.

The EA's own bloc is a separate field (manifest field 14). Rule 13 then requires two mirrors (the public copies of the bulletin board, §17.5) that are outside that bloc. Voters check the board against one of them, so the board can't hide entries from every independent source.

**Labels are claims.** The EA writes them, so it could give an ally a neutral-looking label. The protocol does not prevent that. It makes the label **public**: every label is printed beside the organisation's name and key fingerprint in the verifier report (§23, step 16), where anyone can challenge it. The rule is enforced by the code, and the honesty of the label is left to public scrutiny.

## Why distinct trustee keys

Rule 11 also requires that no two trustees share a signing key or an HPKE key. The reason is that a bloc count is only meaningful if each count is a different person. If one key holder were listed twice, under `"TSE"` and under `"OAB"`, they would hold two shares while the bloc counts looked fine. Two copied keys would defeat the arithmetic completely.

The same logic applies to signers (rule 12 requires distinct signer keys) and to registry keys (the disjointness check).

**What the check does not catch.** It catches a key entered twice. It does not catch one organisation that generates two different keys and registers them under two labels. The bloc label, public and challengeable, is the defence against that. The key check is there to stop the cheapest mistake, a copy-paste.

## The code, function by function

### `manifest.rs`

| function | what it does | why |
|---|---|---|
| `Manifest::to_value` | encodes the §7.1 map, fields 0 to 15 | one exact byte form, so the hash is stable |
| `Manifest::from_value` | strict decode: wrong type, wrong tag, wrong version or unknown key is an error | a field that is silently ignored could carry meaning the EA intended, so decoding is strict |
| `Manifest::hash` | `Digest("eg/v1/manifest", manifest)` | the fingerprint every later record names |
| `Manifest::contest` | the contest with a given index | index lookup by value, since positions are checked to match |
| `Manifest::validate` | runs all the checks below in order and returns the first failure | one call answers "is this a well-formed election?" |
| `check_structure` | non-empty lists, mirror count, signer count, 2 ≤ k ≤ n, trustee and link-group indices | cardinalities the CDDL states without a rule number |
| `check_parties_and_federations` | rule 4, and party and federation indices | positions double as ids |
| `check_contest` | rules 1, 3, 5, 6, 9 (local part), and apportionment fields present iff proportional | one contest in isolation |
| `check_option_kinds` | rule 2, plus distinct `tiebreak_rank` for proportional candidates | the option rules differ by contest kind |
| `check_link_groups` | rule 7 and the regional-mixing part of rule 9 | a link group is a promise about every contest in it |
| `check_mix_policy` | rule 8 | ties the "at least one honest mixer" assumption to k |
| `check_trustee_independence` | rule 11: unique keys, then fewer than k per bloc | the bloc count is only meaningful with distinct keys |
| `check_signer_independence` | rule 12 | the same count, for software approval |
| `bloc_counts` | counts trustees or signers per bloc label | helper for rules 11 and 12 |
| `mixnet_size_ok` | rule 6: options + 1 < 2²⁰ | the bound the lookup table of §19.5 depends on, kept in one helper so the test can pin it |
| `check_option_kinds` (party part) | `party_index` must name a real party | a candidate of a party that doesn't exist can't be apportioned |
| `sign_manifest` | builds `{0: "signed_manifest", 1: manifest, 2: Sign(ea_sk, "eg/v1/sig/manifest", …)}` | the EA's signature, the first board entry (§7.3) |
| `open_signed_manifest` | decodes, **verifies the signature**, then validates | a signature proves who wrote it, validation proves it's sound; both are needed |
| `rule`, `structure` | build the error messages `rule N: …` and `structure: …` | every error names the rule it broke |
| `ApportionmentRule::to_value`/`from_value` | the `dhondt` and `brazil-2021` parameter maps | the rule's parameters are data, so they can change without changing code |

### `registry.rs`

| function | what it does | why |
|---|---|---|
| `Registry::to_value` / `from_value` | the §7.7 map; strict decode | as for the manifest |
| `Registry::validate` | the registry rules above | checks the registry against one manifest |
| `Registry::check_machine_contests` | non-empty, ascending, real contests, all or none of each link group | the all-or-none rule stops a machine from offering a candidate in one senator contest but not the other |
| `Registry::machine`, `Registry::section` | look up by id | the verifier needs the key and section of a machine named in a package |
| `check_keys_disjoint` | one map from key bytes to owner; a repeat is an error | a key used as a machine key and a poll worker key would let one device sign for both roles |
| `MachineEntry`, `SectionEntry`, `ObserverEntry` (`to_value`, `from_value`) | per-entry codecs | the strict field-by-field layout of §7.7 |
| `sign_registry` | `{0: "signed_registry", 1: registry, 2: Sign(ea_sk, "eg/v1/sig/registry", …)}` | the EA's signature over the registry |
| `open_signed_registry` | verifies the signature with the EA key of the manifest, then validates | the same two steps as the manifest |
| `reg_err` | builds `registry: …` errors | errors name their source |

### `fixtures.rs`

Compiled only for tests and with the `fixtures` feature (`#[cfg(any(test, feature = "fixtures"))]` in `lib.rs`). Other modules' tests build on it.

| function | what it does | why |
|---|---|---|
| `Keys` | every secret key of the sample: EA, board, trustee signing and HPKE, machine, poll worker, observer, release signer, release log, mirror | tests need the secrets to sign things, but the manifest and registry only carry public keys |
| `sample_manifest(seed)` | builds the manifest and its keys from a seed | the same seed gives the same election, hashes and signatures |
| `sample_registry(manifest, keys)` | builds a registry for that manifest | the same |
| `sk` | makes a signing key from the seeded RNG | keeps key generation in one line |
| `option`, `single_options`, `contest` | small builders for options and contests | keep the sample readable |

## The sample election

`sample_manifest(seed)` is the test election. Its doc comment calls it "a small Brazilian-style pilot", and this is its shape.

**Contests** (six, indices 0 to 5):

| index | name | kind | method | L | options | notes |
|---|---|---|---|---|---|---|
| 0 | Governador | single | homomorphic | 1 | Ana (12), Bruno (45), Carla (13), Branco, Nulo | plain single-seat contest |
| 1 | Senador | multi | homomorphic | 2 | Hugo (1001), Iara (1002), Joana (1003), Lucio (1004), Nulo | a two-seat contest where the voter may pick up to two, or null; no blank |
| 2 | Deputado Federal | proportional | homomorphic | 1 | candidates Dora (12001, party 0, rank 1), Edu (12002, party 0, rank 2), Fabi (45001, party 1, rank 3), Gil (45002, party 1, rank 4); party options Partido Azul (12) and Partido Verde (45); Branco, Nulo | D'Hondt, 3 seats, no threshold |
| 3 | Prefeito | single | **mixnet** | 1 | Hugo (10), Iara (20), Joana (30), Branco, Nulo | `regional_mix = true`, so it is mixed per region |
| 4 | 1º Senador | single | homomorphic | 1 | Mario (501), Nina (502), Otavio (503), Branco, Nulo | link group 0 |
| 5 | 2º Senador | single | homomorphic | 1 | the same three names and blank and null | link group 0 |

Contests 4 and 5 have identical option lists, which rule 7 requires of a link group. A voter may pick each senator at most once across the two contests (§7.5).

**Parties:** Partido Azul (index 0, number 12) and Partido Verde (index 1, number 45). No federations.

**Trustees:** three (n = 3), threshold k = 2, in the blocs `TSE`, `OAB` and `university`. The EA's bloc is `TSE`. Rule 11 holds: each bloc has one trustee, which is less than k = 2.

**Signers:** three release signers in the same three blocs, with k_r = 2.

**Mirrors:** two, operated by blocs `OAB` and `university`. Both differ from `TSE`, so rule 13 holds.

**Mix policy:** at least 2 mixers per unit (`min_mixers` = 2, which is between k = 2 and n = 3), regions merged until they have at least 1 row.

**Link groups:** one, group 0, contests 4 and 5.

**Approved hashes:** a single placeholder, `[0xaa; 32]`. The real build hashes come from the release process (§24).

**Registry** (`sample_registry`):

| entry | value |
|---|---|
| machine `M-S1-01` | section S1, offers all contests |
| machine `M-S2-01` | section S2, offers all contests |
| machine `M-R-01` | reserve machine (section `""`), offers all contests |
| section S1 | region SP, 100 eligible voters, 2 poll workers, max 2 sessions per machine |
| section S2 | region RJ, 100 eligible voters, 2 poll workers, max 2 sessions per machine |
| observers | "Party Azul observers" and "Civil society observers" |

The registry is valid for this manifest. Every section has a regular machine, the reserve machine has no section, and all the keys are distinct.

## Design choices

- **Strict decoding, then validation.** Decoding checks types and shape, and rejects unknown keys. Validation checks meaning. They are separate so that a decoder can't be talked into accepting a malformed election, and so that the error says which of the two failed.
- **Verify the signature before validating.** `open_signed_manifest` checks the EA signature first, then runs the rules. The test `signed_manifest_with_invalid_rule_is_rejected_after_signature` pins this order: an invalid manifest signed by the EA is reported as a rule violation, not as a bad signature.
- **Positional indices.** Contest, option, party, federation, trustee and link-group indices must equal their positions. A reference such as "contest 3" then has exactly one meaning, and a duplicated or missing index is caught at once.
- **Errors name the rule.** Each message starts with the rule number. A failing election tells its operator what to fix.
- **Hash over the canonical bytes.** The manifest hash covers the deterministic CBOR encoding (file 01), so two implementations agree on the fingerprint.
- **The registry can be replaced until polls open.** Machines fail, and keys can be corrected. Freezing at `polls_open` (§17.7) keeps the replacement window bounded and visible.
- **Keys made where they are used.** Machine, poll worker and observer keys must be generated inside the device or token that uses them (§7.7). The EA collects only public keys. An EA that generated them would be able to forge a whole section's packages, and only observers' independent copies would expose it (§28.18).
- **`min_mixers` ties to k.** Rule 8 forces `min_mixers` ≥ k. Then "fewer than k trustees are corrupt" guarantees at least one honest mixer among any `min_mixers` distinct mixers (file 16).

## Attacks each check prevents

| attack | check |
|---|---|
| EA and allies decrypt ballots alone | rule 11: fewer than k trustees per bloc |
| one key holder counted twice under two labels | distinct trustee keys |
| EA-controlled group approves a release on its own | rule 12: fewer than k_r signers per bloc |
| a board hides entries from voters | rule 13: two mirrors outside the EA's bloc, checked by voters (§17.5) |
| a machine lets a voter pick a senator in one contest but not the other | rule 7 and the all-or-none registry rule |
| a machine offers a contest that doesn't exist | registry: unknown contest |
| a section with only reserve machines, which can't be checked | registry: every section needs a regular machine |
| one device used as both a machine and a poll worker | disjoint keys |
| a poll worker's key used to sign for a machine | the same disjointness check |
| tied candidates whose order is decided by whoever runs the count | distinct `tiebreak_rank` |
| typed numbers that match two options | rule 5: unique display numbers |
| a mixnet contest too large for the lookup table | rule 6 |
| regional mixing on a contest that can't use it | rule 9 |
| a threshold of 1, which lets one trustee decrypt | structure: 2 ≤ k |

## Tests

**`manifest.rs`: 32 tests.**
- Sample validation, including the Brazil-rule variant.
- Round trips, with and without optional fields.
- Signed manifest: opens with the right key, fails with the wrong key, fails when tampered, and an invalid rule set signed by the EA is rejected after the signature check.
- Hash stable, and it changes with content.
- Strict decoding: wrong version, unknown key, bad tag, missing field, `regional_mix` set to false, unknown contest or option kind, bool in the wrong place, short release signer.
- One test per rule, `rule_1_…` to `rule_13_…`, each building a manifest that breaks just that rule and checking the error names it.
- `mixnet_bound_helper` for rule 6.

**`registry.rs`: 17 tests.**
- The sample validates; round trip; strict decoding rejects a wrong version and an unknown key.
- Signed registry opens with the right key and fails with the wrong key or after tampering.
- Each registry rule has a rejection test: unknown section, duplicate machine id, a partial link group offer, an unknown or unsorted contest, a section with no regular machine, a key reused across roles, a manifest hash mismatch, a zero registry version, zero `max_sessions`, duplicate section id.
- A reserve machine is allowed.

**`fixtures.rs`:** no tests of its own. It is exercised by every test that calls `sample_manifest` or `sample_registry`, which is most of the crate.

## Spec gaps relevant here

- **Spec issue 10 (reserve machines):** a reserve machine's contests must match the section it serves, but that is only known on polling day, so registry validation can't check it. Package ingestion does.
- **Spec issue 11 (brazil-2021 parameters):** the basis-point parameters have no stated bounds, and the code doesn't range-check them. A manifest could set a threshold above 100%.
- **Spec §7.7 registry freeze:** the registry is frozen by a later board rule (no `signed_registry` after `polls_open`). That rule lives in board ingestion (file 15), not in this file.
