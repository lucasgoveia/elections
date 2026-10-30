# 13 · Ballots: encrypting and judging a whole ballot

**Code:** `crates/eg-core/src/ballot.rs`. **Spec:** §12 (ballots), §14.2 (checking a spoiled ballot, which uses the reveal functions here), §7.5 (link groups). The proofs it calls are in files 05 and 06.

## The problem

A ballot is what the voter chose, turned into a package that can be published:

1. **Hidden.** Nobody reading the board can tell which option was picked.
2. **Legal.** Each box holds a value that the rules allow (0 or 1, and in a single-seat contest exactly one 1). Every claim comes with a proof.
3. **Bound to this ballot.** A proof for one ballot must not be usable on another, or copied to a new one.
4. **Re-buildable on demand.** If the voter spoils the ballot, anyone must be able to rebuild it from a revealed seed and check it matches. (§14.2)
5. **Judged per contest.** A ballot covers several contests. A fault in one should not throw away the others.

File 04 gives the locked box, file 05 the Schnorr and Chaum-Pedersen proofs, file 06 the "0 or 1" proof. This file puts them together.

## The idea, without math

- A **ballot** is a set of rows of locked boxes, one row per contest. A single-seat contest with three candidates, a blank and a null has five boxes in its row. Exactly one box holds 1.
- Every box's randomness, its **nonce**, is derived from one secret **seed ρ** per ballot. Hashing the seed with the ballot's identity, the contest and the position gives each box its own nonce.
- If the voter **casts** the ballot, the machine erases ρ, and the ballot can never be opened, except by the trustees' threshold decryption. If the voter **spoils** it, ρ is published, and anyone can recompute every nonce and check the boxes.
- The **proofs** use separate, fresh randomness. They never draw from ρ (section 3 below).
- A contest is **homomorphic** (boxes are added and then decrypted as a total) or **mixnet** (each box is a slot that is shuffled and decrypted one by one, file 16). The method is set per contest in the manifest.

## Ballot identity (§12.1)

`ballot_id = [machine_id, session_id, seq]`. The machine name, the session on that machine, and the 1-based sequence number inside the session. Every ballot has a different id, and the id is part of every proof's context, so nothing built for one ballot works for another.

## Nonce derivation (§12.2)

```
r(contest, position) = HashToScalar("eg/v1/nonce", context_hash, ballot_id, ρ, contest, position)
```

- `position` is the option index for homomorphic contests, and the placeholder index for multi contests (placeholders follow the options). For mixnet contests, it is the slot index.
- Each box gets a different nonce, because `(contest, position)` differs. Ballots can't share nonces, because `ballot_id` and ρ differ.
- If the result is 0, the machine must draw a new ρ and start again. The probability is negligible, but the code handles it (`Error::ZeroNonce`).

### Why proof randomness must not come from ρ

The spec says proof randomness (the values *u*, *c_f*, *v_f* in the proofs) "MUST come from fresh `Random()` calls and never from ρ" (§12.2). The reason is about keeping two secrets separate.

- A **spoil** publishes ρ, so every nonce becomes public. That is intended: the spoil check needs the nonces.
- The **proofs** must stay zero-knowledge, meaning they reveal nothing beyond "this box holds 0 or 1". The proofs are built from their own random values. If those values were derived from ρ, publishing ρ would also publish the values behind the proofs. Anything that depends on the proofs' secrecy would then depend on the spoil decision.
- Keeping them independent means a published ρ opens exactly what the spoil check needs, and nothing more.

So ρ feeds the nonces, and the proof randomness comes from the RNG passed into `encrypt_ballot`.

## Homomorphic encoding (§12.3)

Let a contest have *m* options and selection limit *L*.

### Single and proportional

There are *m* boxes, one per option (candidates, parties, blank and null). Exactly one holds 1. The **sum target** is 1: the total of all boxes must encrypt exactly 1. No placeholders.

Example: a Governador row with Ana, Bruno, Carla, Branco and Nulo (*m* = 5). A vote for Bruno sets the second box to 1 and the rest to 0. The total is 1, so the sum proof passes.

### Multi (the placeholders and the null)

A multi contest has *m* option boxes **plus L placeholder boxes**. Placeholders are never tallied, but they are part of the sum.

- A voter picking *q* ≤ *L* candidates sets those candidates' boxes to 1, sets the **lowest-positioned L − q placeholders** to 1, and leaves null at 0.
- A voter picking **null** sets the null box to 1, and every candidate and placeholder to 0.
- The **weighted sum** counts the null box *L* times:

```
(α_Σ, β_Σ) = ⊕ candidates ⊕ placeholders ⊕ L·(null)
```

The weighted sum must encrypt exactly *L*.

**Why placeholders.** Every ballot's total is then exactly *L*, so the sum target is the same public number for every ballot. Without placeholders the target would be *q*, the number of candidates chosen, and the sum proof would reveal how many boxes the voter filled. The placeholders hide the count.

**Why the null counts L times.** A null vote must fill the whole budget by itself, and it must not be combinable with candidates. Weighting null by *L* makes a null alone total exactly *L*. Any candidate added to a null pushes the total above *L*.

### Worked example: L = 2, with a null vote and with one candidate plus one placeholder

The Senador contest (contest 1 in file 12) has four candidates and a null: Hugo (position 0), Iara (1), Joana (2), Lucio (3), Nulo (4). Its *m* = 5, and there are *L* = 2 placeholders at positions 5 and 6. Total: seven boxes.

The weights are 1 for every position, except null (position 4), which weighs *L* = 2.

| vote | bits at positions 0..6 | weighted sum | target | result |
|---|---|---|---|---|
| null | 0 0 0 0 **1** \| 0 0 | 2 × 1 = **2** | 2 | valid |
| Hugo + one placeholder (*q* = 1) | **1** 0 0 0 0 \| **1** 0 | 1 + 1 = **2** | 2 | valid |
| Hugo + Iara (*q* = 2, no placeholders) | **1 1** 0 0 0 \| 0 0 | 1 + 1 = **2** | 2 | valid |
| blank (*q* = 0) | 0 0 0 0 0 \| **1 1** | 1 + 1 = **2** | 2 | valid |
| null **and** Hugo (cheat) | **1** 0 0 0 **1** \| 0 0 | 1 + 2 = **3** | 2 | rejected |
| Hugo, Iara and Joana (cheat) | **1 1 1** 0 0 \| 0 0 | 3 | 2 | rejected |

The sum proof is what rejects the last two rows. Each individual box also needs its own 0-or-1 proof, so no box can hold 2 to get around the count.

The code computes this layout in `hom_layout` (weights and target), and the bits in `plaintexts`. Both are in `ballot.rs`, so encryption and the reveal check can't disagree about the encoding.

Note that a multi contest **without** a null option uses the same formula with no null term (§12.3).

### Proportional

Proportional contests use the single-seat rule with *m* options: every candidate, every party option (the *voto de legenda*, a vote for the party alone), blank and null. Exactly one box is 1. The party option is just another box. The apportionment (file 17) adds up the votes by party.

## Mixnet slots (§12.4)

A mixnet contest does not get a validity proof before the shuffle. It gets *L* **slots**:

- a selected option fills a slot with the value `option index + 1`;
- an unused slot holds 0;
- filled slots come first, in ascending option order.

Each slot is encrypted and proved with a Schnorr proof that the prover knows its nonce (§11.5). The slot's proof context includes the ciphertext's β, so a proof can't be moved to another slot.

**Examples** for the single-seat mixnet contest Prefeito (Hugo 0, Iara 1, Joana 2, Branco 3, Nulo 4), with *L* = 1: Joana is value 3, blank is 4, null is 5.

For a two-slot mixnet multi contest: Hugo and Iara give `[1, 2]`, Hugo alone gives `[1, 0]`, blank gives `[0, 0]`.

**Why no validity proof here.** A single slot holds one value, so an invalid value can be caught after decryption instead (§19.6). The mixnet's counting rules check each row after decryption. The mixnet's advantage is that no section-by-section count is needed, and the reason the spec gives for using homomorphic contests for proportional elections is exactly that they **do** need a per-section count (§7.4).

## Link proofs (§12.3a, §7.5)

A **link group** is a set of contests over the same candidates, in which a voter may choose each candidate at most once in total. The Brazilian case is the two single-seat Senate contests (file 12, contests 4 and 5).

For each candidate *x* in the group, the machine adds the boxes for *x* across all contests of the group:

```
(α_x, β_x) = ⊕ over contests c in the group of (α, β)_{c,x}
r_x        = Σ over contests c of r(c, x)
```

The sum encrypts *b_x* = Σ (the bits), and a **link proof** says that this sum is 0 or 1 (the 0-or-1 proof of file 06, with context `["link", ...]`).

**Example.** Voter picks Mario in contest 4 and Mario again in contest 5. The Mario sum encrypts 2. There is no 0-or-1 proof for 2 (file 06, section 5), so the link proof for Mario fails, and the whole group is excluded for this ballot. A voter who picks Mario in one and Nina in the other has sums of 1 and 1, which are both valid.

**Witness when no contest selects the candidate.** The sum is then an encryption of 0, with the sum of the nonces as the witness. The spec doesn't say so explicitly (spec issue 8), and the code does produce a valid proof of 0 in this case.

**Machine layer.** Honest software never produces a duplicate. `check_link_duplicates` refuses to build a ballot that selects the same candidate in two contests of one group, and returns `Error::Ballot`. The protocol layer is the link proof above, which catches software that doesn't do this check.

## Ballot structure (§12.5)

A ballot is:

- field 2, the context hash;
- field 3, the ballot id;
- field 4, one `contest_ballot` per offered contest, ascending. A `hom` entry has *m* (or *m* + *L*) selections and a sum proof; a `mix` entry has *L* slots;
- field 5, one `link_proof` per homomorphic link group whose contests **all** this machine offers, with one proof per candidate.

Every selection is `[α, β, disj01 proof]`. Every slot is `[α, β, Schnorr proof]`.

## Validity (§12.6)

Judging a ballot happens in two steps.

**Step 1: is the ballot well-formed?** If not, the whole ballot is excluded. The checks (`well_formed`):

1. the context hash matches the election;
2. the contests present are exactly those the machine offers, ascending, and each has the right number of selections or slots for its method;
3. there is exactly one link proof per homomorphic group the machine offers, with one proof per candidate;
4. no α is the identity (`O`).

**Step 2: is each contest counted?** `judge` checks each contest on its own:

- homomorphic: every selection's 0-or-1 proof and the sum proof verify, and, if the contest is in a link group, every link proof of the group verifies;
- mixnet: every slot proof verifies (the duplicate check happens after decryption, file 16);
- a contest that fails is **excluded**. If it belongs to a link group, every contest of that group on that ballot is excluded with it, because the link proof can't say which member is inconsistent.

**Why judge per contest.** A machine that attaches bad proofs to one contest should not cost the voter the rest of the ballot. The other contests still count. The bad contest is reported as evidence against the machine (§23).

**α reservation is not here.** Reservation (§12.6) needs to see all the ballots in board order, so it is done at tally time, using `Ballot::alphas`. `tally.rs` holds it, not `ballot.rs`.

`check_ballot` returns a `BallotCheck`: `well_formed` (an `Err` with the reason, or `Ok`) and, if well-formed, the status of each contest.

## Checking a reveal (§14.2)

`check_reveal(election, ballot, rho, claimed)` takes a spoiled ballot's seed ρ and the selections the machine claims it encrypted. It:

1. checks the claim covers the same contests, in the same order;
2. turns each claimed selection into its plaintext bits (the same `plaintexts` as encryption);
3. re-derives every nonce from ρ;
4. re-encrypts each box and compares α and β, byte for byte, with the ballot.

If the machine encrypted Hugo but its reveal says Iara, the boxes won't match. The check returns the first mismatch, naming the contest and position.

It is the part of the spoil check that proves the machine's claim is honest. The voter, or an observer, then compares the claim with the choices they actually made. The check must run on a device independent of the voting machine (§14.2), for the reason explained in file 14.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `BallotId::to_value`, `from_value` | `[tstr, tstr, uint]` | the identity inside every context |
| `derive_nonce` | `HashToScalar("eg/v1/nonce", …)` | the nonce for one box of one ballot |
| `ContestPlain::to_value`, `from_value` | `[uint, [* uint]]` | the voter's choices, in the reveal |
| `Ballot::to_value`, `from_value` | the §12.5 map; strict decode | one exact form, so the digest is stable |
| `Ballot::alphas` | the α values of one contest, in position order | input to α reservation at tally time |
| `Ballot::digest` | `Digest("eg/v1/ballot", ballot)` | what the tracking code hashes (file 14) |
| `ContestBallot::contest`, `to_value`, `from_value` | the `hom` and `mix` entries | one type for both methods |
| `LinkProof::to_value`, `from_value` | `[uint, [+ disj01]]` | the link group's proofs |
| `entry_value`, `triple`, `selection_from_value`, `slot_from_value` | encode and decode `[α, β, proof]` | shared by selections and slots |
| `entries`, `hom_selections` | the boxes of one contest, whatever its method | so generic code can read both |
| `null_position` | index of the null option, if any | used by the weights and the null rule |
| `hom_layout` | the weights and the sum target for a contest (null weighs L, placeholders are 1, target L for multi) | the whole counting rule in one place |
| `plaintexts` | choices → bits (homomorphic) or slot values (mixnet). **The only place the encoding is defined.** Rejects invalid choices | encryption and the reveal check both use it |
| `strictly_ascending` | selections come in ascending order | one encoding per choice |
| `sel_ctx`, `sum_ctx`, `link_ctx`, `slot_ctx` | the context values of each proof | bind every proof to the election, the ballot, the contest, the position |
| `homomorphic_groups` | the link groups of this ballot whose contests are all offered | the ballot must carry exactly these link proofs |
| `group_candidates` | candidate indices of a link group | the link proofs run over candidates, not over every option |
| `member_positions` | where each group member sits in the ballot's contest list | to add up the group's boxes |
| `prove_link` | a 0-or-1 proof on the link sum | the link proof |
| `check_offered` | offered contests non-empty, ascending, and known | rule 2 |
| `check_link_duplicates` | refuses duplicate candidates across a group | the machine-layer rule (§7.5) |
| `hom_contest` | encrypts and proves one homomorphic contest; returns the nonces for the link proofs | selections, the sum proof, and the nonces the link proofs need |
| `mix_contest` | encrypts and proves one mixnet contest | the slots |
| `encrypt_ballot` | the whole ballot: check input, encrypt each contest, build link proofs | the one function a voting machine calls |
| `well_formed` | rules 1 to 4 of §12.6 | step 1 of judging |
| `verify_contest` | verifies one contest's proofs | the per-contest check |
| `judge` | per-contest verdicts, including the link-group exclusion | step 2 of judging |
| `check_ballot` | the public entry point: well-formed, then judge | what observers and verifiers call |
| `check_reveal` | re-encrypts from ρ and compares bytes | the spoil check (§14.2) |

## Design choices

- **One encoding function.** `plaintexts` decides what each choice means. Encryption and the reveal check both call it, so they can't disagree. A second copy of the rules would be a second place for a bug.
- **Choices are checked before encryption.** `encrypt_ballot` rejects wrong contests, unordered selections, out-of-range options, and two selections in a single-seat contest, so an honest machine can't produce a ballot that the protocol would later exclude.
- **Link proofs reuse the nonces.** The link ciphertext is built from the same nonces as the contest boxes, so a link proof of the group sum refers to the same boxes the contest proofs refer to. A debug assertion checks the sum equals the link ciphertext.
- **Context on every proof.** The contexts name the election, the ballot, the contest, the position and, for slots, β. A proof copied from one box to another, or from one ballot to another, fails the check.
- **Strict decoding; structure checked later.** `from_value` checks the CBOR shape only. The check against the manifest (which contests, how many boxes) is `check_ballot`'s job, so decoding doesn't need the manifest.
- **Null and blank are options, not absence.** A blank vote is a valid choice with its own box (or, in a multi contest, zero candidate boxes plus all placeholders). It is not a missing ballot, so the verifier can tell "chose blank" from "machine dropped the contest".

## Attacks each check prevents

| attack | check that stops it |
|---|---|
| a box holds 2 (five votes for one candidate) | the 0-or-1 proof on that box (file 06) |
| two candidates in a single-seat contest | the sum proof: the total is 2, not 1 |
| null together with a candidate in a multi contest | the weighted sum: null weighs L, so the total exceeds L |
| the same candidate in two senator contests | the link proof: the sum for that candidate is 2 |
| an α of O, which exposes β = m·B in the clear | rule 4 of §12.6 (file 04 explains why) |
| copying a proof from another box or ballot | the contexts, which name the position and the ballot |
| a contest the machine wasn't offering | rule 2: the contest list must match the registry |
| a reveal that claims different choices | `check_reveal`, byte for byte |
| a cheating machine that attaches bad proofs only to one candidate | the per-contest judgment, with the bad contest reported and the rest counted |
| a cast ballot copied with valid proofs (replay) | α reservation at tally time (file 14 and `tally.rs`), since a valid copy needs the nonce |

## Tests (15)

- A valid ballot is counted and decrypts to the bits intended.
- Multi contests: null, blank, and full selections all decrypt to the intended placeholder pattern.
- Mixnet single contest requires exactly one selection.
- Value round trip is canonical; a malformed ballot is rejected by the decoder.
- `encrypt_ballot` rejects invalid choices (wrong contest, unordered, out of range, duplicates across a group).
- Cheats: two 1s in a single contest excluded; a selection encrypting 2 excluded; the same candidate in two linked contests excludes both contests; swapped selection proofs excluded; a proof copied from another ballot excluded.
- Identity α not well-formed; structural failures (wrong contest count, wrong slot count) not well-formed.
- `check_reveal` accepts true claims and rejects others.
- `derive_nonce` is deterministic and sensitive to position.

## Spec gaps relevant here

- **Spec issue 8:** the witness for a link proof when no contest selects a candidate is 0. The spec should say so; the code does it.
- **Spec issue 12:** α reservation inside link groups. When a later contest of a group is excluded by reservation, earlier contests of the same group keep their reservations on that ballot, and the spec doesn't say so. This is decided in `tally.rs`.
