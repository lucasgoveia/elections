# 14 · Tracking codes, the machine chain, slips and spoil receipts

**Code:** `crates/eg-core/src/chain.rs`. **Spec:** §13 (chain, display form, slip), §14 (Benaloh audit-or-cast: states, spoil receipt, checking a spoiled ballot, detection probability).

## The problem

A voter needs to know their ballot made it onto the board, unchanged, without being able to prove to anyone how they voted. Three things must hold together:

1. **Inclusion.** The voter can find their ballot on the public board and see it was cast.
2. **Integrity.** The machine can't swap a cast ballot for another, drop it, reorder the session, or give two voters the same ballot.
3. **Verifiability of the machine.** The machine must not be able to cheat on the ballot's contents and get away with it. A voter should be able to ask for a ballot to be opened and checked, without that ballot being counted.

The tracking code handles (1) and (2). The cast-or-spoil choice, with the chain and the spoil receipt, handles (3). This file covers both.

## The idea, without math

**The chain.** Think of the codes as a row of linked boxes. Each box's label is a fingerprint of everything in the boxes before it, plus its own ballot. Change one ballot in the middle and every later label changes too. A label is a fingerprint of the whole history, not just of one ballot.

**The machine commits, then the voter decides.** The machine encrypts the ballot, shows its code, and only then does the voter choose:

- **cast**: the ballot is counted. The machine erases the secret seed ρ, so the ballot can never be opened again.
- **spoil**: the ballot is never counted. The machine publishes ρ and the choices it claims, so anyone can check the ballot. The voter then votes again.

The machine must commit before it knows which ballots will be audited. A voter who will audit is chosen by the voter's own decision, which the machine can't see in advance.

## The chain (§13.1)

### Start

```
head_0 = Digest("eg/v1/chain-start", context_hash, machine_id, session_id, software_measurement, opening_challenge)
```

The starting head ties the chain to this election (`context_hash`), this machine (`machine_id`), this session, the machine's software measurement (a hash of the software it runs, §24.4), and a random 16-byte `opening_challenge`. Even two sessions on the same machine, with the same software, start from different heads, because the challenge differs. The spec does not spell out the purpose; this is the property it gives.

### Each ballot

```
code_s = Digest("eg/v1/code", head_{s−1}, Digest("eg/v1/ballot", ballot_s))
```

The code is a fingerprint of the previous head and of this ballot's digest (file 13). The machine shows this to the voter.

### Each decision

```
head_s = Digest("eg/v1/chain", code_s, status_s, reveal_digest_s)
```

- `status_s` is `"cast"`, `"spoiled"` or `"abandoned"`;
- `reveal_digest_s` is `Digest("eg/v1/reveal", reveal)` for a spoiled ballot and 32 zero bytes otherwise.

The head after a decision is what the next code depends on.

### A worked trace

Take three ballots, `B1` (cast), `B2` (spoiled), `B3` (cast). Write `D(x)` for `Digest(x)` and ignore the exact byte layout.

```
head_0 = D(start)
code_1 = D(code, head_0, D(B1))            head_1 = D(chain, code_1, cast, 0)
code_2 = D(code, head_1, D(B2))            head_2 = D(chain, code_2, spoiled, D(reveal_2))
code_3 = D(code, head_2, D(B3))            head_3 = D(chain, code_3, cast, 0)
```

Now suppose the machine quietly changes `B1` into a different ballot `B1'`:

- `code_1` changes, because it includes `D(B1')`;
- so `head_1` changes, which changes `code_2`;
- so `head_2` changes, which changes `code_3`.

The voter holds `code_3`. It no longer matches the chain the board would have to show. Every later code is caught by the change, not just the one changed ballot.

### Why clash attacks fail

A **clash attack** is when a machine gives two voters the same code, so that one voter's ballot can be quietly substituted for the other's. Two things prevent it.

- The code depends on the head before it, which is different for every position in the session.
- Even two voters with **identical** choices get different ballots, because each ballot has a fresh seed ρ, and so different ciphertexts and a different digest. Their codes differ.

`machine_id` also keeps codes apart between machines, so a code from one machine can't be mistaken for one from another.

## Short codes in Crockford base32 (§13.2)

A full code is 32 bytes, which is far too long to type or read off a slip. The **short code** is the first 100 bits of the code, written as 20 characters:

- the alphabet is Crockford base32: `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. It has 32 characters, and leaves out `I`, `L`, `O` and `U` because they are easy to confuse with `1` and `0`;
- each character holds 5 bits, so 20 characters hold 100 bits;
- the characters are grouped in fours with hyphens, as in the spec's example `K7QD-3XMA-9PRT-2BHW-6YCN`.

**Worked example: the first character.** The first 5 bits of the code are `10011`, which is 16 + 2 + 1 = 19. Index 19 in the alphabet is `K`, which is where the example starts.

**Typing.** `parse_short_code` accepts lowercase, hyphens optional, and two aliases: `O` is read as `0`, and `I` or `L` as `1`. `U` is not in the alphabet, so it is rejected. Any other character, or a wrong length, is rejected.

**Why 100 bits and not 128.** The short code is a lookup key, typed by voters and read by eye. 100 bits is 2¹⁰⁰ possible values, so a random typo or a guessed code finds a real ballot with negligible probability. The full 32 bytes go into the QR code on the slip, for scanning. Hence `short_code_matches` compares 100 bits of a full code against a parsed short code.

## The slip (§13.3)

When the ballot is cast, the voter gets a **slip**: a machine-signed record of the context, the machine id and the code.

```
slip = { 0: "slip", 1: 1, 2: context_hash, 3: machine_id, 4: code, 5: Sign(machine_sk, "eg/v1/sig/slip", …) }
```

The slip contains **no selections, no sequence number and no time**. The reason is practical and important. The slip proves the ballot exists with the code it names. It does not prove how the voter voted, and the encrypted ballot on the board doesn't reveal it either, because ρ was erased. A voter can't use the slip to show a third party what they chose.

**Evidence.** A signed slip whose code is missing from the board, or present with a different status from the one the voter chose, is **proof of misbehaviour** by the machine or the board (§13.3). The machine signed it, so the machine can't deny it.

## Cast or spoil: the Benaloh audit (§14)

### The states (§14.1)

```
Selected ──encrypt()──► Committed ──cast()──► Cast        (ρ erased)
                            │
                            └──spoil()──────► Spoiled     (ρ and choices revealed)
```

1. **encrypt**: the machine draws ρ, builds the ballot, computes `code_s`, journals it, and shows and prints the code. The ballot is now fixed.
2. **cast**: the machine journals `cast`, **securely erases ρ**, signs and prints the slip, and uses up one authorisation.
3. **spoil**: the machine journals a `reveal` (ρ and the choices it claims it encrypted) and prints a **spoil receipt**. The ballot is never counted, the authorisation is not used, and the voter votes again.

**Why erase ρ on cast.** ρ determines every nonce. While ρ exists, the ballot can be rebuilt and opened. Once ρ is erased, the only way to read a cast ballot is the threshold decryption of the election total (§20, with the trustees' shares from file 10). A machine can't later reveal the choices in a cast ballot, which means it can't be pressured into doing so.

**The spoil receipt (§14.1).**

```
spoil_receipt = { 0: "spoil_receipt", 1: 1, 2: context_hash, 3: machine_id, 4: code, 5: reveal, 6: Sign(machine_sk, "eg/v1/sig/spoil", …) }
```

It is printed as a QR code with the claimed choices in plain text. It is safe to take home, because the spoiled ballot is never counted. It is also marked as **not** a vote, unlike the cast slip, so no one mistakes it for one.

### Why the machine can't know which ballots will be audited

The machine must display the code **before** the voter decides. From that point, the ballot is fixed. Whether the voter casts it or spoils it is the voter's choice, made after the machine has committed. So the machine can't:

- change a ballot after seeing the audit decision, because the decision comes later;
- guess which voters will audit, because the spec asks hosts to prompt voters **at random** to audit (§14.3).

### How many changed ballots would be caught? (§14.3, informative)

If a machine changes *k* ballots, and each voter independently spoils with probability *p*, the chance that **none** of the changed ballots is audited is (1 − *p*)^*k*.

| p (spoil rate) | k = 10 changed | k = 20 changed |
|---|---|---|
| 0.1 | 0.35 | 0.12 |
| 0.2 | 0.11 | 0.012 |

So a machine that cheats on 20 ballots in an election where one voter in five audits has about a 1.2% chance (roughly 1 in 90) of going unnoticed. Observers' audit-only sessions raise *p* at no privacy cost (below).

### The privacy cost

A spoiled ballot's choices are **published**: the reveal goes into the chain directly before the voter's next cast ballot (§14.3). Voters must be told this. Hosts should therefore favour observer audit-only sessions, which have no privacy cost, over voter audits (§28.13).

## Checking a spoiled ballot (§14.2)

The check is in `ballot.rs` (`check_reveal`, file 13), and it runs on a device other than the voting machine. Given a spoil receipt, a checker:

1. verifies the receipt's signature, then fetches the package holding `code` with its inclusion proof (file 15), and checks the code's status is `spoiled` and its reveal equals the receipt's reveal;
2. re-derives every nonce from ρ;
3. re-encrypts the claimed choices, using the encoding of §12.3 or §12.4;
4. checks every (α, β) is byte-for-byte equal to the ballot's;
5. shows the claimed choices to the voter or observer, who compares them with what they chose.

**Why not the voting machine.** A cheating machine would show the expected choices. The check must be run where the machine's word isn't the last word.

**What a mismatch proves.** The ballot, the reveal, the spoil receipt and the signed package are all signed or chained by the machine. A mismatch is cryptographic evidence against it.

## The code, function by function

| function | what it does | why |
|---|---|---|
| `Measurement` (`to_value`, `from_value`) | the software measurement `{0: "measurement", 1: "sha256", 2: bstr .size 32}` | which software the machine ran, bound into the chain start; the algorithm must be `sha256` |
| `chain_start` | `Digest("eg/v1/chain-start", …)` → `head_0` | the first head, tied to election, machine, session, software and challenge |
| `tracking_code` | `Digest("eg/v1/code", head, Digest("eg/v1/ballot", ballot))` | the code the voter sees |
| `Status` and `Status::as_str` | `cast`, `spoiled`, `abandoned` | the text that goes into the head, so the status is committed |
| `next_head` | `Digest("eg/v1/chain", code, status, reveal_digest)`; panics on a reveal without `spoiled`, or `spoiled` without a reveal | moves the chain forward after each decision |
| `short_code` | the first 100 bits as 20 Crockford characters, in fours | the typed or read-out form |
| `parse_short_code` | the reverse, with aliases and optional hyphens; returns 100 bits packed in 13 bytes | the voter's typed input |
| `crockford_value` | one character to its value, applying `O`→0 and `I`/`L`→1 | the alphabet rule, in one place |
| `short_code_matches` | does a full code start with a parsed short code | the lookup check |
| `bit` | bit *i* of a byte string, most significant first | used by the short-code encoder |
| `Reveal` (`to_value`, `from_value`, `digest`) | the §14.1 reveal map; the digest is `Digest("eg/v1/reveal", …)` | the claimed choices and seed, committed into the chain |
| `Slip::sign`, `Slip::from_signed` | builds and verifies the signed slip | the voter's receipt of the cast |
| `SpoilReceipt::sign`, `SpoilReceipt::from_signed` | builds and verifies the signed spoil receipt | the voter's receipt of a spoil |
| `replay_chain` | recomputes every code and the final head from `head_0` and the decisions in order | how a verifier checks a whole session at once |
| `fields` | builds the `(key, value)` list that `sign_record` takes | keeps the signed field layout in one place |

## Design choices

- **Commit the status into the head.** A cast ballot and a spoiled one get different heads. A board that quietly turns a cast ballot into a spoiled one changes every later code, and the voter's signed slip records `cast`. The mismatch is caught.
- **Commit the reveal by digest.** A spoiled ballot's reveal is folded into the chain, so it can't be altered later without changing the head.
- **Short codes are a truncation, not a separate value.** The short code is just a prefix of the full code. Nothing else has to be kept in sync.
- **Crockford base32 with aliases.** Voters make transcription errors. Leaving out the four easily confused letters and accepting `O`, `I`, `L` as their look-alikes makes typing forgiving without making codes ambiguous.
- **Signatures use a separate tag per record.** The slip and the spoil receipt each have their own domain tag (`eg/v1/sig/slip`, `eg/v1/sig/spoil`), so a signature on one can never be replayed as the other.
- **`replay_chain` is the verifier's tool.** It takes the decisions in order and rebuilds every code. A verifier needs nothing else from the machine.
- **Panics on programming errors.** `next_head` panics if a spoil has no reveal, or a reveal comes with a non-spoil status. These are bugs in the caller, not bad input from a voter, so they are not returned as errors.

## Attacks each check prevents

| attack | what stops it |
|---|---|
| swapping a cast ballot for another | every later code changes, so the voter's code no longer matches the chain |
| dropping or reordering ballots in a session | the same, plus the sequence is in the head |
| two voters given the same code | heads differ by position; ballots differ by fresh ρ |
| the board showing a cast ballot as spoiled, or the reverse | the status is in the head; the slip says `cast` |
| a forged reveal, or a reveal that claims different choices | the reveal digest is in the head; `check_reveal` re-encrypts and compares |
| a machine that cheats only on ballots it expects nobody to audit | the decision comes after the commitment; audits are random |
| a machine that copies a code from another machine | `machine_id` and the chain start |
| a forged slip or spoil receipt | the machine's signature, with a per-record tag |
| a voter typing a code they don't have | 100 bits; collisions are not a practical risk |
| a verifier reading the slip as proof of the vote | the slip names no choices |

## Tests (14)

- Hand-built digests: `chain_start`, `tracking_code` and `next_head` each match an independently built digest.
- `next_head` panics when a spoil has no reveal, or a reveal comes with a non-spoil status (`should_panic` tests).
- `later_codes_depend_on_every_earlier_entry`: changing an early ballot changes every later code.
- Short codes: known vectors, round trip, aliases, case, optional hyphens, and rejection of bad input (wrong length, `U`, other characters).
- Measurement round trip, and a wrong algorithm is rejected.
- Reveal round trip and digest, and an empty selection list is rejected.
- Slip: sign, verify, and a tampered slip fails.
- Spoil receipt: sign, verify, and a tampered receipt fails.

## Spec gaps relevant here

- **§14.2 and the verifier:** the spec's check needs the package, which lives in the board (file 15). The spoil check can't run from the receipt alone.
- **Spec issue 9 (verifier independence):** §23 requires the verifier to be independent of the code that produced ballots. The plan is a separate verifier crate that reuses the primitive codecs. Until that exists, the checks in this file are only as independent as the code they share.
