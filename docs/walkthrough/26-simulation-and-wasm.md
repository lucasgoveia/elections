# 26 · The simulator and the WASM bindings

**Code:** `crates/eg-core/src/sim.rs` (the driver, behind the `fixtures` feature; `lib.rs:28`). `crates/eg-core/src/fixtures.rs` (the two sample elections). `crates/eg-wasm`: `src/lib.rs` (the JavaScript bindings and the pure-Rust methods they call), `src/dto.rs` (the data shapes that cross to JavaScript), `tests/native.rs` (tests that run natively). **Spec:** none directly. The simulator drives §8 to §21 in order, and the WASM crate runs the §23 verifier (file 25) on what it produced. The web app that uses the bindings is in `web/` and is still being built (see `web/DESIGN.md`).

**Version.** This file describes the code at commit `220b848` ("Add Star Wars election scenario"). Line numbers are for that commit. The scenario support was added after the first version of the bindings (`b667b68`), and changed `sim.rs`, `fixtures.rs` and the wasm crate.

**Scope of this file.** The simulator plays a whole election in one process. It is a demo and a test tool. It is **not** a voting machine, a board or an EA, and nothing in it may be used to run a real election. The WASM crate exposes it to a browser, so that a person can run an election, see every record, and break one on purpose to watch a check catch it.

## The problem

The protocol has many parties: the EA, the board, the trustees, the machines, the poll workers and the voter. Each has its own records and its own checks. Two things are hard to show by reading the spec:

1. the whole sequence works, from the key ceremony to the published result, with real records at every step;
2. each check in the verifier actually catches what it is meant to catch.

The simulator answers the first, and its attack switches answer the second. An attack switch makes one party misbehave in one specific way. The verifier, or a voter's own check, must then fail in the place the spec says it should.

## Two elections: Pilot and Star Wars

The simulator plays one of two sample elections, chosen by `Scenario` (`sim.rs:67`).

| | `Pilot` (the default) | `StarWars` |
|---|---|---|
| what it is | the Brazilian sample: governor, senate, deputies, mayor | the Galactic Republic election |
| identifier (`Scenario::name`) | `"pilot"` | `"star-wars"` |
| contests | 6 | 11 |
| sections | 2 | 10 (one per planet) |
| machines | one per section, plus a reserve machine | one per section, no reserve machine |
| each regular machine offers | all 6 contests | 2 contests: the President and its own planet's senate race |
| link group (§12.6) | yes | no |
| mixnet contest (§19) | yes | no |
| random ballots per machine in `run_all` (`random_ballots_per_machine`, `:108`) | 3 | 2 |
| sample data | `fixtures::sample_manifest`, `sample_registry` | `fixtures::starwars_manifest`, `starwars_registry` |

Because a Star Wars election has no mixnet and no link group, its board has no mix records. The Pilot exercises every part of the protocol, which is why the attack tests run on both.

## Why the simulator is a demo, and why it leaks

Two design choices in `sim.rs` look wrong for a real system. They are right for a demo, and wrong for anything else.

**Seeded randomness.** Every random choice (the keys, the polynomials, the nonces, the voters' choices) is drawn from a ChaCha20 stream that the caller seeds (`Simulation::new`, `sim.rs:340`, which calls `ChaCha20Rng::seed_from_u64`). The same seed gives the same election, byte for byte. That is what makes the demo repeatable: a bug or an attack can be reproduced exactly, and the tests can check exact values. A real election must use a fresh, unpredictable source of randomness for every key and nonce, because a predictable nonce breaks the encryption (§5.6). A seeded generator is never acceptable there.

**Leaked references.** `Simulation::with_scenario` (`sim.rs:346`) puts the manifest and the registry in `Box::leak` (`:348` and `:349`). `run_ceremony` does the same for the context (`:534`). The leak gives each one a `'static` lifetime, so the `Session<'static>` and `BoardState<'static>` values can be stored in the `Simulation` struct without a tangle of borrowed lifetimes. The cost is a few kilobytes per simulation, which is fine for a driver that lives for a short time. A long-running service would leak without limit. This is a convenience of the driver, not a design of the protocol.

**One process plays everyone.** All keys sit in memory (`Simulation::keys`). The same struct holds the EA's key, the board's key, the trustees' keys and the machines' keys. In a real election each of these is held by a different party, in a different place, and some of them in hardware. The driver's whole point is that it can see all of them; that is the opposite of what the protocol needs.

So: the simulator is for demonstrations and tests. Nothing in `sim.rs` may be moved into a production path, and the `fixtures` feature (`eg-core/src/lib.rs:14` and `:28`) keeps both the fixtures and the simulator out of a normal build.

## The phases

`Phase` (`sim.rs:118`) has five values, in order: `Setup`, `CeremonyDone`, `PollsOpen`, `PollsClosed`, `Tallied`. Each driver method checks the phase it needs with `expect_phase` (`sim.rs:1205`) and moves the election on. A method called out of order returns an error with a `sim:` prefix, not a panic.

| phase | method (line) | what it does | records posted to the board |
|---|---|---|---|
| (start) | `Simulation::new` (`:340`), `with_scenario` (`:346`) | samples the manifest, keys and registry of the scenario from the seed. `new` is `with_scenario(seed, Pilot)`. | the `signed_manifest` at entry 0 |
| `Setup` to `CeremonyDone` | `run_ceremony` (`:413`) | the distributed key generation (§8). Each trustee makes a polynomial and sends encrypted shares to the others; the shares are checked. Builds the context and each trustee's secret share `z_j`. Starts the board's ingester. | `dkg_round1`, `dkg_round2`, `dkg_round3`, and any `dkg_complaint` and `dkg_reveal` |
| `CeremonyDone` to `PollsOpen` | `open_polls` (`:571`) | signs the registry and the `polls_open` record that names it | `signed_registry`, `polls_open` |
| `PollsOpen` | `open_session` (`:592`) | opens a session on one machine. The first poll worker of its section signs the zerésima, the opening record that the paper copy shows (§15). A reserve machine needs its section named. | none until the session closes |
| `PollsOpen` | `authorize` (`:711`), `encrypt` (`:725`), `cast` (`:750`), `spoil` (`:773`), `abandon` (`:803`) | one voter's ballot: authorise, encrypt the choices, then cast it, spoil it, or abandon it without revealing | none directly; the machine's journal goes into its package |
| `PollsOpen` | `close_session` (`:819`) | closes a session and signs its pre-BU (§16.2). Posts the machine's package and a `section_attestation` from the second poll worker. | `package` (unless an attack drops it), `section_attestation`, and a `rejection` if the board refuses the package |
| `PollsOpen` to `PollsClosed` | `cutoff` (`:870`) | closes every open session, then signs `tally_cutoff` (§17.7) | `tally_cutoff` |
| `PollsClosed` to `Tallied` | `tally` (`:895`) | runs the authority pipeline (`run_pipeline`, `:1415`, file 24) on the board up to the cutoff. Signs the result as the EA. Keeps the honest recount beside the published result. | the section tallies, the pool and the encrypted tally; the trustees' `final_bu`, `mix_output` and `decryption_shares`; and the EA-signed `result` |
| any time after the ceremony | `sign_sth` (`:943`) | signs a tree head over the current log | none (the driver keeps the STH in `sths`) |

`post` (`sim.rs:1244`) is the one place that puts a record on the board. It appends the record to the log, gives it to the board's ingester, and if the ingester refuses it, posts a `rejection` for it (§17.6). Every other method goes through it, so the board in the simulator is always the board the ingester would make.

### `run_all`: the whole election in one call

`run_all` (`sim.rs:1102`) does the full sequence for the chosen scenario. For the demo this is what runs in the browser.

1. `run_ceremony`, then `open_polls`.
2. For each regular machine (`regular_machine_ids`, `:1182`; reserve machines are not used by `run_all`): `open_session`, then `vote` (`:1193`), which spoils one ballot and casts the next, then `cast_random` (`:1091`) for `random_ballots_per_machine` more ballots.
3. `close_session` for every machine, then `cutoff`.
4. `tally`, then `sign_sth`.

The count follows from the scenario. A machine casts `1 + random_ballots_per_machine` ballots (`casts_per_machine`, `:1728`). In the Pilot, both machines offer every contest, so each contest ends with 8 counted ballots. In the Star Wars, each contest is counted over the machines that offer it (`machines_offering`, `:1733`). The shared test `check_honest_run` (`:1742`) checks this for both scenarios.

`random_choices` (`:1125`) picks a valid set of choices for the contests a machine offers. For a multi contest it picks up to `L` candidates. A candidate already chosen in a linked contest is not chosen again, because a link group does not allow the same candidate twice (§12.6). `linked_candidates` (`:1610`) finds those.

### The authority pipeline inside `tally`

`run_pipeline` (`sim.rs:1415`) is the only place that calls the eg-core pipeline, so it is worth knowing what it calls, in order.

1. `authority::board_view` (the board up to the cutoff, every cast ballot judged, file 24).
2. `section_tallies` and `pool_tally`, then `encrypted_tally` at the STH root of the cutoff.
3. For each section tally with contests to open: `trustee_sets` (`:1499`) has every trustee call `authority::trustee_decrypt`, which refuses to sign a target that does not match the board (file 24). Then `authority::final_bu` combines the valid sets.
4. For the mixnet contests (the Pilot only): `authority::mix_plan`, then `run_mix_chain`, with the mixers in turn.
5. `authority::election_result` assembles the result with the seats.

Every value the driver posts is one that the eg-core functions produce, so the simulator is exactly as correct as the code it calls, and no more. A bug in `judge_cast` is a bug in the simulator and in the verifier at once (see file 25, the deviation).

## The voter's own checks

Two methods on the driver are not EA or machine steps. They are what a voter does, with the public board only.

- `lookup` (`sim.rs:1002`) takes a short code, the code printed on the slip (§17.5). It finds the ballot on the board, reports its status (`cast` or `spoiled`), checks its inclusion proof against the latest STH (`inclusion_ok`, `:1281`), and reports for each contest whether it was counted.
- `check_spoil` (`sim.rs:1030`) takes a spoil receipt, verifies its signature with the machine's key, finds the committed ballot with the same code on the board, and runs `check_reveal` (eg-core `ballot.rs`, file 13) to see whether the receipt's choices re-encrypt to that ballot (§14.2). This is the check a voter does at home.

`recount` (`:996`) returns the honest result, from before any EA change. The attack test below uses it to show that the published result differs.

## The attack switches

`Attacks` (`sim.rs:128`) is a struct of six switches. All are off by default (`Attacks::default()`). Each makes one party misbehave in one specific way. The table gives what the switch does in the code, which check catches it, and which test shows that. Every attack test runs on both scenarios.

"The verifier" means `eg_verify::verify` (file 25). "The voter" means `check_spoil` above.

| switch | what the simulator does (line) | what catches it | tests |
|---|---|---|---|
| `machine_flips_votes` | the machine encrypts the opposite of the voter's choice for contest 0 (`encrypt`, `:731`, via `flip_contest_zero`, `:1588`). When the ballot is spoiled, the machine signs a receipt that claims the voter's own choices (`spoil`, `:775` to `:787`). | **the voter's check**: `check_spoil`. The receipt's choices do not re-encrypt to the committed ballot. **The verifier does not catch it**: see below. | sim: `machine_that_flips_votes_fails_the_spoil_check` |
| `board_drops_package_of` | the board never receives the named machine's package (`close_session`, `:860`). The section attestation of its pre-BU is still posted. | **the verifier, step 7**: the attestation names a package that is missing. Step 7 also gives a warning that the machine has no package. | sim: `dropped_package_leaves_its_attestation_on_the_board`. wasm: `verify_dropped_package_is_flagged_at_step_7` |
| `trustee_lies` | after trustee 3 (`LYING_TRUSTEE`, `sim.rs:54`) signs its decryption shares, the driver changes one share and signs again with the trustee's own key (`trustee_sets`, `:1513`; `corrupt_set`, `:1523`). The signature is valid. The proof is not. | **the verifier, step 11**: `combine` rejects trustee 3's proofs. The result is still produced, because two trustees are enough (`k = 2`). **The pipeline itself** also drops the set, since `final_bu` uses `combine`. | sim: `lying_trustee_is_rejected_and_tally_completes`. wasm: `verify_trustee_lies_fails_at_step_11_and_keeps_result` |
| `ea_alters_result` | before signing, `tally` adds 100 to option 0 of contest 0 and to its count (`:923` to `:925`). The honest recount is kept. | **the verifier, step 15**: the published result differs from the recomputed one. The EA's signature is valid, so only the comparison catches it. | sim: `ea_alteration_differs_from_the_recount`. wasm: `verify_ea_altered_result_fails_at_step_15` |
| `board_equivocates` | after the first STH, `sign_sth` (`:955`) signs a second STH at the same size over a log whose last entry is changed. | **the verifier, step 1**: two STHs at one size with different roots (§17.4). | sim: `equivocating_board_is_detected` (uses `check_sth_pair`). wasm: `verify_equivocating_board_fails_at_step_1` |
| `bad_dkg_share` | trustee 1 sends trustee 2 a share that does not match trustee 1's commitments (`run_ceremony`, `:431`). | **not a failure**: trustee 2 complains, and trustee 1 reveals the correct share. Step 3 requires only that each complaint has a valid reveal, so the verifier should pass the run. | sim: `bad_dkg_share_is_complained_about_and_resolved` (one complaint, reveals present). No verifier test. |

### The one the verifier cannot see

`machine_flips_votes` is the important case, because it shows what the verifier can and cannot check.

On the board, the flipped ballot and its spoiled reveal are consistent with each other. The machine's journal records the choices it actually encrypted, so the spoiled reveal on the board matches the spoiled ballot. Step 8 checks exactly that, and it passes. The **forged** receipt, which claims the voter's choices, is given only to the voter. The verifier never sees it.

The lie is caught by the voter, who compares the receipt with the board using `check_spoil`. If enough voters do that, the lie is found; the verifier alone cannot find it. This is the reason §14.2 asks each voter to check their own receipt, and it is a limit of any verifier that works from the board alone. File 25 notes it under step 8.

### The bad DKG share

`bad_dkg_share` looks like an attack but is designed to be survived. Trustee 1's bad share produces a complaint from trustee 2. The reveal shows the correct share, and the ceremony finishes. The `run_ceremony` return value lists the complaints (`CeremonyReport::complaints`), and the test checks there is one. The verifier should pass the run, because the complaint has a valid reveal, which is all step 3 requires. No verifier test covers this, and it would be a good one to add.

## Tests in `sim.rs`

Nine tests, in the `tests` module (from `sim.rs:1776`). The honest-run test and the attack tests loop over `Scenario::ALL`, so each one runs on both elections.

| test | what it checks |
|---|---|
| `run_all_without_attacks_tallies_and_verifies` | for each scenario, the honest run counts the expected number of ballots in every contest; the lookup of a cast slip finds it as `cast` with an inclusion proof that verifies; the spoil receipt checks out (`check_honest_run`, `:1742`) |
| `starwars_run_all_has_eleven_contests_and_ten_sections` | the Star Wars run has 11 contests and 10 sections, the first contest is the President of the Galactic Republic, every contest is counted, and the board has no `mix` records |
| `scenario_names_round_trip` | each scenario's name parses back to itself; `Simulation::new` is the Pilot |
| `machine_that_flips_votes_fails_the_spoil_check` | the flipped spoil receipt is rejected by `check_spoil`, and the check runs against the committed ballot (not "no committed ballot") |
| `ea_alteration_differs_from_the_recount` | the published option count is the honest one plus 100 |
| `lying_trustee_is_rejected_and_tally_completes` | the run completes and every section matches its pre-BU |
| `dropped_package_leaves_its_attestation_on_the_board` | the dropped machine's package is missing from the board, and its attestation is there |
| `bad_dkg_share_is_complained_about_and_resolved` | one complaint and its reveal are on the board, and the ceremony finishes |
| `equivocating_board_is_detected` | the two STHs share a size and have different roots, and `check_sth_pair` says so |

## The WASM crate

`crates/eg-wasm` builds the simulator and the verifier as a WebAssembly module with `wasm-bindgen`. It is a `cdylib` (and an `rlib`, so the native tests can use it, `Cargo.toml`). It is a **thin wrapper**. It holds no protocol logic.

### How a call travels

Every JavaScript method in `lib.rs` is a small wrapper around a pure-Rust method, which in turn calls the simulator or the verifier:

```
JavaScript               wrapper (lib.rs)           pure Rust (lib.rs)            does the work
sim.run_all()      ->    run_all()            ->    run_all_dto()          ->    Simulation::run_all
                         to_js(...)                 returns Result<ResultDto, Error>
```

- The pure-Rust methods take and return Rust values and `eg_core::Error`. They are the only part the native tests call, because a `#[wasm_bindgen]` method cannot run outside a browser.
- The wrapper converts the result to a JavaScript value with `to_js` (`lib.rs:31`), which uses `serde_wasm_bindgen` in JSON-compatible mode, and turns an error into a `JsError` with `js_err` (`lib.rs:27`). Arguments come in with `from_js` (`lib.rs:37`).

The rule is that a `*_dto` method name is the Rust name with `_dto` added. The exceptions are the methods named for what they return: `phase_name`, `scenario_name`, `board_root_hex`, `entry_json_dto` and `entry_hex_dto`, and `verify_dto`.

### Names on the JavaScript side

- **Methods are snake_case.** `wasm-bindgen` keeps the Rust names, so the methods are `sim.run_all()`, `sim.check_spoil(hex)`, `sim.set_attacks(obj)`, `sim.export_board()`, `sim.entry_json(i)`. The web code uses these names as they are.
- **The constructor is `new Sim(seed)`.** It makes a Pilot election (`lib.rs:266`). The seed is a 32-bit unsigned integer. The wrapper widens it to the 64 bits that `Simulation::new` takes, so seeds above 2^32 cannot be used from JavaScript.
- **A Star Wars election is `Sim.with_scenario(seed, "star-wars")`.** It is a static method, not a constructor. An unknown name is an error that lists the valid names (`with_scenario_dto`, `lib.rs:66`).
- **Free functions are snake_case too.** `scenarios()`, `verify_board(entriesHex, sthsHex)` and `short_code_of(codeHex)` are module-level functions.
- **Data is camelCase.** Every DTO in `dto.rs` has `#[serde(rename_all = "camelCase")]`. So a Rust field `machine_flips_votes` is `machineFlipsVotes` on the wire, and `step_name` is `stepName`.
- **Bytes are lower-case hex.** Digests, signatures and records cross as hex strings. A CBOR value crosses either as CBOR hex (for the raw bytes) or as pretty JSON (`cbor_json`, `dto.rs:82`), with long byte strings shortened to their first 16 hex characters and their length.

### The methods

| JavaScript | Rust (`lib.rs`) | returns |
|---|---|---|
| `scenarios()` | `scenarios` (`:427`) | `[{ id, name }]`: `star-wars` first, then `pilot` (`scenarios_dto`, `dto.rs:190`) |
| `new Sim(seed)` | `Sim::new` (`:266`) | a Pilot in phase `setup` |
| `Sim.with_scenario(seed, id)` | `with_scenario` (`:275`) | a `Sim` for the named scenario |
| `sim.scenario()` | `scenario` (`:280`) | `"pilot"` or `"star-wars"` |
| `sim.phase()` | `phase` (`:285`) | `"setup"`, `"ceremony-done"`, `"polls-open"`, `"polls-closed"` or `"tallied"` |
| `sim.election()` | `election` (`:289`) | the election: scenario, contests, sections, machines and the contests each machine offers, reserve machines, trustees (`ElectionDto`, `dto.rs:232`) |
| `sim.run_ceremony()` | `run_ceremony` (`:293`) | `CeremonyDto`: trustees, threshold, joint key, complaints |
| `sim.open_polls()` | `open_polls` (`:297`) | nothing |
| `sim.open_session(machine, section?)` | `open_session` (`:301`) | `ZeresimaDto` |
| `sim.authorize(machine)` | `authorize` (`:313`) | the authorisation sequence number (`u32`) |
| `sim.encrypt(machine, choices)` | `encrypt` (`:318`) | `EncryptDto` with the full and short code. `choices` is an array of `{ contest, selected }` (`ChoiceDto`, `dto.rs:401`). |
| `sim.cast(machine)` | `cast` (`:323`) | `SlipDto`: the slip the voter takes |
| `sim.spoil(machine)` | `spoil` (`:327`) | `SpoilDto` (`dto.rs:495`): the short code, the receipt in hex and as JSON, and the choices it claims |
| `sim.abandon(machine)` | `abandon` (`:331`) | nothing |
| `sim.close_session(machine)` | `close_session` (`:335`) | `PreBuDto` |
| `sim.cutoff()` | `cutoff` (`:339`) | nothing |
| `sim.tally()` | `tally` (`:343`) | `ResultDto` (the published result, with names) |
| `sim.sign_sth()` | `sign_sth` (`:347`) | an array of `SthDto` (one, or two with `boardEquivocates`) |
| `sim.lookup(shortCode)` | `lookup` (`:351`) | `LookupDto`: found, status, inclusion proof, counted per contest |
| `sim.check_spoil(receiptHex)` | `check_spoil` (`:355`) | `SpoilCheckDto`: ok, message, claimed choices |
| `sim.board()` | `board` (`:359`) | an array of `BoardEntryDto` (`dto.rs:744`): index, kind, detail, leaf hash |
| `sim.board_root()` | `board_root` (`:363`) | the Merkle root of the board as hex |
| `sim.entry_json(i)` | `entry_json` (`:367`) | the entry as pretty JSON text |
| `sim.entry_hex(i)` | `entry_hex` (`:371`) | the entry as CBOR hex |
| `sim.random_choices(machine)` | `random_choices` (`:375`) | a random valid set of choices |
| `sim.cast_random(machine, n)` | `cast_random` (`:379`) | nothing |
| `sim.run_all()` | `run_all` (`:383`) | `ResultDto`, after the whole election |
| `sim.set_attacks(obj)` | `set_attacks` (`:389`) | nothing; `obj` is an `AttacksDto` (below) |
| `sim.get_attacks()` | `get_attacks` (`:395`) | the current `AttacksDto` |
| `sim.export_board()` | `export_board` (`:400`) | `ExportDto` (`dto.rs:764`): `{ entries, sths }`, each a CBOR hex string |
| `sim.verify()` | `verify` (`:405`) | `ReportDto`: runs `eg_verify::verify` over the simulator's own board |
| `verify_board(entriesHex, sthsHex)` | `verify_board` (`:413`) | `ReportDto`: verifies any board given as hex arrays, for example one from `export_board` |
| `short_code_of(codeHex)` | `short_code_of` (`:421`) | the short code of a 32-byte code |

`verify_board` takes the contest and option names from entry 0 when it is a valid signed manifest (`verify_board_dto`, `lib.rs:239`). Without it, names come out as "contest N" and "option N" (`ReportDto::new`, `dto.rs:981`). The names are for display only: the verifier uses the manifest it opened itself for every check.

### The election as JSON

`ElectionDto::new(manifest, registry, scenario)` (`dto.rs:298`) builds the election the UI draws. Its fields, in camelCase:

- `scenario`: `"pilot"` or `"star-wars"`;
- `contests`, `sections`, `trustees`, `parties`, as in the first version;
- `sections[].machines` (ids, kept for compatibility) and `sections[].machineContests`: `[{ id, contests }]`, the same machines with the contest indices each one offers (`MachineOfferDto`, `dto.rs:216`);
- `reserveMachines` (ids, empty in Star Wars) and `reserveMachineContests` (`[{ id, contests }]`).

### The attack switches and the report, as JSON

`AttacksDto` (`dto.rs:782`) has `#[serde(default)]`, so any field left out is off. It has six fields, in camelCase:

```
{ machineFlipsVotes, boardDropsPackageOf, trusteeLies, eaAltersResult, boardEquivocates, badDkgShare }
```

`boardDropsPackageOf` is a machine id string, or `null`.

`ReportDto` (`dto.rs:968`) is what `verify` returns:

- `passed`: true when there are no failures;
- `failures`, `warnings`, `excluded`: arrays of `FindingDto` (`dto.rs:849`) with `step`, `entry` (number or `null`), `section`, `message` and `stepName`;
- `independence`: `trustees`, `releaseSigners`, `mirrors` (each with `organisation`, `bloc`, `fingerprint`), `rules` (`[{ rule, ok }]` for rules 11 to 13), `partyKeys`, `sectionsWithoutObserver`, `partiesWithoutObserver`;
- `contextHash`: hex, or `null` if the ceremony did not verify;
- `result`: `{ contests: [{ index, name, votes: [{ option, votes }], counted, invalid, excluded }] }`, or `null`.

`STEP_NAMES` (`dto.rs:820`) holds the title of each of the sixteen steps, and `step_name` (`dto.rs:840`) looks one up: "Board", "Manifest", "Key ceremony", "Context", "Registry & freeze", "Packages", "Completeness", "Spoiled ballots", "Homomorphic tally", "Mixnet", "Decryption", "Final BUs", "Counts", "Apportionment", "Result", "Independence". The web app can use these as headings.

`phase_name` (`dto.rs:44`) gives the phase string.

### Sharing the crate with the browser

- `eg-wasm` depends on `eg-core` with the `fixtures` feature, because the simulator needs the sample manifests and keys (`Cargo.toml`).
- `getrandom` is set to use `crypto.getRandomValues` (its `js` feature), because the library asks the operating system for random bytes through it, and a browser has no such system call.

## The tests in `tests/native.rs`

The JavaScript methods cannot run outside a browser, so `tests/native.rs` drives the pure-Rust methods (the `*_dto` ones, `phase_name`, `scenario_name` and `verify_dto`) natively. There are 21 tests.

Simulator and DTOs:

| test | what it checks |
|---|---|
| `election_dto_lists_six_contests` | the Pilot has six contests and at least one section; the phase starts at `setup` |
| `run_all_dto_returns_contests_with_votes` | after `run_all_dto`, the phase is `tallied`, every contest has a count, some option has votes, every section matches |
| `board_dto_is_non_empty_after_run` | the board has one entry before the run and more after; entry 0 is index 0 with a 64-character leaf hash |
| `entry_json_of_entry_zero_is_the_signed_manifest` | entry 0 is shown as a `signed_manifest`; an index past the end is an error |
| `vote_flow_through_dto_methods` | a full vote through the DTO methods: open, choose, authorise, encrypt, cast, close, cut off, sign; the lookup finds the slip as cast with an inclusion proof |
| `spoil_receipt_checks_out_through_dto_methods` | a spoil receipt checks out through `check_spoil_dto` |
| `attacks_round_trip_and_reach_the_simulation` | the switches survive the round trip through `AttacksDto`, and `ea_alters_result` changes the published count by 100 |
| `export_board_matches_the_board` | the export has the same number of entries as the board and at least one STH; the root is 64 characters |
| `short_code_of_formats_four_groups` | the short code of 32 zero bytes is `0000-0000-0000-0000-0000`; bad hex is an error |
| `scenarios_list_star_wars_then_pilot` | `scenarios_dto` lists `star-wars` and then `pilot` |
| `unknown_scenario_is_an_error_that_lists_the_names` | an unknown scenario name is an error that names both valid ones |
| `pilot_election_dto_offers_every_contest_on_each_machine` | each regular Pilot machine offers all six contests; the reserve machine is listed with its offers |
| `starwars_election_dto_has_eleven_contests_and_ten_sections` | the Star Wars election has 11 contests and 10 sections; each planet has one machine offering two contests; no reserve machines |

Verifier, through the simulator's boards:

| test | what it checks |
|---|---|
| `verify_honest_run_passes` | an honest Pilot run passes; the only warnings are in §24 (the release-log warning); six contests in the result; three bloc rules |
| `starwars_run_all_verifies_with_only_the_release_log_warning` | an honest Star Wars run passes with only the §24 warning, and its result has 11 contests |
| `verify_ea_altered_result_fails_at_step_15` | the altered result fails at step 15, with the step's name "Result" |
| `verify_trustee_lies_fails_at_step_11_and_keeps_result` | a lying trustee fails at step 11, and the result is still there |
| `verify_equivocating_board_fails_at_step_1` | the second STH makes step 1 fail |
| `verify_dropped_package_is_flagged_at_step_7` | a dropped package fails step 7 and warns at step 7 |
| `verify_board_standalone_names_contests_from_entry_zero` | `verify_board` on an exported board names the contests from the manifest |
| `verify_board_rejects_bad_hex_and_handles_an_empty_board` | bad hex is an error; an empty board gives a failed report with no result |

There is also one unit test in `dto.rs`, `long_bytes_are_shortened_but_digests_are_not`: a 64-byte signature is shortened in the pretty JSON, and a 32-byte digest is shown whole.

The native tests run with `cargo test -p eg-wasm`. They do not need `wasm-pack`.

## Building the browser package

The web app loads a generated package from `web/src/wasm`. To rebuild it, from the `web` directory:

```sh
cd web && bun run wasm
```

`bun run wasm` (`web/package.json`) runs `wasm-pack build crates/eg-wasm --target web --out-dir ../../web/src/wasm --release`, and then removes the `.gitignore` that `wasm-pack` writes into the output directory. You need `wasm-pack` installed, and the Rust `wasm32-unknown-unknown` target that it builds for. The output is `eg_wasm.js`, `eg_wasm_bg.wasm` and their TypeScript declarations, which the app imports directly.

The generated files were not in git when this file was written (they showed as untracked in `git status`). Rebuild them after any change to `eg-core`, `eg-verify` or `eg-wasm`, or the page will run the old code.

## The web app

`web/` holds the browser front end, called "Urna Lab" in `web/DESIGN.md`. Its job, in that brief, is to run a Brazilian polling day from end to end through the WebAssembly module, show every artifact the protocol produces, and let a viewer break things on purpose to see the checks catch them. Its audience is the protocol designer, auditors and party observers, who know the paper of the voting machine but are not cryptographers. The app is being built now, and this file describes only the bindings it uses.

## Design choices

- **The simulator is the only driver of the protocol in the browser.** The browser never calls eg-core directly. Every record is made by the same functions the tests use, so a demo that works is a test that passes.
- **The attack switches are part of the simulator, not of the protocol.** The protocol code has no notion of an attack. The switches change the driver's behaviour in named places, so an attack is visible in one place in the code and cannot leak into the honest path.
- **Two scenarios, one driver.** The Star Wars election exercises the same phases with no mixnet and no link group, and no reserve machine. The attack tests run on both, so a check that only the Pilot exercises is visible as a gap.
- **Pure-Rust methods under the wasm wrappers.** Almost all the logic can be tested natively, and the wrappers are small enough to read in one sitting.
- **camelCase on the wire, snake_case for methods.** The methods are the Rust API, as a Rust reader expects them; the data is the JavaScript reader's shape.
- **The verifier is called as is.** `verify` and `verify_board` run `eg_verify::verify` without any change, so the browser shows the same findings the native verifier gives.

## See also

- File 25 for the verifier, its 16 steps and the tamper table that these switches correspond to.
- File 24 for the pipeline that `tally` runs.
- File 23 for the voting machine that `open_session`, `encrypt`, `cast`, `spoil` and `close_session` drive.
- `docs/spec-issues.md` item 9 for the verifier's dependence on eg-core.
