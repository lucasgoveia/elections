# eg/v1 implementation walkthrough

This walkthrough explains every piece of the `eg-core` crate, and then the verifier (`eg-verify`) and the simulator with its browser bindings (`eg-wasm`). It's written for someone who isn't a cryptographer. For each piece it covers:

- what problem the piece solves;
- which part of `SPEC.md` it implements;
- the idea, with small "toy" numbers you can check by hand;
- the code, function by function, with file paths;
- the design choices and why they were made;
- what the tests check.

Read the files in order. Each layer is built on the ones before it.

## The layers

```
bytes        01 CBOR            one exact byte form for every value
  │
group        02 group           points, scalars, generators, Lagrange
  │
hash         03 hash            fingerprints and Fiat-Shamir challenges
  │
encryption   04 ElGamal         the locked box you can add without opening
  │
proofs       05 Schnorr / CP    "I know the secret", "same secret twice", sum = L, honest decryption
             06 disj01          "this box holds 0 or 1" without saying which
  │
vectors      07 test vectors    fixed answers other implementations must reproduce
  │
messages     08 signatures      who said what, and that it wasn't changed
             09 HPKE            sending a secret to one trustee over a public channel
  │
key ceremony 10 DKG math        a key nobody knows, shared among n trustees
             11 ceremony        the public messages and the public ceremony verifier
  │
rulebook     12 manifest        the public description of the election: contests, trustees, blocs, mirrors
             12 registry        which machine serves which section, and who may sign
  │
ballots      13 ballots         one whole ballot: nonces, encodings, link proofs, judging
             14 tracking codes  the hash chain, cast-or-spoil, slips and spoil receipts
  │
board        15 board log       Merkle tree, signed tree heads, cutoffs
mixnet       16 shuffle         re-encrypt and permute, with a proof anyone can check
  │
result       17 apportionment   from verified totals to seats, with integer-only rules
  │
tally        18 tally           judging ballots, adding the locked boxes, the subtotal fingerprint
journal      19 journal         the machine's hash-chained record, zerésima, pre-BU
decryption   20 decryption      threshold opening, mixnet counting, final BU, results
packages     21 packages        what the board accepts, observers, attestations, the freeze
mixing       22 mixing          mix units, region merging, input lists, the mixer chain
  │
machine      23 voting machine  one polling session: encrypt, cast, spoil, restart, pre-BU, package
pipeline     24 authority       board to result: section tallies, the pool, trustee refusal, seats
  │
verifier     25 verifier         the 16 steps of §23, run on the public board alone
simulator    26 sim and WASM    a whole election in one process, attack switches, browser bindings
```

## Files

| # | file | spec |
|---|---|---|
| 01 | [CBOR](01-cbor.md) | §6 |
| 02 | [Group](02-group.md) | §5.1, §5.2, §5.6, §5.7 |
| 03 | [Hash](03-hash.md) | §5.3 |
| 04 | [ElGamal](04-elgamal.md) | §10, §20.4 |
| 05 | [Schnorr and Chaum-Pedersen proofs](05-proofs-schnorr-cp.md) | §11.1, §11.2, §11.4, §11.6 |
| 06 | [The 0-or-1 proof](06-proofs-disj01.md) | §11.3 |
| 07 | [Test vectors](07-test-vectors.md) | §27 |
| 08 | [Signatures](08-signatures.md) | §5.4 |
| 09 | [HPKE share encryption](09-hpke-share-encryption.md) | §5.5 |
| 10 | [DKG math](10-dkg-math.md) | §8 |
| 11 | [Ceremony records](11-ceremony-records.md) | §7.1, §8, §9 |
| 12 | [Manifest, registry and the sample election](12-manifest-registry.md) | §7, §2.4 |
| 13 | [Ballots](13-ballots.md) | §12, §14.2 |
| 14 | [Tracking codes, slips and spoil receipts](14-tracking-codes.md) | §13, §14 |
| 15 | [Bulletin board log](15-board-log.md) | §17 |
| 16 | [The mixnet shuffle and its proof](16-shuffle.md) | §19.1 to §19.3, Appendix B |
| 17 | [Seat apportionment](17-apportionment.md) | §22 |
| 18 | [Homomorphic tally](18-tally.md) | §12.6, §18 |
| 19 | [Machine journal and zerésima](19-journal.md) | §15, §16.2 |
| 20 | [Threshold decryption, mixnet counting and results](20-decryption-results.md) | §16.5, §19.4 to §19.6, §20, §21 |
| 21 | [Packages and board ingestion](21-packages-ingestion.md) | §16.1, §16.3, §16.4, §17.6, §17.7 |
| 22 | [Mixnet orchestration](22-mixnet-orchestration.md) | §19.1, §19.2, §23 step 10 |
| 23 | [The voting machine: one polling day](23-voting-machine.md) | §13.1, §14.1, §15, §16.1, §16.2, §16.4, §18.1 |
| 24 | [The authority pipeline: from the board to the result](24-authority-pipeline.md) | §16.2, §16.5, §17.7, §18 to §22 |
| 25 | [The verifier: checking a board in 16 steps](25-verifier.md) | §23, §2.4 |
| 26 | [The simulator and the WASM bindings](26-simulation-and-wasm.md) | none directly: drives §8 to §21 and runs §23 |

Files 18 to 22 follow apportionment in the layer order. Each one needs the layers above it: 18 needs ballots (13) and locked boxes (04); 19 needs chains (14) and the tally's imported records (18); 20 needs the tally (18), the shuffle (16) and the seat records (17); 21 needs the journal (19), the manifest (12) and the registry; 22 needs the tally (18) and the shuffle (16).

Files 23 and 24 come last. 23 needs the journal (19), the registry and the packages it produces (21), and the tally's section sums (18). 24 needs the packages (21), the tally (18), the mix plan (22), and decryption and the final BU (20).

File 25 needs the pipeline (24) and every record format below it. It is the check that runs on a board, so it is the place to see the whole protocol at once. File 26 needs everything, and is a demo driver: it plays the election in one process and is never part of a real one.

## The toy group used throughout

Most examples use an "11-hour clock": the numbers 0 to 10, where adding wraps around (8 + 5 = 13, which wraps to 2). The generator is **B = 3**. The real group (Ristretto255) works the same way, but has about 2²⁵² "hours", and you can't work backwards from *x·B* to *x*. In the toy you can, which is what makes it useful for checking examples by hand.

## Running the tests

```sh
cargo test -p eg-core                                  # unit tests + vector checks
cargo clippy -p eg-core --all-targets -- -D warnings   # lints
EG_WRITE_VECTORS=1 cargo test -p eg-core --test vectors   # regenerate test vectors (only after an intended change)
```
