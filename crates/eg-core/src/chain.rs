//! Tracking codes, the per-session hash chain, slips and Benaloh spoil records
//! (SPEC.md §13 and §14.1 record formats).
//!
//! Each machine session keeps a chain: every ballot's tracking code commits to
//! the head before it, and each decision (cast, spoil, abandon) moves the head
//! forward. Replaying the chain from `head_0` and the sequence of decisions
//! therefore reproduces every code, and any change to an earlier entry changes
//! every later code.

use crate::ballot::{Ballot, BallotId, ContestPlain};
use crate::cbor::{record_fields, Value};
use crate::error::Error;
use crate::hash::digest;
use crate::manifest::{bytes32, decode_list, expect_version, record, schema};
use crate::sign::{sign_record, verify_record, SigningKey, VerifyingKey};

/// Signature tag of a slip (§13.3).
const SIG_SLIP: &str = "eg/v1/sig/slip";
/// Signature tag of a spoil receipt (§14.1).
const SIG_SPOIL: &str = "eg/v1/sig/spoil";
/// Algorithm name of the software measurement (§24.4).
const MEASUREMENT_ALG: &str = "sha256";
/// Crockford base32 alphabet (no I, L, O or U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Number of characters in a short code (§13.2).
const SHORT_CHARS: usize = 20;

/// Software measurement of the machine (`software_measurement`, §24.4):
/// `{ 0: "measurement", 1: "sha256", 2: bstr .size 32 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement(pub [u8; 32]);

impl Measurement {
    /// Encodes as the CBOR map of §24.4.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("measurement")),
            (1, Value::from(MEASUREMENT_ALG)),
            (2, Value::from(self.0)),
        ])
    }

    /// Strict decode of §24.4. The algorithm must be `"sha256"`.
    pub fn from_value(v: &Value) -> Result<Measurement, Error> {
        let f = record_fields(v, "measurement", 3)?;
        if f[1].as_text()? != MEASUREMENT_ALG {
            return Err(schema("software measurement algorithm must be \"sha256\""));
        }
        Ok(Measurement(bytes32(f[2])?))
    }
}

/// Head of the chain before the first ballot (§13.1):
/// `Digest("eg/v1/chain-start", context_hash, machine_id, session_id,
/// software_measurement, opening_challenge)`.
pub fn chain_start(
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    measurement: &Measurement,
    opening_challenge: &[u8; 16],
) -> [u8; 32] {
    digest(
        "eg/v1/chain-start",
        &[
            Value::from(*context_hash),
            Value::from(machine_id),
            Value::from(session_id),
            measurement.to_value(),
            Value::from(&opening_challenge[..]),
        ],
    )
}

/// Tracking code of a ballot (§13.1):
/// `code_s = Digest("eg/v1/code", head_{s-1}, Digest("eg/v1/ballot", ballot_s))`.
pub fn tracking_code(prev_head: &[u8; 32], ballot: &Ballot) -> [u8; 32] {
    digest(
        "eg/v1/code",
        &[Value::from(*prev_head), Value::from(ballot.digest())],
    )
}

/// Outcome of a ballot in the chain (`status_s`, §13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Cast,
    Spoiled,
    Abandoned,
}

impl Status {
    /// The text used in the chain hash.
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Cast => "cast",
            Status::Spoiled => "spoiled",
            Status::Abandoned => "abandoned",
        }
    }
}

/// Next head after a decision (§13.1):
/// `head_s = Digest("eg/v1/chain", code_s, status_s, reveal_digest_s)`, where
/// `reveal_digest_s` is `Digest("eg/v1/reveal", reveal_s)` for spoiled ballots
/// and 32 zero bytes otherwise.
///
/// Panics if `reveal` is `Some` for a status other than `Spoiled`, or `None`
/// for `Spoiled` (programming error).
pub fn next_head(code: &[u8; 32], status: Status, reveal: Option<&Reveal>) -> [u8; 32] {
    let reveal_digest = match (status, reveal) {
        (Status::Spoiled, Some(r)) => r.digest(),
        (Status::Spoiled, None) => panic!("spoiled ballot needs its reveal"),
        (_, Some(_)) => panic!("only spoiled ballots carry a reveal"),
        (_, None) => [0u8; 32],
    };
    digest(
        "eg/v1/chain",
        &[
            Value::from(*code),
            Value::from(status.as_str()),
            Value::from(reveal_digest),
        ],
    )
}

/// Encodes the first 100 bits of `code` as 20 Crockford base32 characters,
/// grouped in fours with hyphens (§13.2).
pub fn short_code(code: &[u8; 32]) -> String {
    let mut out = String::with_capacity(SHORT_CHARS + 4);
    for i in 0..SHORT_CHARS {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        let mut value = 0usize;
        for j in 0..5 {
            value = (value << 1) | bit(code, i * 5 + j) as usize;
        }
        out.push(CROCKFORD[value] as char);
    }
    out
}

/// Parses a short code into its 100 bits, packed as 13 bytes (the low 4 bits of
/// the last byte are zero). Case-insensitive, hyphens optional, and the
/// Crockford aliases O→0 and I/L→1 are accepted. Returns `None` for any other
/// character or a wrong length.
pub fn parse_short_code(s: &str) -> Option<[u8; 13]> {
    let chars: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if chars.len() != SHORT_CHARS {
        return None;
    }
    let mut out = [0u8; 13];
    for (i, &c) in chars.iter().enumerate() {
        let value = crockford_value(c)?;
        for j in 0..5 {
            if (value >> (4 - j)) & 1 == 1 {
                let idx = i * 5 + j;
                out[idx / 8] |= 0x80 >> (idx % 8);
            }
        }
    }
    Some(out)
}

/// True if the first 100 bits of `code` equal the parsed short code.
pub fn short_code_matches(code: &[u8; 32], short: &[u8; 13]) -> bool {
    code[..12] == short[..12] && (code[12] & 0xf0) == (short[12] & 0xf0)
}

/// Bit `idx` (0 = most significant bit of byte 0) of `bytes`.
fn bit(bytes: &[u8], idx: usize) -> u8 {
    (bytes[idx / 8] >> (7 - idx % 8)) & 1
}

/// Value of one Crockford character, applying the aliases, or `None`.
fn crockford_value(c: u8) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    match c {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        _ => CROCKFORD.iter().position(|&a| a == c).map(|p| p as u8),
    }
}

/// Reveal of a spoiled ballot (`reveal`, §14.1): the nonce seed ρ and the
/// selections the machine claims it encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub ballot_id: BallotId,
    pub rho: [u8; 32],
    /// Non-empty (`[+ contest_plain]`).
    pub selections: Vec<ContestPlain>,
}

impl Reveal {
    /// Encodes as the CBOR map of §14.1.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("reveal")),
            (1, Value::Uint(1)),
            (2, self.ballot_id.to_value()),
            (3, Value::from(self.rho)),
            (
                4,
                Value::Array(self.selections.iter().map(ContestPlain::to_value).collect()),
            ),
        ])
    }

    /// Strict decode of §14.1. An empty selection list is rejected.
    pub fn from_value(v: &Value) -> Result<Reveal, Error> {
        let f = record_fields(v, "reveal", 5)?;
        expect_version(f[1])?;
        Ok(Reveal {
            ballot_id: BallotId::from_value(f[2])?,
            rho: bytes32(f[3])?,
            selections: decode_list(f[4], 1, "reveal selections", ContestPlain::from_value)?,
        })
    }

    /// `Digest("eg/v1/reveal", reveal)` (§13.1).
    pub fn digest(&self) -> [u8; 32] {
        digest("eg/v1/reveal", &[self.to_value()])
    }
}

/// Signed slip given to the voter after a cast (`slip`, §13.3). Contains no
/// selections, sequence number or time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slip {
    pub context_hash: [u8; 32],
    pub machine_id: String,
    pub code: [u8; 32],
}

impl Slip {
    /// Builds the signed `slip` record with the machine key.
    pub fn sign(&self, sk: &SigningKey) -> Value {
        sign_record(
            sk,
            SIG_SLIP,
            fields(vec![
                (0, Value::from("slip")),
                (1, Value::Uint(1)),
                (2, Value::from(self.context_hash)),
                (3, Value::from(self.machine_id.as_str())),
                (4, Value::from(self.code)),
            ]),
            5,
        )
    }

    /// Decodes a signed `slip` and verifies it with the machine key.
    pub fn from_signed(v: &Value, machine_pk: &VerifyingKey) -> Result<Slip, Error> {
        let f = record_fields(v, "slip", 6)?;
        verify_record(machine_pk, SIG_SLIP, v, 5)?;
        expect_version(f[1])?;
        Ok(Slip {
            context_hash: bytes32(f[2])?,
            machine_id: f[3].as_text()?.to_owned(),
            code: bytes32(f[4])?,
        })
    }
}

/// Signed spoil receipt (`spoil_receipt`, §14.1). Not a vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoilReceipt {
    pub context_hash: [u8; 32],
    pub machine_id: String,
    pub code: [u8; 32],
    pub reveal: Reveal,
}

impl SpoilReceipt {
    /// Builds the signed `spoil_receipt` record with the machine key.
    pub fn sign(&self, sk: &SigningKey) -> Value {
        sign_record(
            sk,
            SIG_SPOIL,
            fields(vec![
                (0, Value::from("spoil_receipt")),
                (1, Value::Uint(1)),
                (2, Value::from(self.context_hash)),
                (3, Value::from(self.machine_id.as_str())),
                (4, Value::from(self.code)),
                (5, self.reveal.to_value()),
            ]),
            6,
        )
    }

    /// Decodes a signed `spoil_receipt` and verifies it with the machine key.
    pub fn from_signed(v: &Value, machine_pk: &VerifyingKey) -> Result<SpoilReceipt, Error> {
        let f = record_fields(v, "spoil_receipt", 7)?;
        verify_record(machine_pk, SIG_SPOIL, v, 6)?;
        expect_version(f[1])?;
        Ok(SpoilReceipt {
            context_hash: bytes32(f[2])?,
            machine_id: f[3].as_text()?.to_owned(),
            code: bytes32(f[4])?,
            reveal: Reveal::from_value(f[5])?,
        })
    }
}

/// Recomputes a session chain (§13.1). Given `head_0` and the sequence of
/// `(ballot, status, reveal)` entries in sequence order, returns each tracking
/// code and the final head.
///
/// Panics under the same conditions as [`next_head`].
pub fn replay_chain(
    head_0: &[u8; 32],
    entries: &[(&Ballot, Status, Option<&Reveal>)],
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let mut head = *head_0;
    let mut codes = Vec::with_capacity(entries.len());
    for &(ballot, status, reveal) in entries {
        let code = tracking_code(&head, ballot);
        head = next_head(&code, status, reveal);
        codes.push(code);
    }
    (codes, head)
}

/// Builds a signed record's field list from `(uint key, value)` pairs.
fn fields(entries: Vec<(u64, Value)>) -> Vec<(Value, Value)> {
    entries
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{encrypt_ballot, Election};
    use crate::cbor;
    use crate::fixtures::{sample_manifest, sample_registry};
    use crate::group::{random_scalar, B};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest as _, Sha256};

    const CTX: [u8; 32] = [9; 32];
    const MACHINE: &str = "M-S1-01";
    const SESSION: &str = "S-1";

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn bid(seq: u64) -> BallotId {
        BallotId {
            machine_id: MACHINE.into(),
            session_id: SESSION.into(),
            seq,
        }
    }

    /// Encrypts one ballot for the sample election, with the given ρ seed.
    fn ballot(seq: u64, rho_seed: u8) -> Ballot {
        let (manifest, keys) = sample_manifest(1);
        let registry = sample_registry(&manifest, &keys);
        let offered = registry.machine(MACHINE).expect("machine").contests.clone();
        let mut r = rng(3);
        let s = random_scalar(&mut r);
        let election = Election {
            context_hash: CTX,
            k: s * B,
            manifest: &manifest,
        };
        let cp = |contest, selected: Vec<u64>| ContestPlain { contest, selected };
        let choices = vec![
            cp(0, vec![1]),
            cp(1, vec![1]),
            cp(2, vec![4]),
            cp(3, vec![1]),
            cp(4, vec![0]),
            cp(5, vec![2]),
        ];
        let rho = [rho_seed; 32];
        encrypt_ballot(
            &mut rng(rho_seed),
            &election,
            &offered,
            &bid(seq),
            &rho,
            &choices,
        )
        .expect("encrypt")
    }

    fn measurement() -> Measurement {
        Measurement([0x42; 32])
    }

    fn challenge() -> [u8; 16] {
        [7; 16]
    }

    fn reveal_for(b: &Ballot, rho_seed: u8) -> Reveal {
        Reveal {
            ballot_id: b.id.clone(),
            rho: [rho_seed; 32],
            selections: vec![ContestPlain {
                contest: 0,
                selected: vec![1],
            }],
        }
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn arr(items: Vec<Value>) -> Vec<u8> {
        cbor::encode(&Value::Array(items))
    }

    #[test]
    fn chain_start_matches_hand_built_digest() {
        let got = chain_start(&CTX, MACHINE, SESSION, &measurement(), &challenge());
        let measurement_value = Value::Map(vec![
            (Value::Uint(0), Value::from("measurement")),
            (Value::Uint(1), Value::from("sha256")),
            (Value::Uint(2), Value::Bytes(vec![0x42; 32])),
        ]);
        let expected = sha(&arr(vec![
            Value::from("eg/v1/chain-start"),
            Value::Bytes(CTX.to_vec()),
            Value::from(MACHINE),
            Value::from(SESSION),
            measurement_value,
            Value::Bytes(vec![7; 16]),
        ]));
        assert_eq!(got, expected);
    }

    #[test]
    fn tracking_code_matches_hand_built_digest() {
        let b = ballot(1, 11);
        let head = [5u8; 32];
        let ballot_digest = sha(&arr(vec![Value::from("eg/v1/ballot"), b.to_value()]));
        assert_eq!(ballot_digest, b.digest());
        let expected = sha(&arr(vec![
            Value::from("eg/v1/code"),
            Value::Bytes(head.to_vec()),
            Value::Bytes(ballot_digest.to_vec()),
        ]));
        assert_eq!(tracking_code(&head, &b), expected);
    }

    #[test]
    fn next_head_matches_hand_built_digest() {
        let code = [3u8; 32];
        let expected = sha(&arr(vec![
            Value::from("eg/v1/chain"),
            Value::Bytes(code.to_vec()),
            Value::from("cast"),
            Value::Bytes(vec![0; 32]),
        ]));
        assert_eq!(next_head(&code, Status::Cast, None), expected);

        let r = reveal_for(&ballot(1, 11), 11);
        let reveal_digest = sha(&arr(vec![Value::from("eg/v1/reveal"), r.to_value()]));
        let expected_spoiled = sha(&arr(vec![
            Value::from("eg/v1/chain"),
            Value::Bytes(code.to_vec()),
            Value::from("spoiled"),
            Value::Bytes(reveal_digest.to_vec()),
        ]));
        assert_eq!(
            next_head(&code, Status::Spoiled, Some(&r)),
            expected_spoiled
        );
    }

    #[test]
    #[should_panic(expected = "spoiled ballot needs its reveal")]
    fn spoiled_without_reveal_panics() {
        next_head(&[0; 32], Status::Spoiled, None);
    }

    #[test]
    #[should_panic(expected = "only spoiled ballots carry a reveal")]
    fn cast_with_reveal_panics() {
        let r = reveal_for(&ballot(1, 11), 11);
        next_head(&[0; 32], Status::Cast, Some(&r));
    }

    #[test]
    fn later_codes_depend_on_every_earlier_entry() {
        let b0 = ballot(1, 11);
        let b0_other = ballot(1, 12);
        let b1 = ballot(2, 21);
        let b2 = ballot(3, 31);
        let head0 = chain_start(&CTX, MACHINE, SESSION, &measurement(), &challenge());
        let r0 = reveal_for(&b0, 11);
        let r0_other = Reveal {
            rho: [99; 32],
            ..r0.clone()
        };

        let base = [
            (&b0, Status::Cast, None),
            (&b1, Status::Cast, None),
            (&b2, Status::Abandoned, None),
        ];
        let (codes, final_head) = replay_chain(&head0, &base);
        assert_eq!(codes.len(), 3);

        // Same entries replayed again give the same result.
        assert_eq!(replay_chain(&head0, &base), (codes.clone(), final_head));

        // Status of entry 0 changes it and every later code.
        let spoiled0 = [
            (&b0, Status::Spoiled, Some(&r0)),
            (&b1, Status::Cast, None),
            (&b2, Status::Abandoned, None),
        ];
        let (c, h) = replay_chain(&head0, &spoiled0);
        assert_eq!(c[0], codes[0]);
        assert_ne!(c[1], codes[1]);
        assert_ne!(c[2], codes[2]);
        assert_ne!(h, final_head);

        // Reveal of entry 0 changes every later code.
        let reveal_changed = [
            (&b0, Status::Spoiled, Some(&r0_other)),
            (&b1, Status::Cast, None),
            (&b2, Status::Abandoned, None),
        ];
        // Entry 0's own code only depends on head_0 and ballot_0, so it stays.
        let (c, _) = replay_chain(&head0, &reveal_changed);
        let (spoiled_codes, _) = replay_chain(&head0, &spoiled0);
        assert_eq!(c[0], spoiled_codes[0]);
        assert_ne!(c[1], spoiled_codes[1]);
        assert_ne!(c[2], spoiled_codes[2]);

        // Ballot of entry 0 changes every later code.
        let ballot_changed = [
            (&b0_other, Status::Cast, None),
            (&b1, Status::Cast, None),
            (&b2, Status::Abandoned, None),
        ];
        let (c, _) = replay_chain(&head0, &ballot_changed);
        assert_ne!(c[0], codes[0]);
        assert_ne!(c[1], codes[1]);
        assert_ne!(c[2], codes[2]);

        // Changing the middle entry's status leaves its own code (which only
        // depends on the head before it) and changes the codes after it.
        let middle_changed = [
            (&b0, Status::Cast, None),
            (&b1, Status::Abandoned, None),
            (&b2, Status::Abandoned, None),
        ];
        let (c, _) = replay_chain(&head0, &middle_changed);
        assert_eq!(c[0], codes[0]);
        assert_eq!(c[1], codes[1]);
        assert_ne!(c[2], codes[2]);
    }

    #[test]
    fn short_code_known_vectors() {
        assert_eq!(short_code(&[0u8; 32]), "0000-0000-0000-0000-0000");
        assert_eq!(short_code(&[0xff; 32]), "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ");

        // Bytes 08 42 10 84 21 08 42 10 84 21 08 42 10 are the bit pattern
        // 00001 repeated 20 times (100 bits). Each 5-bit group is value 1 ('1'),
        // so the result is 20 ones. Only the first 100 bits are used, so the
        // trailing bits of the 32-byte code don't matter.
        let mut code = [0xaa; 32];
        let pattern = [
            0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10,
        ];
        code[..13].copy_from_slice(&pattern);
        assert_eq!(short_code(&code), "1111-1111-1111-1111-1111");
    }

    #[test]
    fn short_code_round_trip() {
        let mut code = [0u8; 32];
        for (i, b) in code.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let s = short_code(&code);
        assert_eq!(s.len(), 24);
        let parsed = parse_short_code(&s).expect("parses");
        assert!(short_code_matches(&code, &parsed));
        assert_eq!(short_code(&code), s);
        // Re-encoding the parsed bits gives the same display form.
        let mut padded = [0u8; 32];
        padded[..13].copy_from_slice(&parsed);
        assert_eq!(short_code(&padded), s);

        let mut other = code;
        other[11] ^= 0x01;
        assert!(!short_code_matches(&other, &parsed));
        let mut low_nibble = code;
        low_nibble[12] ^= 0x08; // bit 100 is excluded, so the match still holds
        assert!(short_code_matches(&low_nibble, &parsed));
    }

    #[test]
    fn parse_accepts_aliases_case_and_missing_hyphens() {
        let canonical = "K7QD-3XMA-9PRT-2BHW-6YCN";
        let base = parse_short_code(canonical).expect("canonical");
        assert_eq!(parse_short_code("k7qd3xma9prt2bhw6ycn"), Some(base));
        assert_eq!(parse_short_code("K7QD3XMA9PRT2BHW6YCN"), Some(base));

        assert_eq!(
            parse_short_code("0000-0000-0000-0000-0000"),
            parse_short_code("OOOO-OOOO-OOOO-OOOO-OOOO")
        );
        assert_eq!(
            parse_short_code("1111-1111-1111-1111-1111"),
            parse_short_code("IIII-LLLL-iiii-llll-IiLl")
        );
        assert_eq!(
            parse_short_code("0000-0000-0000-0000-0000"),
            Some([0u8; 13])
        );
        assert_eq!(
            parse_short_code("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"),
            Some([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0])
        );
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(parse_short_code("K7QD-3XMA-9PRT-2BHW-6YC"), None);
        assert_eq!(parse_short_code("K7QD-3XMA-9PRT-2BHW-6YCNA"), None);
        assert_eq!(parse_short_code(""), None);
        // U, the other letter Crockford excludes, is not an alias.
        assert_eq!(parse_short_code("U7QD-3XMA-9PRT-2BHW-6YCN"), None);
        assert_eq!(parse_short_code("K7QD-3XMA-9PRT-2BHW-6YC!"), None);
        assert_eq!(parse_short_code("K7QD 3XMA 9PRT 2BHW 6YCN"), None);
    }

    #[test]
    fn measurement_round_trip_and_wrong_algorithm() {
        let m = measurement();
        let v = m.to_value();
        assert_eq!(Measurement::from_value(&v), Ok(m));

        let wrong = record(vec![
            (0, Value::from("measurement")),
            (1, Value::from("sha512")),
            (2, Value::from(m.0)),
        ]);
        assert!(Measurement::from_value(&wrong).is_err());

        let short = record(vec![
            (0, Value::from("measurement")),
            (1, Value::from("sha256")),
            (2, Value::from(&[1u8; 31][..])),
        ]);
        assert!(Measurement::from_value(&short).is_err());
    }

    #[test]
    fn reveal_round_trip_digest_and_empty_rejected() {
        let b = ballot(1, 11);
        let r = reveal_for(&b, 11);
        assert_eq!(Reveal::from_value(&r.to_value()), Ok(r.clone()));

        let r2 = Reveal {
            rho: [12; 32],
            ..r.clone()
        };
        assert_ne!(r.digest(), r2.digest());

        let empty = Reveal {
            selections: vec![],
            ..r.clone()
        };
        assert!(Reveal::from_value(&empty.to_value()).is_err());
    }

    #[test]
    fn slip_sign_verify_and_tamper() {
        let sk = SigningKey::generate(&mut rng(40));
        let other = SigningKey::generate(&mut rng(41));
        let slip = Slip {
            context_hash: CTX,
            machine_id: MACHINE.into(),
            code: [0x5a; 32],
        };
        let signed = slip.sign(&sk);
        assert_eq!(
            Slip::from_signed(&signed, &sk.verifying_key()),
            Ok(slip.clone())
        );
        assert!(Slip::from_signed(&signed, &other.verifying_key()).is_err());

        let tampered = Slip {
            code: [0x5b; 32],
            ..slip.clone()
        };
        let mut bad = signed.clone();
        if let Value::Map(entries) = &mut bad {
            entries[4].1 = Value::from(tampered.code);
        }
        assert!(Slip::from_signed(&bad, &sk.verifying_key()).is_err());
        // Also: a signature over the tampered slip doesn't verify the original.
        assert!(Slip::from_signed(&tampered.sign(&other), &sk.verifying_key()).is_err());
    }

    #[test]
    fn spoil_receipt_sign_verify_and_tamper() {
        let sk = SigningKey::generate(&mut rng(50));
        let other = SigningKey::generate(&mut rng(51));
        let receipt = SpoilReceipt {
            context_hash: CTX,
            machine_id: MACHINE.into(),
            code: [0x6b; 32],
            reveal: reveal_for(&ballot(1, 11), 11),
        };
        let signed = receipt.sign(&sk);
        assert_eq!(
            SpoilReceipt::from_signed(&signed, &sk.verifying_key()),
            Ok(receipt.clone())
        );
        assert!(SpoilReceipt::from_signed(&signed, &other.verifying_key()).is_err());

        // Changing the revealed ρ breaks the signature.
        let mut bad_reveal = receipt.clone();
        bad_reveal.reveal.rho = [0; 32];
        let mut bad = signed.clone();
        if let Value::Map(entries) = &mut bad {
            entries[5].1 = bad_reveal.reveal.to_value();
        }
        assert!(SpoilReceipt::from_signed(&bad, &sk.verifying_key()).is_err());

        // A slip signature doesn't verify as a spoil receipt (different tag).
        let slip = Slip {
            context_hash: CTX,
            machine_id: MACHINE.into(),
            code: receipt.code,
        };
        assert!(SpoilReceipt::from_signed(&slip.sign(&sk), &sk.verifying_key()).is_err());
    }
}
