//! Machine journal, zerésima and pre-BU records (SPEC.md §15 and §16.2).
//!
//! The journal is an append-only sequence of records. Each record is stored as
//! deterministic CBOR and framed with a chained digest (§15.1), so any change,
//! deletion or reordering is detected when the frames are read back.
//! [`check_journal`] verifies the invariants of §15.4 over a journal and
//! summarises it. The pre-BU fingerprint is not checked here (§18.1 needs the
//! tally, which the caller recomputes).

use crate::ballot::Ballot;
use crate::board::record_id;
use crate::cbor::{self, record_fields, record_fields_opt, Value};
use crate::chain::{chain_start, next_head, tracking_code, Measurement, Reveal, Status};
use crate::error::Error;
use crate::hash::digest;
use crate::manifest::{bytes32, decode_list, expect_version, record, schema, uint_item};
use crate::sign::{
    self, sign_record, signature_from_value, signature_to_value, verify_record,
    verifying_key_from_value, verifying_key_to_value, Signature, SigningKey, VerifyingKey,
};
use crate::tally::Imported;

/// Version of every journal record (§15.2).
const VERSION: u64 = 1;
/// Digest tag of a journal frame (§15.1).
const FRAME_TAG: &str = "eg/v1/journal";
/// Signature tags (§15.2, §15.5, §16.2).
const SIG_ZERESIMA: &str = "eg/v1/sig/zeresima";
const SIG_SECTION: &str = "eg/v1/sig/section";
const SIG_PRE_BU: &str = "eg/v1/sig/pre-bu";
const SIG_AUTH: &str = "eg/v1/sig/auth";
const SIG_AUTH_CANCEL: &str = "eg/v1/sig/auth-cancel";
const SIG_CHECKPOINT: &str = "eg/v1/sig/checkpoint";

/// Builds a map from `(uint key, value)` pairs, as [`sign_record`] expects.
fn kv(entries: Vec<(u64, Value)>) -> Vec<(Value, Value)> {
    entries
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect()
}

/// Returns a required field of an optional-field record.
fn field<'a>(f: &[Option<&'a Value>], k: usize) -> Result<&'a Value, Error> {
    f.get(k)
        .copied()
        .flatten()
        .ok_or_else(|| schema("missing record field"))
}

fn journal_err(msg: impl Into<String>) -> Error {
    Error::Journal(msg.into())
}

/// `Sign(·, tag, [context_hash, machine_id, session_id, seq])` message of
/// authorizations and cancellations (§15.2).
fn auth_message(context_hash: &[u8; 32], machine_id: &str, session_id: &str, seq: u64) -> Value {
    Value::Array(vec![
        Value::from(*context_hash),
        Value::from(machine_id),
        Value::from(session_id),
        Value::Uint(seq),
    ])
}

/// Signature of an authorization by a poll worker of the section (§15.2).
pub fn auth_signature(
    pw_sk: &SigningKey,
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    seq: u64,
) -> Signature {
    sign::sign(
        pw_sk,
        SIG_AUTH,
        &auth_message(context_hash, machine_id, session_id, seq),
    )
}

/// Signature of an authorization cancellation by a poll worker (§15.2).
pub fn auth_cancel_signature(
    pw_sk: &SigningKey,
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    seq: u64,
) -> Signature {
    sign::sign(
        pw_sk,
        SIG_AUTH_CANCEL,
        &auth_message(context_hash, machine_id, session_id, seq),
    )
}

/// `[context_hash, machine_id, session_id, count, frame_digest, chain_head]`,
/// the object signed by a checkpoint (§15.2).
fn checkpoint_message(
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    count: u64,
    frame_digest: &[u8; 32],
    chain_head: &[u8; 32],
) -> Value {
    Value::Array(vec![
        Value::from(*context_hash),
        Value::from(machine_id),
        Value::from(session_id),
        Value::Uint(count),
        Value::from(*frame_digest),
        Value::from(*chain_head),
    ])
}

/// Machine signature of a checkpoint (§15.2).
#[allow(clippy::too_many_arguments)]
pub fn checkpoint_signature(
    machine_sk: &SigningKey,
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    count: u64,
    frame_digest: &[u8; 32],
    chain_head: &[u8; 32],
) -> Signature {
    sign::sign(
        machine_sk,
        SIG_CHECKPOINT,
        &checkpoint_message(
            context_hash,
            machine_id,
            session_id,
            count,
            frame_digest,
            chain_head,
        ),
    )
}

/// Checks a checkpoint signature against the machine key (§15.2).
#[allow(clippy::too_many_arguments)]
pub fn verify_checkpoint(
    machine_pk: &VerifyingKey,
    context_hash: &[u8; 32],
    machine_id: &str,
    session_id: &str,
    count: u64,
    frame_digest: &[u8; 32],
    chain_head: &[u8; 32],
    sig: &Signature,
) -> bool {
    sign::verify(
        machine_pk,
        SIG_CHECKPOINT,
        &checkpoint_message(
            context_hash,
            machine_id,
            session_id,
            count,
            frame_digest,
            chain_head,
        ),
        sig,
    )
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// `session_open` (§15.2): the first record of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOpen {
    pub context_hash: [u8; 32],
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    pub measurement: Measurement,
    /// Unix seconds. The only time field allowed besides `session_close` (§15.3).
    pub opened_at: u64,
    /// 16 random bytes from the poll terminal (§15.5).
    pub opening_challenge: [u8; 16],
    /// Attestation quote (§24.5), opaque to this module.
    pub attestation: Option<Value>,
}

impl SessionOpen {
    /// Encodes the record as the CBOR map of §15.2.
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("session_open")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.machine_id.as_str())),
            (4, Value::from(self.section_id.as_str())),
            (5, Value::from(self.session_id.as_str())),
            (6, self.measurement.to_value()),
            (7, Value::Uint(self.opened_at)),
            (8, Value::from(&self.opening_challenge[..])),
        ];
        if let Some(attestation) = &self.attestation {
            entries.push((9, attestation.clone()));
        }
        record(entries)
    }

    /// Strict decode of §15.2.
    pub fn from_value(v: &Value) -> Result<SessionOpen, Error> {
        let f = record_fields_opt(v, "session_open", 9, &[9])?;
        expect_version(field(&f, 1)?)?;
        let challenge: [u8; 16] = field(&f, 8)?
            .as_bytes()?
            .try_into()
            .map_err(|_| schema("opening_challenge must be 16 bytes"))?;
        Ok(SessionOpen {
            context_hash: bytes32(field(&f, 2)?)?,
            machine_id: field(&f, 3)?.as_text()?.to_owned(),
            section_id: field(&f, 4)?.as_text()?.to_owned(),
            session_id: field(&f, 5)?.as_text()?.to_owned(),
            measurement: Measurement::from_value(field(&f, 6)?)?,
            opened_at: field(&f, 7)?.as_uint()?,
            opening_challenge: challenge,
            attestation: f.get(9).copied().flatten().cloned(),
        })
    }
}

/// The zerésima (§15.5), signed by the machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zeresima {
    pub context_hash: [u8; 32],
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    pub measurement: Measurement,
    /// Chain head before the first ballot (§13.1).
    pub head_0: [u8; 32],
    /// RecordId of the `session_open` record.
    pub session_open_id: [u8; 32],
    pub opened_at: u64,
}

impl Zeresima {
    /// Builds the machine-signed zerésima (fields 0..9 plus signature 10).
    pub fn sign(&self, machine_sk: &SigningKey) -> Value {
        sign_record(
            machine_sk,
            SIG_ZERESIMA,
            kv(vec![
                (0, Value::from("zeresima")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(self.context_hash)),
                (3, Value::from(self.machine_id.as_str())),
                (4, Value::from(self.section_id.as_str())),
                (5, Value::from(self.session_id.as_str())),
                (6, self.measurement.to_value()),
                (7, Value::from(self.head_0)),
                (8, Value::from(self.session_open_id)),
                (9, Value::Uint(self.opened_at)),
            ]),
            10,
        )
    }

    /// Strict decode of a machine-signed zerésima.
    pub fn from_signed(v: &Value, machine_pk: &VerifyingKey) -> Result<Zeresima, Error> {
        let f = record_fields(v, "zeresima", 11)?;
        verify_record(machine_pk, SIG_ZERESIMA, v, 10)?;
        expect_version(f[1])?;
        Ok(Zeresima {
            context_hash: bytes32(f[2])?,
            machine_id: f[3].as_text()?.to_owned(),
            section_id: f[4].as_text()?.to_owned(),
            session_id: f[5].as_text()?.to_owned(),
            measurement: Measurement::from_value(f[6])?,
            head_0: bytes32(f[7])?,
            session_open_id: bytes32(f[8])?,
            opened_at: f[9].as_uint()?,
        })
    }
}

/// A poll worker or observer signature over a signed record (`section_sig`, §15.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionSig {
    pub key: VerifyingKey,
    pub sig: Signature,
}

/// The object signed by a section signature: `Bytes(RecordId(signed record))`.
fn section_message(signed_record: &Value) -> Value {
    Value::from(record_id(signed_record))
}

impl SectionSig {
    /// Signs a signed record with `sk`.
    pub fn create(sk: &SigningKey, signed_record: &Value) -> SectionSig {
        SectionSig {
            key: sk.verifying_key(),
            sig: sign::sign(sk, SIG_SECTION, &section_message(signed_record)),
        }
    }

    /// Checks the signature over `signed_record`.
    pub fn verify(&self, signed_record: &Value) -> bool {
        sign::verify(
            &self.key,
            SIG_SECTION,
            &section_message(signed_record),
            &self.sig,
        )
    }

    /// Encodes as `[ed25519pk, ed25519sig]`.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            verifying_key_to_value(&self.key),
            signature_to_value(&self.sig),
        ])
    }

    /// Strict decode of `[ed25519pk, ed25519sig]`.
    pub fn from_value(v: &Value) -> Result<SectionSig, Error> {
        match v.as_array()? {
            [k, s] => Ok(SectionSig {
                key: verifying_key_from_value(k)?,
                sig: signature_from_value(s)?,
            }),
            _ => Err(schema("section_sig must be [ed25519pk, ed25519sig]")),
        }
    }
}

/// The pre-BU (§16.2), signed by the machine. Field numbers follow the spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreBu {
    pub context_hash: [u8; 32],
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    /// Recovered packages imported into the section (§16.4).
    pub imported: Vec<Imported>,
    /// Frame digest of the record just before this pre-BU.
    pub frame_digest: [u8; 32],
    /// Chain head at this point.
    pub chain_head: [u8; 32],
    pub authorizations: u64,
    pub cast: u64,
    pub spoiled: u64,
    pub abandoned: u64,
    /// Voter-roll count entered by the poll worker.
    pub roll_count: u64,
    /// Subtotal fingerprint (§18.1).
    pub fingerprint: [u8; 32],
    /// Contests pooled because they have fewer than `min_section_ballots` ballots.
    pub pooled: Vec<u64>,
}

impl PreBu {
    /// Builds the machine-signed pre-BU (fields 0..15 plus signature 16).
    pub fn sign(&self, machine_sk: &SigningKey) -> Value {
        sign_record(
            machine_sk,
            SIG_PRE_BU,
            kv(vec![
                (0, Value::from("pre_bu")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(self.context_hash)),
                (3, Value::from(self.machine_id.as_str())),
                (4, Value::from(self.section_id.as_str())),
                (5, Value::from(self.session_id.as_str())),
                (
                    6,
                    Value::Array(self.imported.iter().map(Imported::to_value).collect()),
                ),
                (7, Value::from(self.frame_digest)),
                (8, Value::from(self.chain_head)),
                (9, Value::Uint(self.authorizations)),
                (10, Value::Uint(self.cast)),
                (11, Value::Uint(self.spoiled)),
                (12, Value::Uint(self.abandoned)),
                (13, Value::Uint(self.roll_count)),
                (14, Value::from(self.fingerprint)),
                (
                    15,
                    Value::Array(self.pooled.iter().map(|&p| Value::Uint(p)).collect()),
                ),
            ]),
            16,
        )
    }

    /// Strict decode of a machine-signed pre-BU.
    pub fn from_signed(v: &Value, machine_pk: &VerifyingKey) -> Result<PreBu, Error> {
        let f = record_fields(v, "pre_bu", 17)?;
        verify_record(machine_pk, SIG_PRE_BU, v, 16)?;
        expect_version(f[1])?;
        Ok(PreBu {
            context_hash: bytes32(f[2])?,
            machine_id: f[3].as_text()?.to_owned(),
            section_id: f[4].as_text()?.to_owned(),
            session_id: f[5].as_text()?.to_owned(),
            imported: decode_list(f[6], 0, "imported", Imported::from_value)?,
            frame_digest: bytes32(f[7])?,
            chain_head: bytes32(f[8])?,
            authorizations: f[9].as_uint()?,
            cast: f[10].as_uint()?,
            spoiled: f[11].as_uint()?,
            abandoned: f[12].as_uint()?,
            roll_count: f[13].as_uint()?,
            fingerprint: bytes32(f[14])?,
            pooled: decode_list(f[15], 0, "pooled", uint_item)?,
        })
    }
}

/// One journal record (§15.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    SessionOpen(SessionOpen),
    /// The signed zerésima and its section signatures (§15.5).
    ZeresimaSigned {
        zeresima: Value,
        sigs: Vec<SectionSig>,
    },
    /// Authorization of one voter (`auth`). Carries no voter data and no time.
    Authorization {
        seq: u64,
        pw_key: VerifyingKey,
        sig: Signature,
    },
    /// A ballot was encrypted and its tracking code shown (`committed`).
    Committed {
        ballot: Ballot,
        code: [u8; 32],
    },
    Cast {
        code: [u8; 32],
    },
    Spoiled {
        code: [u8; 32],
        reveal: Reveal,
    },
    Abandoned {
        code: [u8; 32],
    },
    /// Cancellation of an unused authorization (`auth_cancel`).
    AuthCancel {
        seq: u64,
        pw_key: VerifyingKey,
        sig: Signature,
    },
    Checkpoint {
        count: u64,
        frame_digest: [u8; 32],
        chain_head: [u8; 32],
        sig: Signature,
    },
    /// A recovered package imported into this session (§16.4). Journaled so
    /// that a restarted machine knows which packages its pre-BU must cover.
    Import(Imported),
    /// The pre-BU with its section signatures (§16.2).
    PreBuSigned {
        pre_bu: Value,
        sigs: Vec<SectionSig>,
    },
    SessionClose {
        authorizations: u64,
        cast: u64,
        spoiled: u64,
        abandoned: u64,
        final_head: [u8; 32],
        closed_at: u64,
        /// Closing attestation (§24.5), opaque to this module.
        attestation: Option<Value>,
    },
}

/// Encodes an authorization or cancellation record.
fn key_record(tag: &str, seq: u64, pw_key: &VerifyingKey, sig: &Signature) -> Value {
    record(vec![
        (0, Value::from(tag)),
        (1, Value::Uint(VERSION)),
        (2, Value::Uint(seq)),
        (3, verifying_key_to_value(pw_key)),
        (4, signature_to_value(sig)),
    ])
}

impl Record {
    /// Encodes the record as the CBOR map of §15.2.
    pub fn to_value(&self) -> Value {
        match self {
            Record::SessionOpen(s) => s.to_value(),
            Record::ZeresimaSigned { zeresima, sigs } => record(vec![
                (0, Value::from("zeresima_signed")),
                (1, Value::Uint(VERSION)),
                (2, zeresima.clone()),
                (
                    3,
                    Value::Array(sigs.iter().map(SectionSig::to_value).collect()),
                ),
            ]),
            Record::Authorization { seq, pw_key, sig } => key_record("auth", *seq, pw_key, sig),
            Record::Committed { ballot, code } => record(vec![
                (0, Value::from("committed")),
                (1, Value::Uint(VERSION)),
                (2, ballot.to_value()),
                (3, Value::from(*code)),
            ]),
            Record::Cast { code } => record(vec![
                (0, Value::from("cast")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(*code)),
            ]),
            Record::Spoiled { code, reveal } => record(vec![
                (0, Value::from("spoiled")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(*code)),
                (3, reveal.to_value()),
            ]),
            Record::Abandoned { code } => record(vec![
                (0, Value::from("abandoned")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(*code)),
            ]),
            Record::AuthCancel { seq, pw_key, sig } => key_record("auth_cancel", *seq, pw_key, sig),
            Record::Checkpoint {
                count,
                frame_digest,
                chain_head,
                sig,
            } => record(vec![
                (0, Value::from("checkpoint")),
                (1, Value::Uint(VERSION)),
                (2, Value::Uint(*count)),
                (3, Value::from(*frame_digest)),
                (4, Value::from(*chain_head)),
                (5, signature_to_value(sig)),
            ]),
            Record::Import(imported) => record(vec![
                (0, Value::from("import")),
                (1, Value::Uint(VERSION)),
                (2, imported.to_value()),
            ]),
            Record::PreBuSigned { pre_bu, sigs } => record(vec![
                (0, Value::from("pre_bu_signed")),
                (1, Value::Uint(VERSION)),
                (2, pre_bu.clone()),
                (
                    3,
                    Value::Array(sigs.iter().map(SectionSig::to_value).collect()),
                ),
            ]),
            Record::SessionClose {
                authorizations,
                cast,
                spoiled,
                abandoned,
                final_head,
                closed_at,
                attestation,
            } => {
                let mut entries = vec![
                    (0, Value::from("session_close")),
                    (1, Value::Uint(VERSION)),
                    (2, Value::Uint(*authorizations)),
                    (3, Value::Uint(*cast)),
                    (4, Value::Uint(*spoiled)),
                    (5, Value::Uint(*abandoned)),
                    (6, Value::from(*final_head)),
                    (7, Value::Uint(*closed_at)),
                ];
                if let Some(a) = attestation {
                    entries.push((8, a.clone()));
                }
                record(entries)
            }
        }
    }

    /// Strict decode of a journal record (§15.2). Records are checked for
    /// shape only; the journal checker verifies their meaning.
    pub fn from_value(v: &Value) -> Result<Record, Error> {
        let tag = v
            .get(0)?
            .ok_or_else(|| schema("record has no type tag"))?
            .as_text()?;
        Ok(match tag {
            "session_open" => Record::SessionOpen(SessionOpen::from_value(v)?),
            "zeresima_signed" => {
                let f = record_fields(v, tag, 4)?;
                expect_version(f[1])?;
                Record::ZeresimaSigned {
                    zeresima: f[2].clone(),
                    sigs: decode_list(f[3], 1, "section signatures", SectionSig::from_value)?,
                }
            }
            "auth" | "auth_cancel" => {
                let f = record_fields(v, tag, 5)?;
                expect_version(f[1])?;
                let seq = f[2].as_uint()?;
                let pw_key = verifying_key_from_value(f[3])?;
                let sig = signature_from_value(f[4])?;
                if tag == "auth" {
                    Record::Authorization { seq, pw_key, sig }
                } else {
                    Record::AuthCancel { seq, pw_key, sig }
                }
            }
            "committed" => {
                let f = record_fields(v, tag, 4)?;
                expect_version(f[1])?;
                Record::Committed {
                    ballot: Ballot::from_value(f[2])?,
                    code: bytes32(f[3])?,
                }
            }
            "cast" => {
                let f = record_fields(v, tag, 3)?;
                expect_version(f[1])?;
                Record::Cast {
                    code: bytes32(f[2])?,
                }
            }
            "spoiled" => {
                let f = record_fields(v, tag, 4)?;
                expect_version(f[1])?;
                Record::Spoiled {
                    code: bytes32(f[2])?,
                    reveal: Reveal::from_value(f[3])?,
                }
            }
            "abandoned" => {
                let f = record_fields(v, tag, 3)?;
                expect_version(f[1])?;
                Record::Abandoned {
                    code: bytes32(f[2])?,
                }
            }
            "checkpoint" => {
                let f = record_fields(v, tag, 6)?;
                expect_version(f[1])?;
                Record::Checkpoint {
                    count: f[2].as_uint()?,
                    frame_digest: bytes32(f[3])?,
                    chain_head: bytes32(f[4])?,
                    sig: signature_from_value(f[5])?,
                }
            }
            "import" => {
                let f = record_fields(v, tag, 3)?;
                expect_version(f[1])?;
                Record::Import(Imported::from_value(f[2])?)
            }
            "pre_bu_signed" => {
                let f = record_fields(v, tag, 4)?;
                expect_version(f[1])?;
                Record::PreBuSigned {
                    pre_bu: f[2].clone(),
                    sigs: decode_list(f[3], 1, "section signatures", SectionSig::from_value)?,
                }
            }
            "session_close" => {
                let f = record_fields_opt(v, tag, 8, &[8])?;
                expect_version(field(&f, 1)?)?;
                Record::SessionClose {
                    authorizations: field(&f, 2)?.as_uint()?,
                    cast: field(&f, 3)?.as_uint()?,
                    spoiled: field(&f, 4)?.as_uint()?,
                    abandoned: field(&f, 5)?.as_uint()?,
                    final_head: bytes32(field(&f, 6)?)?,
                    closed_at: field(&f, 7)?.as_uint()?,
                    attestation: f.get(8).copied().flatten().cloned(),
                }
            }
            other => return Err(schema(format!("unknown record type {other:?}"))),
        })
    }
}

// ---------------------------------------------------------------------------
// Framing (§15.1)
// ---------------------------------------------------------------------------

/// Frame digest: `Digest("eg/v1/journal", prev_frame_digest, CBOR(record))`.
pub fn frame_digest(prev: &[u8; 32], record_bytes: &[u8]) -> [u8; 32] {
    digest(
        FRAME_TAG,
        &[Value::from(*prev), Value::Bytes(record_bytes.to_vec())],
    )
}

/// True if `bytes[at..]` starts with a complete CBOR record followed by its
/// 32-byte frame digest under `prev`. A CBOR item carries its own length, so
/// this works without trusting the frame's length field.
fn intact_record_at(bytes: &[u8], at: usize, prev: &[u8; 32]) -> bool {
    let Some(rest) = bytes.get(at..) else {
        return false;
    };
    let Ok((_, used)) = cbor::decode_prefix(rest) else {
        return false;
    };
    let Some(stored) = rest.get(used..used + 32) else {
        return false;
    };
    stored == frame_digest(prev, &rest[..used])
}

/// An in-memory journal. Keeps the CBOR of each record and its frame digest,
/// so the framed bytes can be produced without re-encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Journal {
    records: Vec<Record>,
    /// CBOR of each record.
    bytes: Vec<Vec<u8>>,
    /// Frame digest of each record.
    digests: Vec<[u8; 32]>,
}

impl Journal {
    /// An empty journal.
    pub fn new() -> Journal {
        Journal::default()
    }

    /// Appends a record and returns the new frame digest.
    pub fn append(&mut self, r: Record) -> [u8; 32] {
        let bytes = cbor::encode(&r.to_value());
        let d = frame_digest(&self.last_digest(), &bytes);
        self.records.push(r);
        self.bytes.push(bytes);
        self.digests.push(d);
        d
    }

    /// The records, in order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Frame digest of the last record, or 32 zero bytes if empty.
    pub fn last_digest(&self) -> [u8; 32] {
        self.digests.last().copied().unwrap_or([0; 32])
    }

    /// Frame digest of the record before index `idx` (zeros for `idx == 0`).
    ///
    /// Panics if `idx` is greater than [`Journal::len`].
    pub fn digest_before(&self, idx: usize) -> [u8; 32] {
        if idx == 0 {
            [0; 32]
        } else {
            self.digests[idx - 1]
        }
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if the journal has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The framed journal: `u32_be(len) || CBOR || digest` for each record.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (b, d) in self.bytes.iter().zip(&self.digests) {
            let len = u32::try_from(b.len()).expect("journal record fits in u32");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b);
            out.extend_from_slice(d);
        }
        out
    }

    /// Parses framed bytes and verifies each frame digest.
    ///
    /// A truncated final frame (a torn write) is dropped and reported through
    /// the returned flag. Any other damage (bad digest, malformed record, a
    /// damaged length field in front of an intact record) is an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Journal, bool), Error> {
        let mut journal = Journal::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let idx = journal.len();
            let Some(prefix) = bytes.get(pos..pos + 4) else {
                return Ok((journal, true));
            };
            let n = u32::from_be_bytes(prefix.try_into().expect("four bytes")) as usize;
            let Some(end) = pos.checked_add(n).and_then(|x| x.checked_add(36)) else {
                return Err(journal_err(format!("record {idx}: frame length overflows")));
            };
            let Some(frame) = bytes.get(pos..end) else {
                // The frame runs past the end. That is a torn final write only
                // if the record behind the length field is itself incomplete.
                // A complete record with a matching digest means the length
                // field is damaged, and the frames after it would be lost.
                if intact_record_at(bytes, pos + 4, &journal.last_digest()) {
                    return Err(journal_err(format!(
                        "record {idx}: length field is damaged; the record behind it is intact"
                    )));
                }
                return Ok((journal, true));
            };
            let body = &frame[4..4 + n];
            let stored: [u8; 32] = frame[4 + n..].try_into().expect("32-byte digest");
            let value = cbor::decode(body)?;
            let rec = Record::from_value(&value)
                .map_err(|e| journal_err(format!("record {idx}: malformed: {e}")))?;
            let expected = frame_digest(&journal.last_digest(), body);
            if stored != expected {
                return Err(journal_err(format!("record {idx}: frame digest mismatch")));
            }
            journal.records.push(rec);
            journal.bytes.push(body.to_vec());
            journal.digests.push(expected);
            pos = end;
        }
        Ok((journal, false))
    }

    /// Builds a journal by appending each record in turn.
    pub fn from_records(records: Vec<Record>) -> Journal {
        let mut journal = Journal::new();
        for r in records {
            journal.append(r);
        }
        journal
    }
}

// ---------------------------------------------------------------------------
// Invariant checker (§15.4)
// ---------------------------------------------------------------------------

/// Keys and parameters needed to check a session's journal.
pub struct SessionKeys<'a> {
    pub context_hash: [u8; 32],
    /// The machine that wrote the journal.
    pub machine_key: VerifyingKey,
    /// Poll worker keys of the session's section (§7.7).
    pub poll_worker_keys: &'a [VerifyingKey],
    /// Section threshold for pooling (§18), carried for the caller.
    pub min_section_ballots: u64,
}

/// What a checked journal says about its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSummary {
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    pub measurement: Measurement,
    pub head_0: [u8; 32],
    /// Tracking code and status of every committed ballot, in order.
    pub codes: Vec<([u8; 32], Status)>,
    pub final_head: [u8; 32],
    pub authorizations: u64,
    pub cast: u64,
    pub spoiled: u64,
    pub abandoned: u64,
    /// Explicit cancellations, plus unused authorizations of a recovered journal.
    pub cancelled: u64,
    /// Recovered packages imported into the session, in journal order (§16.4).
    pub imports: Vec<Imported>,
    pub pre_bu: Option<PreBu>,
    /// True if the journal ends with the full §15.4 ending.
    pub complete: bool,
}

/// Error for record `i` in the form `record i: rule`.
fn fail<T>(i: usize, msg: impl std::fmt::Display) -> Result<T, Error> {
    Err(journal_err(format!("record {i}: {msg}")))
}

struct Checker<'a> {
    keys: &'a SessionKeys<'a>,
    complete: bool,
    open: Option<SessionOpen>,
    head_0: [u8; 32],
    head: [u8; 32],
    /// The authorization journaled and not yet cast or cancelled.
    unused: Option<u64>,
    next_seq: u64,
    /// The committed ballot waiting for its status, with its code.
    pending: Option<(Ballot, [u8; 32])>,
    /// Set after a record that must be followed by a checkpoint.
    need_checkpoint: bool,
    pre_bu: Option<PreBu>,
    imports: Vec<Imported>,
    closed: bool,
    authorizations: u64,
    cast: u64,
    spoiled: u64,
    abandoned: u64,
    cancelled: u64,
    codes: Vec<([u8; 32], Status)>,
}

impl<'a> Checker<'a> {
    fn new(keys: &'a SessionKeys<'a>, complete: bool) -> Checker<'a> {
        Checker {
            keys,
            complete,
            open: None,
            head_0: [0; 32],
            head: [0; 32],
            unused: None,
            next_seq: 1,
            pending: None,
            need_checkpoint: false,
            pre_bu: None,
            imports: Vec::new(),
            closed: false,
            authorizations: 0,
            cast: 0,
            spoiled: 0,
            abandoned: 0,
            cancelled: 0,
            codes: Vec::new(),
        }
    }

    fn session(&self, i: usize) -> Result<&SessionOpen, Error> {
        self.open
            .as_ref()
            .ok_or_else(|| journal_err(format!("record {i}: no session_open before it")))
    }

    fn is_poll_worker(&self, key: &VerifyingKey) -> bool {
        self.keys.poll_worker_keys.contains(key)
    }

    fn take_pending(&mut self, i: usize, what: &str) -> Result<(Ballot, [u8; 32]), Error> {
        self.pending
            .take()
            .ok_or_else(|| journal_err(format!("record {i}: {what} without a committed ballot")))
    }

    fn step(&mut self, i: usize, rec: &Record, journal: &Journal) -> Result<(), Error> {
        if i == 0 {
            return match rec {
                Record::SessionOpen(so) => self.on_session_open(i, so),
                _ => fail(i, "journal must begin with session_open"),
            };
        }
        if i == 1 {
            return match rec {
                Record::ZeresimaSigned { zeresima, sigs } => {
                    self.on_zeresima(i, zeresima, sigs)
                }
                _ => fail(
                    i,
                    "zeresima_signed must directly follow session_open (no authorization may precede it)",
                ),
            };
        }
        if self.closed {
            return fail(i, "record after session_close");
        }
        if self.pending.is_some()
            && !matches!(
                rec,
                Record::Cast { .. } | Record::Spoiled { .. } | Record::Abandoned { .. }
            )
        {
            // Checkpoints follow only status records, so a recovered journal cut
            // at its last checkpoint never ends inside a ballot: an unfinished
            // ballot sits after that checkpoint and is discarded (§16.4).
            return fail(
                i,
                "committed ballot has no cast, spoiled or abandoned record",
            );
        }
        if self.need_checkpoint && !matches!(rec, Record::Checkpoint { .. }) {
            return fail(i, format!("missing checkpoint after record {}", i - 1));
        }
        if self.pre_bu.is_some()
            && !matches!(rec, Record::Checkpoint { .. } | Record::SessionClose { .. })
        {
            return fail(
                i,
                "only the checkpoint and session_close may follow pre_bu_signed",
            );
        }
        match rec {
            Record::SessionOpen(_) | Record::ZeresimaSigned { .. } => fail(
                i,
                "session_open and zeresima_signed appear only once, at the start",
            ),
            Record::Authorization { seq, pw_key, sig } => {
                self.on_authorization(i, *seq, pw_key, sig)
            }
            Record::Committed { ballot, code } => self.on_committed(i, ballot, *code),
            Record::Cast { code } => self.on_cast(i, *code),
            Record::Spoiled { code, reveal } => self.on_spoiled(i, *code, reveal),
            Record::Abandoned { code } => self.on_abandoned(i, *code),
            Record::AuthCancel { seq, pw_key, sig } => self.on_cancel(i, *seq, pw_key, sig),
            Record::Checkpoint {
                count,
                frame_digest,
                chain_head,
                sig,
            } => self.on_checkpoint(i, journal, *count, *frame_digest, *chain_head, sig),
            Record::Import(imported) => self.on_import(i, imported),
            Record::PreBuSigned { pre_bu, sigs } => self.on_pre_bu(i, journal, pre_bu, sigs),
            Record::SessionClose {
                authorizations,
                cast,
                spoiled,
                abandoned,
                final_head,
                ..
            } => self.on_close(
                i,
                [*authorizations, *cast, *spoiled, *abandoned],
                *final_head,
            ),
        }
    }

    fn on_session_open(&mut self, i: usize, so: &SessionOpen) -> Result<(), Error> {
        if so.context_hash != self.keys.context_hash {
            return fail(i, "session context hash differs from the election");
        }
        self.open = Some(so.clone());
        Ok(())
    }

    fn on_zeresima(&mut self, i: usize, value: &Value, sigs: &[SectionSig]) -> Result<(), Error> {
        let so = self.session(i)?;
        let z = Zeresima::from_signed(value, &self.keys.machine_key).map_err(|_| {
            journal_err(format!(
                "record {i}: zeresima_signed is malformed or not signed by the machine"
            ))
        })?;
        if z.context_hash != so.context_hash
            || z.machine_id != so.machine_id
            || z.section_id != so.section_id
            || z.session_id != so.session_id
            || z.measurement != so.measurement
            || z.opened_at != so.opened_at
        {
            return fail(i, "zeresima fields differ from session_open");
        }
        if z.session_open_id != record_id(&so.to_value()) {
            return fail(
                i,
                "zeresima session_open_id is not the record id of session_open",
            );
        }
        let head_0 = chain_start(
            &so.context_hash,
            &so.machine_id,
            &so.session_id,
            &so.measurement,
            &so.opening_challenge,
        );
        if z.head_0 != head_0 {
            return fail(i, "zeresima head_0 is not chain_start of the session");
        }
        if !sigs
            .iter()
            .any(|s| self.is_poll_worker(&s.key) && s.verify(value))
        {
            return fail(i, "zeresima has no valid poll worker signature");
        }
        self.head_0 = head_0;
        self.head = head_0;
        self.need_checkpoint = true;
        Ok(())
    }

    fn on_authorization(
        &mut self,
        i: usize,
        seq: u64,
        pw_key: &VerifyingKey,
        sig: &Signature,
    ) -> Result<(), Error> {
        if seq != self.next_seq {
            return fail(
                i,
                format!("auth_seq {seq} where {} was expected", self.next_seq),
            );
        }
        if self.unused.is_some() {
            return fail(
                i,
                "second unused authorization: the previous one must be cast or cancelled first",
            );
        }
        let so = self.session(i)?;
        let msg = auth_message(&so.context_hash, &so.machine_id, &so.session_id, seq);
        if !self.is_poll_worker(pw_key) || !sign::verify(pw_key, SIG_AUTH, &msg, sig) {
            return fail(
                i,
                "authorization is not signed by a poll worker of the section",
            );
        }
        self.unused = Some(seq);
        self.next_seq += 1;
        self.authorizations += 1;
        Ok(())
    }

    fn on_committed(&mut self, i: usize, ballot: &Ballot, code: [u8; 32]) -> Result<(), Error> {
        let so = self.session(i)?;
        if ballot.context_hash != so.context_hash {
            return fail(i, "committed ballot belongs to another election");
        }
        if code != tracking_code(&self.head, ballot) {
            return fail(i, "committed code is not the tracking code of its ballot");
        }
        self.pending = Some((ballot.clone(), code));
        Ok(())
    }

    fn on_cast(&mut self, i: usize, code: [u8; 32]) -> Result<(), Error> {
        if self.unused.take().is_none() {
            return fail(i, "cast without an unused authorization");
        }
        let (_, pending_code) = self.take_pending(i, "cast")?;
        if pending_code != code {
            return fail(i, "cast code is not the pending committed ballot");
        }
        self.head = next_head(&code, Status::Cast, None);
        self.codes.push((code, Status::Cast));
        self.cast += 1;
        self.need_checkpoint = true;
        Ok(())
    }

    fn on_spoiled(&mut self, i: usize, code: [u8; 32], reveal: &Reveal) -> Result<(), Error> {
        let (ballot, pending_code) = self.take_pending(i, "spoiled")?;
        if pending_code != code {
            return fail(i, "spoiled code is not the pending committed ballot");
        }
        if reveal.ballot_id != ballot.id {
            return fail(i, "spoiled reveal names a different ballot");
        }
        self.head = next_head(&code, Status::Spoiled, Some(reveal));
        self.codes.push((code, Status::Spoiled));
        self.spoiled += 1;
        self.need_checkpoint = true;
        Ok(())
    }

    fn on_abandoned(&mut self, i: usize, code: [u8; 32]) -> Result<(), Error> {
        let (_, pending_code) = self.take_pending(i, "abandoned")?;
        if pending_code != code {
            return fail(i, "abandoned code is not the pending committed ballot");
        }
        self.head = next_head(&code, Status::Abandoned, None);
        self.codes.push((code, Status::Abandoned));
        self.abandoned += 1;
        self.need_checkpoint = true;
        Ok(())
    }

    fn on_cancel(
        &mut self,
        i: usize,
        seq: u64,
        pw_key: &VerifyingKey,
        sig: &Signature,
    ) -> Result<(), Error> {
        if self.unused != Some(seq) {
            return fail(
                i,
                format!("auth_cancel names auth_seq {seq}, which is not the unused authorization"),
            );
        }
        let so = self.session(i)?;
        let msg = auth_message(&so.context_hash, &so.machine_id, &so.session_id, seq);
        if !self.is_poll_worker(pw_key) || !sign::verify(pw_key, SIG_AUTH_CANCEL, &msg, sig) {
            return fail(
                i,
                "cancellation is not signed by a poll worker of the section",
            );
        }
        self.unused = None;
        self.cancelled += 1;
        Ok(())
    }

    fn on_checkpoint(
        &mut self,
        i: usize,
        journal: &Journal,
        count: u64,
        frame_digest: [u8; 32],
        chain_head: [u8; 32],
        sig: &Signature,
    ) -> Result<(), Error> {
        if count != i as u64 {
            return fail(
                i,
                format!("checkpoint count {count} but {i} records precede it"),
            );
        }
        if frame_digest != journal.digest_before(i) {
            return fail(
                i,
                "checkpoint frame digest is not the digest of the previous record",
            );
        }
        if chain_head != self.head {
            return fail(i, "checkpoint chain head does not match the chain");
        }
        let so = self.session(i)?;
        if !verify_checkpoint(
            &self.keys.machine_key,
            &so.context_hash,
            &so.machine_id,
            &so.session_id,
            count,
            &frame_digest,
            &chain_head,
            sig,
        ) {
            return fail(i, "checkpoint is not signed by the machine");
        }
        self.need_checkpoint = false;
        Ok(())
    }

    fn on_import(&mut self, i: usize, imported: &Imported) -> Result<(), Error> {
        if self
            .imports
            .iter()
            .any(|x| x.package_id == imported.package_id)
        {
            return fail(i, "recovered package is imported twice");
        }
        self.imports.push(imported.clone());
        Ok(())
    }

    fn on_pre_bu(
        &mut self,
        i: usize,
        journal: &Journal,
        value: &Value,
        sigs: &[SectionSig],
    ) -> Result<(), Error> {
        let so = self.session(i)?;
        let pb = PreBu::from_signed(value, &self.keys.machine_key).map_err(|_| {
            journal_err(format!(
                "record {i}: pre_bu is malformed or not signed by the machine"
            ))
        })?;
        if pb.context_hash != so.context_hash
            || pb.machine_id != so.machine_id
            || pb.section_id != so.section_id
            || pb.session_id != so.session_id
        {
            return fail(i, "pre_bu identifiers differ from the session");
        }
        if pb.frame_digest != journal.digest_before(i) {
            return fail(
                i,
                "pre_bu frame digest is not the digest of the previous record",
            );
        }
        if pb.chain_head != self.head {
            return fail(i, "pre_bu chain head does not match the chain");
        }
        let counts = [self.authorizations, self.cast, self.spoiled, self.abandoned];
        if [pb.authorizations, pb.cast, pb.spoiled, pb.abandoned] != counts {
            return fail(i, "pre_bu counts do not match the journal");
        }
        if pb.imported != self.imports {
            return fail(i, "pre_bu imports differ from the imports in the journal");
        }
        if !sigs
            .iter()
            .any(|s| self.is_poll_worker(&s.key) && s.verify(value))
        {
            return fail(i, "pre_bu has no valid poll worker signature");
        }
        self.pre_bu = Some(pb);
        self.need_checkpoint = true;
        Ok(())
    }

    /// `counts` is `[authorizations, cast, spoiled, abandoned]`.
    fn on_close(&mut self, i: usize, counts: [u64; 4], final_head: [u8; 32]) -> Result<(), Error> {
        if self.pre_bu.is_none() {
            return fail(i, "session_close without pre_bu_signed");
        }
        if counts != [self.authorizations, self.cast, self.spoiled, self.abandoned] {
            return fail(i, "session_close counts do not match the journal");
        }
        if final_head != self.head {
            return fail(i, "session_close final chain head does not match the chain");
        }
        if self.cast.checked_add(self.cancelled) != Some(self.authorizations) {
            return fail(
                i,
                "session_close: authorizations must equal cast plus cancellations",
            );
        }
        self.closed = true;
        Ok(())
    }

    fn finish(self, journal: &Journal) -> Result<JournalSummary, Error> {
        let so = self
            .open
            .ok_or_else(|| journal_err("journal has no session_open"))?;
        let ends_with_checkpoint =
            matches!(journal.records().last(), Some(Record::Checkpoint { .. }));
        let mut cancelled = self.cancelled;
        if self.complete {
            if !self.closed {
                return Err(journal_err("journal does not end with session_close"));
            }
        } else {
            if !ends_with_checkpoint {
                return Err(journal_err("recovered journal is not cut at a checkpoint"));
            }
            // Recovered journals: unused authorizations count as cancelled (§15.4).
            if self.unused.is_some() {
                cancelled += 1;
            }
        }
        Ok(JournalSummary {
            machine_id: so.machine_id,
            section_id: so.section_id,
            session_id: so.session_id,
            measurement: so.measurement,
            head_0: self.head_0,
            codes: self.codes,
            final_head: self.head,
            authorizations: self.authorizations,
            cast: self.cast,
            spoiled: self.spoiled,
            abandoned: self.abandoned,
            cancelled,
            imports: self.imports,
            pre_bu: self.pre_bu,
            complete: self.complete,
        })
    }
}

/// Checks every §15.4 rule over `journal` and summarises the session.
///
/// `complete = true` requires the full ending (`pre_bu_signed`, its checkpoint,
/// `session_close`). `complete = false` checks a recovered journal (§16.4): it
/// must end with a checkpoint, a committed ballot without status is abandoned,
/// and unused authorizations are cancelled.
///
/// The pre-BU fingerprint is not checked here; the caller recomputes it.
pub fn check_journal(
    keys: &SessionKeys<'_>,
    journal: &Journal,
    complete: bool,
) -> Result<JournalSummary, Error> {
    if journal.is_empty() {
        return Err(journal_err("journal is empty"));
    }
    let mut checker = Checker::new(keys, complete);
    for (i, rec) in journal.records().iter().enumerate() {
        checker.step(i, rec, journal)?;
    }
    checker.finish(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{encrypt_ballot, BallotId, ContestPlain, Election};
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::group::{random_scalar, RistrettoPoint, B};
    use crate::manifest::Manifest;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    const MACHINE: &str = "M-S1-01";
    const SECTION: &str = "S1";
    const SESSION: &str = "S-1";
    const OPENED_AT: u64 = 1_700_000_000;
    const CHALLENGE: [u8; 16] = [5; 16];

    struct World {
        manifest: Manifest,
        keys: Keys,
        ctx: [u8; 32],
        k: RistrettoPoint,
        offered: Vec<u64>,
        poll_keys: Vec<VerifyingKey>,
    }

    fn world() -> World {
        let (manifest, keys) = sample_manifest(1);
        let registry = sample_registry(&manifest, &keys);
        let offered = registry.machine(MACHINE).expect("machine").contests.clone();
        let poll_keys = registry
            .section(SECTION)
            .expect("section")
            .poll_worker_keys
            .clone();
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let k = random_scalar(&mut rng) * B;
        let ctx = manifest.hash();
        World {
            manifest,
            keys,
            ctx,
            k,
            offered,
            poll_keys,
        }
    }

    fn skeys(w: &World) -> SessionKeys<'_> {
        SessionKeys {
            context_hash: w.ctx,
            machine_key: w.keys.machines[0].verifying_key(),
            poll_worker_keys: &w.poll_keys,
            min_section_ballots: 1,
        }
    }

    fn session_open(w: &World) -> SessionOpen {
        SessionOpen {
            context_hash: w.ctx,
            machine_id: MACHINE.into(),
            section_id: SECTION.into(),
            session_id: SESSION.into(),
            measurement: Measurement([7; 32]),
            opened_at: OPENED_AT,
            opening_challenge: CHALLENGE,
            attestation: None,
        }
    }

    fn head_0_of(so: &SessionOpen) -> [u8; 32] {
        chain_start(
            &so.context_hash,
            &so.machine_id,
            &so.session_id,
            &so.measurement,
            &so.opening_challenge,
        )
    }

    fn zeresima_record(w: &World, so: &SessionOpen, head_0: [u8; 32]) -> Record {
        let z = Zeresima {
            context_hash: so.context_hash,
            machine_id: so.machine_id.clone(),
            section_id: so.section_id.clone(),
            session_id: so.session_id.clone(),
            measurement: so.measurement,
            head_0,
            session_open_id: record_id(&so.to_value()),
            opened_at: so.opened_at,
        };
        let zv = z.sign(&w.keys.machines[0]);
        let sig = SectionSig::create(&w.keys.poll_workers[0], &zv);
        Record::ZeresimaSigned {
            zeresima: zv,
            sigs: vec![sig],
        }
    }

    fn auth_record(w: &World, seq: u64) -> Record {
        let pw = &w.keys.poll_workers[0];
        Record::Authorization {
            seq,
            pw_key: pw.verifying_key(),
            sig: auth_signature(pw, &w.ctx, MACHINE, SESSION, seq),
        }
    }

    /// Choices for the six contests of the sample manifest (rows of tally tests).
    fn picks(row: usize) -> Vec<ContestPlain> {
        let rows: [[Vec<u64>; 6]; 3] = [
            [vec![1], vec![1], vec![4], vec![1], vec![0], vec![2]],
            [vec![1], vec![0, 3], vec![4], vec![1], vec![0], vec![1]],
            [vec![0], vec![], vec![0], vec![1], vec![1], vec![2]],
        ];
        rows[row]
            .iter()
            .enumerate()
            .map(|(c, sel)| ContestPlain {
                contest: c as u64,
                selected: sel.clone(),
            })
            .collect()
    }

    struct Pending {
        ballot: Ballot,
        code: [u8; 32],
        rho: [u8; 32],
        choices: Vec<ContestPlain>,
    }

    /// Plays the machine: journals records and tracks the chain as the machine would.
    struct Builder<'a> {
        w: &'a World,
        recs: Vec<Record>,
        last: [u8; 32],
        head: [u8; 32],
        rng: ChaCha20Rng,
        ballots: u64,
        pending: Option<Pending>,
        unused: Option<u64>,
        next_seq: u64,
        /// authorizations, cast, spoiled, abandoned
        counts: [u64; 4],
        cancels: u64,
    }

    impl<'a> Builder<'a> {
        fn new(w: &'a World) -> Builder<'a> {
            let so = session_open(w);
            let head = head_0_of(&so);
            let mut b = Builder {
                w,
                recs: Vec::new(),
                last: [0; 32],
                head,
                rng: ChaCha20Rng::from_seed([9; 32]),
                ballots: 0,
                pending: None,
                unused: None,
                next_seq: 1,
                counts: [0; 4],
                cancels: 0,
            };
            b.push(Record::SessionOpen(so.clone()));
            let z = zeresima_record(w, &so, head);
            b.push(z);
            b.checkpoint();
            b
        }

        fn push(&mut self, r: Record) {
            self.last = frame_digest(&self.last, &cbor::encode(&r.to_value()));
            self.recs.push(r);
        }

        fn finish(self) -> Vec<Record> {
            self.recs
        }

        fn auth(&mut self) {
            let w = self.w;
            let seq = self.next_seq;
            self.next_seq += 1;
            self.push(auth_record(w, seq));
            self.unused = Some(seq);
            self.counts[0] += 1;
        }

        fn commit(&mut self, row: usize) -> [u8; 32] {
            let w = self.w;
            self.ballots += 1;
            let mut rho = [0u8; 32];
            self.rng.fill_bytes(&mut rho);
            let id = BallotId {
                machine_id: MACHINE.into(),
                session_id: SESSION.into(),
                seq: self.ballots,
            };
            let choices = picks(row);
            let election = Election {
                context_hash: w.ctx,
                k: w.k,
                manifest: &w.manifest,
            };
            let ballot = encrypt_ballot(&mut self.rng, &election, &w.offered, &id, &rho, &choices)
                .expect("encrypt");
            let code = tracking_code(&self.head, &ballot);
            self.push(Record::Committed {
                ballot: ballot.clone(),
                code,
            });
            self.pending = Some(Pending {
                ballot,
                code,
                rho,
                choices,
            });
            code
        }

        fn take_pending(&mut self) -> Pending {
            self.pending.take().expect("pending committed ballot")
        }

        fn cast(&mut self) {
            let p = self.take_pending();
            self.push(Record::Cast { code: p.code });
            self.head = next_head(&p.code, Status::Cast, None);
            self.counts[1] += 1;
            self.unused = None;
        }

        fn spoil(&mut self) {
            let p = self.take_pending();
            let reveal = Reveal {
                ballot_id: p.ballot.id.clone(),
                rho: p.rho,
                selections: p.choices.clone(),
            };
            self.push(Record::Spoiled {
                code: p.code,
                reveal: reveal.clone(),
            });
            self.head = next_head(&p.code, Status::Spoiled, Some(&reveal));
            self.counts[2] += 1;
        }

        fn abandon(&mut self) {
            let p = self.take_pending();
            self.push(Record::Abandoned { code: p.code });
            self.head = next_head(&p.code, Status::Abandoned, None);
            self.counts[3] += 1;
        }

        /// Advances the chain as an abandonment without journaling it.
        fn abandon_unrecorded(&mut self) {
            let p = self.take_pending();
            self.head = next_head(&p.code, Status::Abandoned, None);
        }

        fn cancel(&mut self) {
            let w = self.w;
            let seq = self.unused.take().expect("unused authorization");
            let pw = &w.keys.poll_workers[0];
            let sig = auth_cancel_signature(pw, &w.ctx, MACHINE, SESSION, seq);
            self.push(Record::AuthCancel {
                seq,
                pw_key: pw.verifying_key(),
                sig,
            });
            self.cancels += 1;
        }

        fn checkpoint(&mut self) {
            let w = self.w;
            let count = self.recs.len() as u64;
            let frame = self.last;
            let head = self.head;
            let sig = checkpoint_signature(
                &w.keys.machines[0],
                &w.ctx,
                MACHINE,
                SESSION,
                count,
                &frame,
                &head,
            );
            self.push(Record::Checkpoint {
                count,
                frame_digest: frame,
                chain_head: head,
                sig,
            });
        }

        fn pre_bu_with(&mut self, adjust: impl FnOnce(&mut PreBu), signer: &SigningKey) {
            let w = self.w;
            let mut pb = PreBu {
                context_hash: w.ctx,
                machine_id: MACHINE.into(),
                section_id: SECTION.into(),
                session_id: SESSION.into(),
                imported: Vec::new(),
                frame_digest: self.last,
                chain_head: self.head,
                authorizations: self.counts[0],
                cast: self.counts[1],
                spoiled: self.counts[2],
                abandoned: self.counts[3],
                roll_count: 2,
                fingerprint: [4; 32],
                pooled: Vec::new(),
            };
            adjust(&mut pb);
            let pre_bu = pb.sign(&w.keys.machines[0]);
            let sig = SectionSig::create(signer, &pre_bu);
            self.push(Record::PreBuSigned {
                pre_bu,
                sigs: vec![sig],
            });
        }

        fn pre_bu(&mut self) {
            let w = self.w;
            self.pre_bu_with(|_| {}, &w.keys.poll_workers[0]);
        }

        /// `counts` is `[authorizations, cast, spoiled, abandoned]`.
        fn close_with(&mut self, adjust: impl FnOnce(&mut [u64; 4])) {
            let mut c = self.counts;
            adjust(&mut c);
            let head = self.head;
            self.push(Record::SessionClose {
                authorizations: c[0],
                cast: c[1],
                spoiled: c[2],
                abandoned: c[3],
                final_head: head,
                closed_at: OPENED_AT + 100,
                attestation: None,
            });
        }
    }

    /// Three voters (one spoils, one is abandoned), one cancelled authorization.
    fn voters(b: &mut Builder<'_>) {
        b.auth();
        b.commit(0);
        b.cast();
        b.checkpoint();

        b.auth();
        b.commit(1);
        b.spoil();
        b.checkpoint();
        b.commit(1);
        b.cast();
        b.checkpoint();

        b.auth();
        b.commit(2);
        b.abandon();
        b.checkpoint();
        b.commit(2);
        b.cast();
        b.checkpoint();
    }

    fn happy(w: &World) -> Vec<Record> {
        let mut b = Builder::new(w);
        voters(&mut b);
        b.auth();
        b.cancel();
        b.pre_bu();
        b.checkpoint();
        b.close_with(|_| {});
        b.finish()
    }

    fn run(w: &World, recs: Vec<Record>, complete: bool) -> Result<JournalSummary, Error> {
        check_journal(&skeys(w), &Journal::from_records(recs), complete)
    }

    fn reject(w: &World, recs: Vec<Record>, complete: bool, needle: &str) {
        match run(w, recs, complete) {
            Err(Error::Journal(msg)) => {
                assert!(msg.contains(needle), "message {msg:?} lacks {needle:?}")
            }
            other => panic!("expected a journal error containing {needle:?}, got {other:?}"),
        }
    }

    fn position(recs: &[Record], pred: impl Fn(&Record) -> bool) -> usize {
        recs.iter().position(pred).expect("record present")
    }

    fn frame_offset(j: &Journal, k: usize) -> usize {
        j.bytes[..k].iter().map(|b| 4 + b.len() + 32).sum()
    }

    #[test]
    fn happy_path_checks_and_summarises() {
        let w = world();
        let s = run(&w, happy(&w), true).expect("valid journal");
        assert!(s.complete);
        assert_eq!(
            (
                s.authorizations,
                s.cast,
                s.spoiled,
                s.abandoned,
                s.cancelled
            ),
            (4, 3, 1, 1, 1)
        );
        assert_eq!(s.codes.len(), 5);
        assert_eq!(s.head_0, head_0_of(&session_open(&w)));
        assert!(s.pre_bu.is_some());
    }

    #[test]
    fn auth_before_zeresima_is_rejected() {
        let w = world();
        let recs = vec![Record::SessionOpen(session_open(&w)), auth_record(&w, 1)];
        reject(&w, recs, true, "zeresima_signed");
    }

    #[test]
    fn gap_in_auth_seq_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Authorization { .. }));
        recs[i] = auth_record(&w, 2);
        reject(&w, recs, true, "auth_seq");
    }

    #[test]
    fn forged_auth_signature_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Authorization { .. }));
        // Signed by a poll worker who is not the key in the record.
        recs[i] = Record::Authorization {
            seq: 1,
            pw_key: w.keys.poll_workers[0].verifying_key(),
            sig: auth_signature(&w.keys.poll_workers[3], &w.ctx, MACHINE, SESSION, 1),
        };
        reject(&w, recs.clone(), true, "poll worker");
        // Signed by the machine key, which is no poll worker.
        recs[i] = Record::Authorization {
            seq: 1,
            pw_key: w.keys.machines[0].verifying_key(),
            sig: auth_signature(&w.keys.machines[0], &w.ctx, MACHINE, SESSION, 1),
        };
        reject(&w, recs, true, "poll worker");
    }

    #[test]
    fn two_unused_authorizations_are_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Authorization { .. }));
        recs.insert(i + 1, auth_record(&w, 2));
        reject(&w, recs, true, "unused");
    }

    #[test]
    fn cast_without_authorization_is_rejected() {
        let w = world();
        let mut b = Builder::new(&w);
        b.commit(0);
        b.cast();
        b.checkpoint();
        reject(&w, b.finish(), true, "cast without an unused authorization");
    }

    #[test]
    fn missing_checkpoint_after_cast_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Cast { .. }));
        recs.remove(i + 1);
        reject(&w, recs, true, "missing checkpoint");
    }

    #[test]
    fn checkpoint_with_wrong_count_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Checkpoint { .. }));
        if let Record::Checkpoint { count, .. } = &mut recs[i] {
            *count += 1;
        }
        reject(&w, recs, true, "checkpoint count");
    }

    #[test]
    fn checkpoint_with_wrong_frame_digest_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Checkpoint { .. }));
        if let Record::Checkpoint { frame_digest, .. } = &mut recs[i] {
            *frame_digest = [9; 32];
        }
        reject(&w, recs, true, "frame digest");
    }

    #[test]
    fn checkpoint_with_wrong_head_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Checkpoint { .. }));
        if let Record::Checkpoint { chain_head, .. } = &mut recs[i] {
            *chain_head = [9; 32];
        }
        reject(&w, recs, true, "chain head");
    }

    #[test]
    fn checkpoint_with_forged_signature_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Checkpoint { .. }));
        let (count, fd, head) = match &recs[i] {
            Record::Checkpoint {
                count,
                frame_digest,
                chain_head,
                ..
            } => (*count, *frame_digest, *chain_head),
            _ => unreachable!(),
        };
        // Signed by a poll worker instead of the machine.
        let forged = checkpoint_signature(
            &w.keys.poll_workers[0],
            &w.ctx,
            MACHINE,
            SESSION,
            count,
            &fd,
            &head,
        );
        if let Record::Checkpoint { sig, .. } = &mut recs[i] {
            *sig = forged;
        }
        reject(&w, recs, true, "signed by the machine");
    }

    #[test]
    fn wrong_tracking_code_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let i = position(&recs, |r| matches!(r, Record::Committed { .. }));
        if let Record::Committed { code, .. } = &mut recs[i] {
            *code = [3; 32];
        }
        reject(&w, recs, true, "tracking code");
    }

    #[test]
    fn pre_bu_counts_mismatch_is_rejected() {
        let w = world();
        let mut b = Builder::new(&w);
        voters(&mut b);
        b.auth();
        b.cancel();
        b.pre_bu_with(|p| p.cast += 1, &w.keys.poll_workers[0]);
        b.checkpoint();
        b.close_with(|_| {});
        reject(&w, b.finish(), true, "counts");
    }

    #[test]
    fn pre_bu_without_poll_worker_signature_is_rejected() {
        let w = world();
        let mut b = Builder::new(&w);
        voters(&mut b);
        b.auth();
        b.cancel();
        b.pre_bu_with(|_| {}, &w.keys.machines[1]);
        b.checkpoint();
        b.close_with(|_| {});
        reject(&w, b.finish(), true, "poll worker");
    }

    #[test]
    fn session_close_counts_mismatch_is_rejected() {
        let w = world();
        let mut b = Builder::new(&w);
        voters(&mut b);
        b.auth();
        b.cancel();
        b.pre_bu();
        b.checkpoint();
        b.close_with(|c| c[1] += 1);
        reject(&w, b.finish(), true, "session_close counts");
    }

    #[test]
    fn record_after_session_close_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        recs.push(Record::Cast { code: [1; 32] });
        reject(&w, recs, true, "after session_close");
    }

    #[test]
    fn zeresima_head_0_mismatch_is_rejected() {
        let w = world();
        let mut recs = happy(&w);
        let so = session_open(&w);
        recs[1] = zeresima_record(&w, &so, [8; 32]);
        reject(&w, recs, true, "head_0");
    }

    #[test]
    fn recovered_journal_cut_at_checkpoint_is_accepted() {
        let w = world();
        let recs = happy(&w);
        let cancel_at = position(&recs, |r| matches!(r, Record::AuthCancel { .. }));
        let cut = recs[..cancel_at]
            .iter()
            .rposition(|r| matches!(r, Record::Checkpoint { .. }))
            .expect("checkpoint before the cancellation");
        let s = run(&w, recs[..=cut].to_vec(), false).expect("recovered journal");
        assert!(!s.complete);
        assert_eq!((s.authorizations, s.cast, s.cancelled), (3, 3, 0));
        assert!(s.pre_bu.is_none());
    }

    #[test]
    fn committed_without_status_is_rejected_in_both_modes() {
        let w = world();
        let mut b = Builder::new(&w);
        b.auth();
        b.commit(0);
        b.abandon_unrecorded();
        b.checkpoint();
        let recs = b.finish();
        reject(&w, recs.clone(), false, "no cast, spoiled or abandoned");
        reject(&w, recs, true, "no cast, spoiled or abandoned");
    }

    #[test]
    fn recovered_journal_not_cut_at_checkpoint_is_rejected() {
        let w = world();
        let recs = happy(&w);
        let cast_at = position(&recs, |r| matches!(r, Record::Cast { .. }));
        match run(&w, recs[..=cast_at].to_vec(), false) {
            Err(Error::Journal(msg)) => assert!(msg.contains("checkpoint"), "{msg}"),
            other => panic!("expected a journal error, got {other:?}"),
        }
        let mut b = Builder::new(&w);
        b.auth();
        b.commit(0);
        match run(&w, b.finish(), false) {
            Err(Error::Journal(msg)) => assert!(msg.contains("checkpoint"), "{msg}"),
            other => panic!("expected a journal error, got {other:?}"),
        }
    }

    #[test]
    fn framing_round_trips() {
        let w = world();
        let j = Journal::from_records(happy(&w));
        let bytes = j.to_bytes();
        let (back, torn) = Journal::from_bytes(&bytes).expect("parses");
        assert!(!torn);
        assert_eq!(back, j);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.last_digest(), j.last_digest());
    }

    #[test]
    fn torn_final_frame_is_dropped() {
        let w = world();
        let recs = happy(&w);
        let n = recs.len();
        let j = Journal::from_records(recs.clone());
        let bytes = j.to_bytes();
        let cuts = [
            bytes.len() - 1,
            bytes.len() - 40,
            frame_offset(&j, n - 1) + 2,
        ];
        for cut in cuts {
            let (back, torn) =
                Journal::from_bytes(&bytes[..cut]).expect("torn tail is not an error");
            assert!(torn, "cut at {cut}");
            assert_eq!(back.records(), &recs[..n - 1]);
        }
    }

    #[test]
    fn damaged_middle_length_is_not_mistaken_for_a_torn_tail() {
        // Spec issue 18: a length field in a middle frame damaged so that it
        // points past the end used to read as a torn final write, silently
        // dropping every later frame.
        let w = world();
        let j = Journal::from_records(happy(&w));
        let mut bytes = j.to_bytes();
        let off = frame_offset(&j, 5);
        bytes[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        match Journal::from_bytes(&bytes) {
            Err(Error::Journal(msg)) => assert!(msg.contains("length field"), "{msg}"),
            other => panic!("expected a damaged-length error, got {other:?}"),
        }
    }

    #[test]
    fn torn_tail_with_a_complete_record_but_short_digest_is_still_torn() {
        let w = world();
        let recs = happy(&w);
        let n = recs.len();
        let j = Journal::from_records(recs.clone());
        let bytes = j.to_bytes();
        // The last record's CBOR is complete, only 10 of its 32 digest bytes landed.
        let cut = frame_offset(&j, n - 1) + 4 + j.bytes[n - 1].len() + 10;
        let (back, torn) = Journal::from_bytes(&bytes[..cut]).expect("torn tail");
        assert!(torn);
        assert_eq!(back.records(), &recs[..n - 1]);
    }

    #[test]
    fn corrupted_middle_byte_is_rejected() {
        let w = world();
        let j = Journal::from_records(happy(&w));
        let mut bytes = j.to_bytes();
        let off = frame_offset(&j, 5);
        bytes[off + 4 + 3] ^= 0x01;
        assert!(Journal::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_frame_digest_is_rejected() {
        let w = world();
        let j = Journal::from_records(happy(&w));
        let mut bytes = j.to_bytes();
        let off = frame_offset(&j, 5) + 4 + j.bytes[5].len();
        bytes[off] ^= 0x01;
        match Journal::from_bytes(&bytes) {
            Err(Error::Journal(msg)) => assert!(msg.contains("digest"), "{msg}"),
            other => panic!("expected a digest error, got {other:?}"),
        }
    }

    #[test]
    fn every_record_type_round_trips_through_cbor() {
        let w = world();
        let mut recs = happy(&w);
        let mut so = session_open(&w);
        so.attestation = Some(Value::Bytes(vec![1, 2, 3]));
        recs.push(Record::SessionOpen(so));
        recs.push(Record::SessionClose {
            authorizations: 1,
            cast: 1,
            spoiled: 0,
            abandoned: 0,
            final_head: [1; 32],
            closed_at: 5,
            attestation: Some(Value::Uint(4)),
        });
        for r in &recs {
            let bytes = cbor::encode(&r.to_value());
            let decoded = cbor::decode(&bytes).expect("cbor");
            assert_eq!(&Record::from_value(&decoded).expect("record"), r);
        }
    }

    #[test]
    fn unknown_record_type_is_rejected() {
        let v = Value::Map(vec![(Value::Uint(0), Value::from("nope"))]);
        assert!(Record::from_value(&v).is_err());
    }
}
