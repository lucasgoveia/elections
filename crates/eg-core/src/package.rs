//! Export packages, section attestations and board package ingestion
//! (SPEC.md §16.1, §16.3, §16.4, §17.6, §17.7 and §24.4).
//!
//! Three things live here:
//!
//! - the records a machine or a replacement machine publishes: [`Package`]
//!   (§16.1), [`RecoveredPackage`] (§16.4) and their [`PackageHeader`];
//! - the observer and attestation records of §16.3: [`ObserverCert`],
//!   [`ObserverRevoke`] and [`SectionAttestation`];
//! - [`BoardState`], the stateful ingester that a board runs over its entries
//!   in order, and that a verifier re-runs (§23). It applies the rules of
//!   §17.6 and §17.7 and keeps the frozen registry, the observer keys and the
//!   accepted packages.
//!
//! Ballot proofs (§12.6) are not checked here. Rule 8 of §17.6 says a bad
//! proof excludes a ballot in the tally and never rejects the package, so the
//! tally judges them. The subtotal fingerprint (§18.1) is not checked here
//! either.

use std::collections::{HashMap, HashSet};

use crate::board::{record_id, PollsOpen, TallyCutoff};
use crate::cbor::{record_fields, record_fields_opt, Value};
use crate::ceremony::Context;
use crate::chain::Measurement;
use crate::error::Error;
use crate::journal::{
    check_journal, Journal, JournalSummary, PreBu, Record, SectionSig, SessionKeys, Zeresima,
};
use crate::manifest::{bytes32, decode_list, expect_version, record, schema, Manifest};
use crate::registry::{open_signed_registry, MachineEntry, Registry};
use crate::sign::{
    sign_record, signature_from_value, signature_to_value, verify_record, verifying_key_from_value,
    verifying_key_to_value, Signature, SigningKey, VerifyingKey,
};

/// Version of every record in this module (§6.3).
const VERSION: u64 = 1;
/// Signature tag of a package (§16.1, machine key).
const SIG_PACKAGE: &str = "eg/v1/sig/package";
/// Signature tag of an observer certificate (§16.3, party key).
const SIG_OBSERVER_CERT: &str = "eg/v1/sig/observer-cert";
/// Signature tag of an observer revocation (§16.3, party key).
const SIG_OBSERVER_REVOKE: &str = "eg/v1/sig/observer-revoke";
/// Signature tag of a software policy update (§24.4, EA key).
const SIG_POLICY_UPDATE: &str = "eg/v1/sig/policy-update";

/// Builds a map from `(uint key, value)` pairs, as [`sign_record`] expects.
fn kv(entries: Vec<(u64, Value)>) -> Vec<(Value, Value)> {
    entries
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect()
}

/// A required field of an optional-field record.
fn req<'a>(f: &[Option<&'a Value>], k: usize) -> Result<&'a Value, Error> {
    f.get(k)
        .copied()
        .flatten()
        .ok_or_else(|| schema(format!("missing record field {k}")))
}

/// A board rejection reason (`Error::Board`).
fn board_err(msg: impl Into<String>) -> Error {
    Error::Board(msg.into())
}

/// Decodes the journal records of a package (`+ journal_record`, §16.1).
fn decode_records(v: &Value) -> Result<Vec<Record>, Error> {
    decode_list(v, 1, "journal records", Record::from_value)
}

/// Encodes journal records as an array.
fn records_value(records: &[Record]) -> Value {
    Value::Array(records.iter().map(Record::to_value).collect())
}

// ---------------------------------------------------------------------------
// Package header and packages (§16.1, §16.4)
// ---------------------------------------------------------------------------

/// `package_header` (§16.1). Field 7 is the optional attestation (§24.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageHeader {
    /// Field 2: context hash of the election.
    pub context_hash: [u8; 32],
    /// Field 3: machine that produced the journal.
    pub machine_id: String,
    /// Field 4: section of the session.
    pub section_id: String,
    /// Field 5: session identifier.
    pub session_id: String,
    /// Field 6: software measurement (§24.4).
    pub measurement: Measurement,
    /// Field 7: attestation, opaque to this module.
    pub attestation: Option<Value>,
    /// Field 8: number of journal records.
    pub record_count: u64,
    /// Field 9: frame digest of the last journal record.
    pub frame_digest: [u8; 32],
    /// Field 10: final chain head.
    pub chain_head: [u8; 32],
}

impl PackageHeader {
    /// Encodes the header as the CBOR map of §16.1.
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("package_header")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.context_hash)),
            (3, Value::from(self.machine_id.as_str())),
            (4, Value::from(self.section_id.as_str())),
            (5, Value::from(self.session_id.as_str())),
            (6, self.measurement.to_value()),
            (8, Value::Uint(self.record_count)),
            (9, Value::from(self.frame_digest)),
            (10, Value::from(self.chain_head)),
        ];
        if let Some(a) = &self.attestation {
            entries.push((7, a.clone()));
        }
        record(entries)
    }

    /// Strict decode of §16.1.
    pub fn from_value(v: &Value) -> Result<PackageHeader, Error> {
        // Key 7 is optional; keys 8 to 10 are required and checked by `req`.
        let f = record_fields_opt(v, "package_header", 7, &[7, 8, 9, 10])?;
        expect_version(req(&f, 1)?)?;
        Ok(PackageHeader {
            context_hash: bytes32(req(&f, 2)?)?,
            machine_id: req(&f, 3)?.as_text()?.to_owned(),
            section_id: req(&f, 4)?.as_text()?.to_owned(),
            session_id: req(&f, 5)?.as_text()?.to_owned(),
            measurement: Measurement::from_value(req(&f, 6)?)?,
            attestation: f.get(7).copied().flatten().cloned(),
            record_count: req(&f, 8)?.as_uint()?,
            frame_digest: bytes32(req(&f, 9)?)?,
            chain_head: bytes32(req(&f, 10)?)?,
        })
    }
}

/// A package (`package`, §16.1): the full journal of a session, signed by the
/// machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub header: PackageHeader,
    /// The whole journal, in order (field 3).
    pub records: Vec<Record>,
}

impl Package {
    /// Builds the machine-signed package (fields 0..3 plus signature 4).
    pub fn sign(&self, machine_sk: &SigningKey) -> Value {
        sign_record(
            machine_sk,
            SIG_PACKAGE,
            kv(vec![
                (0, Value::from("package")),
                (1, Value::Uint(VERSION)),
                (2, self.header.to_value()),
                (3, records_value(&self.records)),
            ]),
            4,
        )
    }

    /// Strict decode of a machine-signed package. The signature must verify
    /// under `machine_pk`.
    pub fn from_signed(v: &Value, machine_pk: &VerifyingKey) -> Result<Package, Error> {
        let f = record_fields(v, "package", 5)?;
        verify_record(machine_pk, SIG_PACKAGE, v, 4)?;
        expect_version(f[1])?;
        Ok(Package {
            header: PackageHeader::from_value(f[2])?,
            records: decode_records(f[3])?,
        })
    }
}

/// Builds the signed package of a finished journal (§16.1).
///
/// The header takes the record count and the last frame digest of `journal`,
/// and the final chain head of its `session_close`. The journal must end with
/// `session_close`. The package carries no attestation.
pub fn build_package(
    journal: &Journal,
    context_hash: &[u8; 32],
    machine_id: &str,
    section_id: &str,
    session_id: &str,
    measurement: Measurement,
    machine_sk: &SigningKey,
) -> Result<Value, Error> {
    let chain_head = match journal.records().last() {
        Some(Record::SessionClose { final_head, .. }) => *final_head,
        _ => {
            return Err(Error::Journal(
                "a package needs a journal that ends with session_close".into(),
            ))
        }
    };
    let package = Package {
        header: PackageHeader {
            context_hash: *context_hash,
            machine_id: machine_id.to_owned(),
            section_id: section_id.to_owned(),
            session_id: session_id.to_owned(),
            measurement,
            attestation: None,
            record_count: journal.len() as u64,
            frame_digest: journal.last_digest(),
            chain_head,
        },
        records: journal.records().to_vec(),
    };
    Ok(package.sign(machine_sk))
}

/// A recovered package (`recovered_package`, §16.4). It is not signed by the
/// machine, which is dead. Poll workers (and observers) sign its unsigned part
/// with [`RecoveredPackage::add_sig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredPackage {
    /// Field 2: header built from the journal. Field 9 is the frame digest of
    /// the last record, which is the last checkpoint.
    pub header: PackageHeader,
    /// Field 3: the journal up to and including its last checkpoint.
    pub records: Vec<Record>,
    /// Field 4: voter-roll count at the time of failure.
    pub roll_count: u64,
    /// Field 5: section signatures over `unsigned_value`.
    pub sigs: Vec<SectionSig>,
}

impl RecoveredPackage {
    /// Fields 0..4 of the record: the object that section signatures cover.
    pub fn unsigned_value(&self) -> Value {
        Value::Map(kv(vec![
            (0, Value::from("recovered_package")),
            (1, Value::Uint(VERSION)),
            (2, self.header.to_value()),
            (3, records_value(&self.records)),
            (4, Value::Uint(self.roll_count)),
        ]))
    }

    /// Adds a section signature by `sk` over `unsigned_value`.
    pub fn add_sig(&mut self, sk: &SigningKey) {
        let unsigned = self.unsigned_value();
        self.sigs.push(SectionSig::create(sk, &unsigned));
    }

    /// Encodes the full record (fields 0..5).
    pub fn to_value(&self) -> Value {
        let Value::Map(mut entries) = self.unsigned_value() else {
            unreachable!("unsigned_value is a map");
        };
        entries.push((
            Value::Uint(5),
            Value::Array(self.sigs.iter().map(SectionSig::to_value).collect()),
        ));
        Value::Map(entries)
    }

    /// Strict decode of §16.4. Signatures are checked by the board, not here.
    pub fn from_value(v: &Value) -> Result<RecoveredPackage, Error> {
        let f = record_fields(v, "recovered_package", 6)?;
        expect_version(f[1])?;
        let sigs = decode_list(f[5], 1, "section signatures", SectionSig::from_value)?;
        Ok(RecoveredPackage {
            header: PackageHeader::from_value(f[2])?,
            records: decode_records(f[3])?,
            roll_count: f[4].as_uint()?,
            sigs,
        })
    }
}

/// Builds an unsigned recovered package from a journal cut at a checkpoint.
///
/// The header is built as for a package, but the frame digest is that of the
/// last record (the checkpoint) and the chain head is the checkpoint's. The
/// journal must end with a checkpoint. The caller adds the poll worker
/// signatures with [`RecoveredPackage::add_sig`].
pub fn build_recovered(
    journal: &Journal,
    context_hash: &[u8; 32],
    machine_id: &str,
    section_id: &str,
    session_id: &str,
    measurement: Measurement,
    roll_count: u64,
) -> Result<RecoveredPackage, Error> {
    let chain_head = match journal.records().last() {
        Some(Record::Checkpoint { chain_head, .. }) => *chain_head,
        _ => {
            return Err(Error::Journal(
                "a recovered package needs a journal that ends with a checkpoint".into(),
            ))
        }
    };
    Ok(RecoveredPackage {
        header: PackageHeader {
            context_hash: *context_hash,
            machine_id: machine_id.to_owned(),
            section_id: section_id.to_owned(),
            session_id: session_id.to_owned(),
            measurement,
            attestation: None,
            record_count: journal.len() as u64,
            frame_digest: journal.last_digest(),
            chain_head,
        },
        records: journal.records().to_vec(),
        roll_count,
        sigs: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Observer certificates and revocations (§16.3)
// ---------------------------------------------------------------------------

/// Builds the party-signed body `[tag, 1, context_hash, party_index, key]`
/// with its signature at field 5.
fn party_key_sign(
    party_sk: &SigningKey,
    tag: &str,
    sig_tag: &str,
    context_hash: &[u8; 32],
    party_index: u64,
    key: &VerifyingKey,
) -> Value {
    sign_record(
        party_sk,
        sig_tag,
        kv(vec![
            (0, Value::from(tag)),
            (1, Value::Uint(VERSION)),
            (2, Value::from(*context_hash)),
            (3, Value::Uint(party_index)),
            (4, verifying_key_to_value(key)),
        ]),
        5,
    )
}

/// Checks a party-signed record and decodes `(context_hash, party_index, key)`.
fn party_key_decode(
    v: &Value,
    tag: &str,
    sig_tag: &str,
    party_pk: &VerifyingKey,
) -> Result<([u8; 32], u64, VerifyingKey), Error> {
    let f = record_fields(v, tag, 6)?;
    verify_record(party_pk, sig_tag, v, 5)?;
    expect_version(f[1])?;
    Ok((
        bytes32(f[2])?,
        f[3].as_uint()?,
        verifying_key_from_value(f[4])?,
    ))
}

/// Reads the party index of a party-signed record before its signature is
/// checked, so the board can find the party key in the manifest.
fn party_index_of(v: &Value, tag: &str) -> Result<u64, Error> {
    Ok(record_fields(v, tag, 6)?[3].as_uint()?)
}

/// `observer_cert` (§16.3): a party certifies an observer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverCert {
    pub context_hash: [u8; 32],
    pub party_index: u64,
    pub observer_key: VerifyingKey,
}

impl ObserverCert {
    /// Builds the certificate signed by the party key.
    pub fn sign(&self, party_sk: &SigningKey) -> Value {
        party_key_sign(
            party_sk,
            "observer_cert",
            SIG_OBSERVER_CERT,
            &self.context_hash,
            self.party_index,
            &self.observer_key,
        )
    }

    /// Strict decode; the signature must verify under `party_pk`.
    pub fn from_signed(v: &Value, party_pk: &VerifyingKey) -> Result<ObserverCert, Error> {
        let (context_hash, party_index, observer_key) =
            party_key_decode(v, "observer_cert", SIG_OBSERVER_CERT, party_pk)?;
        Ok(ObserverCert {
            context_hash,
            party_index,
            observer_key,
        })
    }
}

/// `observer_revoke` (§16.3): a party revokes one of its observer keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverRevoke {
    pub context_hash: [u8; 32],
    pub party_index: u64,
    pub observer_key: VerifyingKey,
}

impl ObserverRevoke {
    /// Builds the revocation signed by the party key.
    pub fn sign(&self, party_sk: &SigningKey) -> Value {
        party_key_sign(
            party_sk,
            "observer_revoke",
            SIG_OBSERVER_REVOKE,
            &self.context_hash,
            self.party_index,
            &self.observer_key,
        )
    }

    /// Strict decode; the signature must verify under `party_pk`.
    pub fn from_signed(v: &Value, party_pk: &VerifyingKey) -> Result<ObserverRevoke, Error> {
        let (context_hash, party_index, observer_key) =
            party_key_decode(v, "observer_revoke", SIG_OBSERVER_REVOKE, party_pk)?;
        Ok(ObserverRevoke {
            context_hash,
            party_index,
            observer_key,
        })
    }
}

/// `section_attestation` (§16.3): an observer or poll worker publishes a full
/// signed zerésima or pre-BU, with its signature over `RecordId(record)`. The
/// signed bytes are those of a [`SectionSig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionAttestation {
    /// Field 2: the full signed `zeresima` or `pre_bu`.
    pub record: Value,
    /// Field 3: observer or poll worker key.
    pub key: VerifyingKey,
    /// Field 4: signature over `RecordId(record)`.
    pub sig: Signature,
}

impl SectionAttestation {
    /// Attests `record` with `sk`. Does not check that `record` is signed.
    pub fn create(sk: &SigningKey, record: &Value) -> SectionAttestation {
        let s = SectionSig::create(sk, record);
        SectionAttestation {
            record: record.clone(),
            key: s.key,
            sig: s.sig,
        }
    }

    /// Checks the signature over the attested record.
    pub fn verify(&self) -> bool {
        SectionSig {
            key: self.key,
            sig: self.sig,
        }
        .verify(&self.record)
    }

    /// Encodes the attestation as the CBOR map of §16.3.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("section_attestation")),
            (1, Value::Uint(VERSION)),
            (2, self.record.clone()),
            (3, verifying_key_to_value(&self.key)),
            (4, signature_to_value(&self.sig)),
        ])
    }

    /// Strict decode of §16.3. The attested record must be a `zeresima` or a
    /// `pre_bu`. Its signature is checked by the board, which knows the keys.
    pub fn from_value(v: &Value) -> Result<SectionAttestation, Error> {
        let f = record_fields(v, "section_attestation", 5)?;
        expect_version(f[1])?;
        let tag = f[2].get(0)?.and_then(|t| t.as_text().ok());
        if !matches!(tag, Some("zeresima" | "pre_bu")) {
            return Err(schema(
                "section_attestation must attest a zeresima or a pre_bu",
            ));
        }
        Ok(SectionAttestation {
            record: f[2].clone(),
            key: verifying_key_from_value(f[3])?,
            sig: signature_from_value(f[4])?,
        })
    }
}

/// `software_policy_update` (§24.4), signed by the EA. Decoded here because the
/// board applies it to the approved list before `polls_open`.
struct PolicyUpdate {
    context_hash: [u8; 32],
    add: Vec<[u8; 32]>,
    withdrawn: Vec<[u8; 32]>,
}

impl PolicyUpdate {
    fn from_signed(v: &Value, ea_pk: &VerifyingKey) -> Result<PolicyUpdate, Error> {
        let f = record_fields(v, "software_policy_update", 6)?;
        verify_record(ea_pk, SIG_POLICY_UPDATE, v, 5)?;
        expect_version(f[1])?;
        Ok(PolicyUpdate {
            context_hash: bytes32(f[2])?,
            add: decode_list(f[3], 1, "added hashes", bytes32)?,
            withdrawn: decode_list(f[4], 0, "withdrawn hashes", bytes32)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Board ingestion (§17.6, §17.7, §16.3)
// ---------------------------------------------------------------------------

/// Result of [`BoardState::ingest`] for one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingest {
    Accepted,
    /// The entry breaks a rule. The text names the rule, for the board's
    /// signed `rejection` entry (§17.6).
    Rejected(String),
}

/// Whether an accepted package is a machine's own package or a recovered one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Package,
    Recovered,
}

/// A package that the board accepted for tallying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedPackage {
    /// Index of the entry on the board (counting every entry fed to ingest).
    pub entry_index: u64,
    /// RecordId of the package or recovered package entry.
    pub package_id: [u8; 32],
    pub kind: PackageKind,
    /// What the journal says about the session.
    pub summary: JournalSummary,
    pub header: PackageHeader,
    /// True when this recovered package was superseded by the machine's own
    /// package for the same session (§16.4).
    pub superseded: bool,
}

/// A section attestation that the board accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedAttestation {
    pub entry_index: u64,
    /// RecordId of the attested zerésima or pre-BU.
    pub record_id: [u8; 32],
    /// Type tag of the attested record: `"zeresima"` or `"pre_bu"`.
    pub record_tag: String,
    pub machine_id: String,
    pub section_id: String,
    pub key: VerifyingKey,
}

/// Stateful ingester run over board entries in order (§17.6, §17.7, §16.3).
///
/// Feed every entry of the board, rejected ones included, to [`ingest`] in
/// board order. A verifier runs the same code and gets the same answers.
///
/// [`ingest`]: BoardState::ingest
pub struct BoardState<'a> {
    manifest: &'a Manifest,
    /// Hash the election's context must have (§9).
    context_hash: [u8; 32],
    /// Index of the next entry.
    next_index: u64,
    /// The registry in force (the latest accepted `signed_registry`).
    registry: Option<Registry>,
    /// The `signed_registry` record the registry came from. `polls_open`
    /// names it by RecordId.
    registry_value: Option<Value>,
    /// Set by `polls_open`. Freezes the registry and the software policy.
    polls_open: bool,
    /// Set by `tally_cutoff`. No package is accepted after it.
    cutoff: bool,
    /// Approved machine artifact hashes (§24.4), updated before polls_open.
    approved: Vec<[u8; 32]>,
    /// Certified observer keys, with the party that certified each (§16.3).
    observers: HashMap<[u8; 32], u64>,
    /// Observer keys revoked by their party (§16.3).
    revoked: HashSet<[u8; 32]>,
    /// Sessions on the board, by (machine_id, session_id), as an index into
    /// `packages`.
    sessions: HashMap<(String, String), usize>,
    /// Sessions counted against each machine's `max_sessions` (§17.6 rule 9).
    sessions_per_machine: HashMap<String, u64>,
    packages: Vec<AcceptedPackage>,
    attestations: Vec<AcceptedAttestation>,
}

impl<'a> BoardState<'a> {
    /// A board state for the election described by `manifest` and `context`,
    /// before any entry.
    pub fn new(manifest: &'a Manifest, context: &'a Context) -> BoardState<'a> {
        BoardState {
            manifest,
            context_hash: context.hash(),
            next_index: 0,
            registry: None,
            registry_value: None,
            polls_open: false,
            cutoff: false,
            approved: manifest.software_policy.approved_hashes.clone(),
            observers: HashMap::new(),
            revoked: HashSet::new(),
            sessions: HashMap::new(),
            sessions_per_machine: HashMap::new(),
            packages: Vec::new(),
            attestations: Vec::new(),
        }
    }

    /// Applies one board entry. Dispatches on its type tag (field 0). Entries
    /// that this module does not check (DKG records, tallies, mix outputs,
    /// results, rejections, STHs and the like) are accepted here, and the
    /// verifier checks them.
    pub fn ingest(&mut self, entry: &Value) -> Ingest {
        let index = self.next_index;
        self.next_index += 1;
        let tag = entry.get(0).ok().flatten().and_then(|t| t.as_text().ok());
        let result = match tag {
            Some("signed_registry") => self.on_registry(entry),
            Some("polls_open") => self.on_polls_open(entry),
            Some("tally_cutoff") => self.on_tally_cutoff(entry),
            Some("software_policy_update") => self.on_policy_update(entry),
            Some("observer_cert") => self.on_observer_cert(entry),
            Some("observer_revoke") => self.on_observer_revoke(entry),
            Some("section_attestation") => self.on_attestation(index, entry),
            Some("package") => self.on_package(index, entry),
            Some("recovered_package") => self.on_recovered(index, entry),
            _ => Ok(()),
        };
        match result {
            Ok(()) => Ingest::Accepted,
            Err(Error::Board(reason)) => Ingest::Rejected(reason),
            Err(other) => Ingest::Rejected(other.to_string()),
        }
    }

    /// Accepted packages and recovered packages, in board order.
    pub fn accepted_packages(&self) -> &[AcceptedPackage] {
        &self.packages
    }

    /// Accepted section attestations, in board order.
    pub fn attestations(&self) -> &[AcceptedAttestation] {
        &self.attestations
    }

    /// The registry in force, if any.
    pub fn registry(&self) -> Option<&Registry> {
        self.registry.as_ref()
    }

    /// True once `polls_open` is on the board.
    pub fn polls_open(&self) -> bool {
        self.polls_open
    }

    /// True once `tally_cutoff` is on the board.
    pub fn cutoff(&self) -> bool {
        self.cutoff
    }

    // -- registry, polls and policy ----------------------------------------

    /// §7.7: a signed registry is accepted until `polls_open`, with the next
    /// registry version.
    fn on_registry(&mut self, entry: &Value) -> Result<(), Error> {
        if self.polls_open {
            return Err(board_err("§7.7: signed_registry after polls_open"));
        }
        let registry = open_signed_registry(entry, self.manifest)?;
        let expected = self.registry.as_ref().map_or(1, |r| r.version + 1);
        if registry.version != expected {
            return Err(board_err(format!(
                "§7.7: registry_version {} where {expected} was expected",
                registry.version
            )));
        }
        self.registry = Some(registry);
        self.registry_value = Some(entry.clone());
        Ok(())
    }

    /// §17.7: `polls_open` freezes the registry and the policy. It names the
    /// registry in force by RecordId.
    fn on_polls_open(&mut self, entry: &Value) -> Result<(), Error> {
        if self.polls_open {
            return Err(board_err("§17.7: polls_open is already on the board"));
        }
        let Some(registry_value) = &self.registry_value else {
            return Err(board_err("§17.7: polls_open before any signed_registry"));
        };
        let po = PollsOpen::from_signed(entry, &self.manifest.ea_key)?;
        if po.context_hash != self.context_hash {
            return Err(board_err("§17.7: polls_open context hash mismatch"));
        }
        if po.registry_id != record_id(registry_value) {
            return Err(board_err(
                "§17.7: polls_open does not name the registry in force",
            ));
        }
        self.polls_open = true;
        Ok(())
    }

    /// §17.7: `tally_cutoff` is accepted once, after `polls_open`.
    fn on_tally_cutoff(&mut self, entry: &Value) -> Result<(), Error> {
        if !self.polls_open {
            return Err(board_err("§17.7: tally_cutoff before polls_open"));
        }
        if self.cutoff {
            return Err(board_err("§17.7: tally_cutoff is already on the board"));
        }
        let tc = TallyCutoff::from_signed(entry, &self.manifest.ea_key)?;
        if tc.context_hash != self.context_hash {
            return Err(board_err("§17.7: tally_cutoff context hash mismatch"));
        }
        self.cutoff = true;
        Ok(())
    }

    /// §24.4: the EA adds or withdraws approved hashes before `polls_open`.
    /// Checking that each added release has k_r signatures in the release log
    /// is not done here (the verifier does it, §24.4).
    fn on_policy_update(&mut self, entry: &Value) -> Result<(), Error> {
        if self.polls_open {
            return Err(board_err("§24.4: software_policy_update after polls_open"));
        }
        let update = PolicyUpdate::from_signed(entry, &self.manifest.ea_key)?;
        if update.context_hash != self.context_hash {
            return Err(board_err("§24.4: software_policy_update context mismatch"));
        }
        for h in update.add {
            if !self.approved.contains(&h) {
                self.approved.push(h);
            }
        }
        self.approved.retain(|h| !update.withdrawn.contains(h));
        Ok(())
    }

    // -- observers (§16.3) --------------------------------------------------

    /// The key of party `index` in the manifest.
    fn party_key(&self, index: u64) -> Result<VerifyingKey, Error> {
        self.manifest
            .parties
            .iter()
            .find(|p| p.index == index)
            .and_then(|p| p.key.as_ref())
            .copied()
            .ok_or_else(|| board_err(format!("§16.3: party {index} has no key in the manifest")))
    }

    /// §16.3: a party certifies an observer. Accepted only before `polls_open`.
    fn on_observer_cert(&mut self, entry: &Value) -> Result<(), Error> {
        if self.polls_open {
            return Err(board_err("§16.3: observer_cert after polls_open"));
        }
        let party_key = self.party_key(party_index_of(entry, "observer_cert")?)?;
        let cert = ObserverCert::from_signed(entry, &party_key)?;
        if cert.context_hash != self.context_hash {
            return Err(board_err("§16.3: observer_cert context hash mismatch"));
        }
        let key = cert.observer_key.to_bytes();
        if let Some(&party) = self.observers.get(&key) {
            if party != cert.party_index {
                return Err(board_err(format!(
                    "§16.3: observer key already certified by party {party}"
                )));
            }
        }
        self.observers.insert(key, cert.party_index);
        Ok(())
    }

    /// §16.3: a party revokes an observer key at any time before the cutoff.
    /// A party may revoke only keys it certified (or keys nobody has certified
    /// yet). Keys in the registry (machines, poll workers, EA-registered
    /// observers) are never revoked this way.
    fn on_observer_revoke(&mut self, entry: &Value) -> Result<(), Error> {
        if self.cutoff {
            return Err(board_err("§16.3: observer_revoke after tally_cutoff"));
        }
        let party_key = self.party_key(party_index_of(entry, "observer_revoke")?)?;
        let rev = ObserverRevoke::from_signed(entry, &party_key)?;
        if rev.context_hash != self.context_hash {
            return Err(board_err("§16.3: observer_revoke context hash mismatch"));
        }
        let key = rev.observer_key.to_bytes();
        if let Some(&party) = self.observers.get(&key) {
            if party != rev.party_index {
                return Err(board_err(
                    "§16.3: observer certified by another party cannot be revoked by this one",
                ));
            }
        }
        if let Some(registry) = &self.registry {
            if registry_keys(registry).any(|k| *k == rev.observer_key) {
                return Err(board_err(
                    "§16.3: only observers certified by the party can be revoked by it",
                ));
            }
        }
        self.revoked.insert(key);
        Ok(())
    }

    /// Whether `key` is a certified or EA-registered observer.
    fn is_observer(&self, key: &VerifyingKey) -> bool {
        self.observers.contains_key(&key.to_bytes())
            || self
                .registry
                .as_ref()
                .is_some_and(|r| r.observers.iter().any(|o| o.key == *key))
    }

    /// §16.3: a section attestation. The attested zerésima or pre-BU must carry
    /// a valid machine signature under the registry key of its machine. The key
    /// must be a poll worker of that section, or an observer that is certified
    /// (or EA-registered) and not revoked. The attestation signature must
    /// verify. Attestations are accepted at any time, with no matching package
    /// needed (that is the evidence of a missing package).
    fn on_attestation(&mut self, index: u64, entry: &Value) -> Result<(), Error> {
        let att = SectionAttestation::from_value(entry)?;
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| board_err("§16.3: section_attestation before any signed_registry"))?;
        let machine_id = att
            .record
            .get(3)?
            .ok_or_else(|| schema("attested record has no machine_id"))?
            .as_text()?
            .to_owned();
        let machine = registry
            .machine(&machine_id)
            .ok_or_else(|| board_err(format!("§16.3: machine {machine_id:?} is not registered")))?;
        let tag = att
            .record
            .get(0)?
            .and_then(|t| t.as_text().ok())
            .unwrap_or("");
        let (context_hash, section_id) = match tag {
            "zeresima" => {
                let z = Zeresima::from_signed(&att.record, &machine.key).map_err(|e| {
                    board_err(format!("§16.3: attested zeresima does not verify: {e}"))
                })?;
                (z.context_hash, z.section_id)
            }
            _ => {
                let pb = PreBu::from_signed(&att.record, &machine.key).map_err(|e| {
                    board_err(format!("§16.3: attested pre_bu does not verify: {e}"))
                })?;
                (pb.context_hash, pb.section_id)
            }
        };
        if context_hash != self.context_hash {
            return Err(board_err("§16.3: attested record context hash mismatch"));
        }
        let key = att.key;
        let is_poll_worker = registry
            .section(&section_id)
            .is_some_and(|s| s.poll_worker_keys.contains(&key));
        if !is_poll_worker {
            if !self.is_observer(&key) {
                return Err(board_err(format!(
                    "§16.3: attestation key is neither a poll worker of section {section_id:?} nor a certified or registered observer"
                )));
            }
            if self.revoked.contains(&key.to_bytes()) {
                return Err(board_err("§16.3: attestation by a revoked observer key"));
            }
        }
        if !att.verify() {
            return Err(board_err("§16.3: attestation signature does not verify"));
        }
        self.attestations.push(AcceptedAttestation {
            entry_index: index,
            record_id: record_id(&att.record),
            record_tag: tag.to_owned(),
            machine_id,
            section_id,
            key,
        });
        Ok(())
    }

    // -- packages (§17.6) ---------------------------------------------------

    /// §17.6 rule 1 for packages: after `polls_open` and before the cutoff.
    fn check_window(&self, what: &str) -> Result<(), Error> {
        if !self.polls_open {
            return Err(board_err(format!("§17.6 rule 1: {what} before polls_open")));
        }
        if self.cutoff {
            return Err(board_err(format!(
                "§17.6 rule 1: {what} after tally_cutoff"
            )));
        }
        Ok(())
    }

    /// The machine registered under `machine_id` in the registry in force.
    fn machine(&self, machine_id: &str) -> Result<&MachineEntry, Error> {
        self.registry
            .as_ref()
            .and_then(|r| r.machine(machine_id))
            .ok_or_else(|| {
                board_err(format!(
                    "§17.6 rule 2: machine {machine_id:?} is not registered"
                ))
            })
    }

    /// §17.6 rules 3 to 7 for a package or recovered package. `complete` is
    /// true for a package (full ending) and false for a recovered package.
    ///
    /// Also checks that the header names the session that the journal holds.
    /// For a reserve machine (empty section in the registry), the section comes
    /// from the session. Its offered contests must equal those of the regular
    /// machines of that section, and all its sessions must name the same
    /// section.
    fn check_records(
        &self,
        header: &PackageHeader,
        records: &[Record],
        complete: bool,
    ) -> Result<JournalSummary, Error> {
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| board_err("§17.6: no registry in force"))?;
        if header.context_hash != self.context_hash {
            return Err(board_err("§17.6 rule 3: context hash mismatch"));
        }
        if !self.approved.contains(&header.measurement.0) {
            return Err(board_err(
                "§17.6 rule 4: software measurement is not on the approved list",
            ));
        }
        if self.manifest.software_policy.attestation_required {
            return Err(board_err(
                "§17.6 rule 4: the software policy requires attestation, which this ingester does not verify",
            ));
        }
        let section_id = match records.first() {
            Some(Record::SessionOpen(so)) => so.section_id.as_str(),
            _ => {
                return Err(board_err(
                    "§17.6 rules 5-7: the journal must begin with session_open",
                ))
            }
        };
        let machine = self.machine(&header.machine_id)?;
        let section = registry.section(section_id).ok_or_else(|| {
            board_err(format!(
                "§17.6 rule 6: section {section_id:?} is not registered"
            ))
        })?;
        if machine.section_id.is_empty() {
            // Reserve machine (§7.7): its contests must equal those of the
            // regular machines of the section it serves.
            let regular: Vec<&MachineEntry> = registry
                .machines
                .iter()
                .filter(|m| m.section_id == section_id)
                .collect();
            if regular.is_empty() || regular.iter().any(|m| m.contests != machine.contests) {
                return Err(board_err(
                    "§17.6 rule 6: reserve machine offers contests that differ from the regular machines of the section",
                ));
            }
            let other_section = self.packages.iter().any(|p| {
                p.header.machine_id == header.machine_id && p.summary.section_id != section_id
            });
            if other_section {
                return Err(board_err(
                    "§17.6 rule 6: a reserve machine's sessions must all name the same section",
                ));
            }
        } else if machine.section_id != section_id {
            return Err(board_err(format!(
                "§17.6 rule 6: machine {:?} serves section {:?}, not {section_id:?}",
                machine.machine_id, machine.section_id
            )));
        }

        let keys = SessionKeys {
            context_hash: self.context_hash,
            machine_key: machine.key,
            poll_worker_keys: &section.poll_worker_keys,
            min_section_ballots: self.manifest.min_section_ballots,
        };
        let journal = Journal::from_records(records.to_vec());
        let summary = check_journal(&keys, &journal, complete)
            .map_err(|e| board_err(format!("§17.6 rules 5-7: {e}")))?;

        let header_matches = summary.machine_id == header.machine_id
            && summary.section_id == header.section_id
            && summary.session_id == header.session_id
            && summary.measurement == header.measurement;
        if !header_matches {
            return Err(board_err(
                "§17.6 rule 5: package header names a different machine, section, session or measurement than its journal",
            ));
        }
        if header.record_count != journal.len() as u64
            || header.frame_digest != journal.last_digest()
            || header.chain_head != summary.final_head
        {
            return Err(board_err(
                "§17.6 rule 5: package header count, frame digest or chain head does not match the journal",
            ));
        }
        // Rule 8: ballot proof failures are not checked here, because they
        // never reject a package. The tally excludes such ballots.
        Ok(summary)
    }

    /// §17.6 rule 9 and the admission of an accepted package. A package
    /// supersedes an accepted recovered package for the same session (§16.4).
    fn admit(
        &mut self,
        index: u64,
        entry: &Value,
        kind: PackageKind,
        summary: JournalSummary,
        header: PackageHeader,
    ) -> Result<(), Error> {
        let pair = (summary.machine_id.clone(), summary.session_id.clone());
        let mut superseded = None;
        match self.sessions.get(&pair) {
            Some(&prev) => {
                let prev_pkg = &self.packages[prev];
                if kind == PackageKind::Package
                    && prev_pkg.kind == PackageKind::Recovered
                    && !prev_pkg.superseded
                {
                    superseded = Some(prev);
                } else {
                    return Err(board_err("§17.6 rule 9: session already on the board"));
                }
            }
            None => {
                let max = self
                    .registry
                    .as_ref()
                    .and_then(|r| r.section(&summary.section_id))
                    .map_or(0, |s| s.max_sessions);
                let used = self
                    .sessions_per_machine
                    .get(&summary.machine_id)
                    .copied()
                    .unwrap_or(0);
                if used >= max {
                    return Err(board_err(
                        "§17.6 rule 9: machine already has max_sessions sessions on the board",
                    ));
                }
            }
        }
        if let Some(prev) = superseded {
            self.packages[prev].superseded = true;
        } else {
            *self
                .sessions_per_machine
                .entry(summary.machine_id.clone())
                .or_insert(0) += 1;
        }
        let idx = self.packages.len();
        self.packages.push(AcceptedPackage {
            entry_index: index,
            package_id: record_id(entry),
            kind,
            summary,
            header,
            superseded: false,
        });
        self.sessions.insert(pair, idx);
        Ok(())
    }

    /// §16.1 and §17.6: a machine's package.
    fn on_package(&mut self, index: u64, entry: &Value) -> Result<(), Error> {
        self.check_window("package")?;
        let f = record_fields(entry, "package", 5)?;
        let header = PackageHeader::from_value(f[2])?;
        let machine_key = self.machine(&header.machine_id)?.key;
        // Rule 2: signed under the registered key of the machine.
        let package = Package::from_signed(entry, &machine_key)
            .map_err(|e| board_err(format!("§17.6 rule 2: {e}")))?;
        let summary = self.check_records(&package.header, &package.records, true)?;
        self.admit(index, entry, PackageKind::Package, summary, package.header)
    }

    /// §16.4 and §17.6: a recovered package, accepted with a poll worker
    /// signature and a last checkpoint that verifies.
    fn on_recovered(&mut self, index: u64, entry: &Value) -> Result<(), Error> {
        self.check_window("recovered_package")?;
        let rp = RecoveredPackage::from_value(entry)?;
        let summary = self.check_records(&rp.header, &rp.records, false)?;
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| board_err("§17.6: no registry in force"))?;
        let section = registry.section(&summary.section_id).ok_or_else(|| {
            board_err(format!(
                "§17.6 rule 6: section {:?} is not registered",
                summary.section_id
            ))
        })?;
        let unsigned = rp.unsigned_value();
        let signed = rp
            .sigs
            .iter()
            .any(|s| section.poll_worker_keys.contains(&s.key) && s.verify(&unsigned));
        if !signed {
            return Err(board_err(format!(
                "§16.4: recovered package has no section signature by a poll worker of section {:?}",
                summary.section_id
            )));
        }
        self.admit(index, entry, PackageKind::Recovered, summary, rp.header)
    }
}

/// Every key of the registry that is a machine, poll worker or observer key.
fn registry_keys(r: &Registry) -> impl Iterator<Item = &VerifyingKey> {
    r.machines
        .iter()
        .map(|m| &m.key)
        .chain(r.sections.iter().flat_map(|s| s.poll_worker_keys.iter()))
        .chain(r.observers.iter().map(|o| &o.key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{check_ballot, encrypt_ballot, Ballot, BallotId, ContestPlain, Election};
    use crate::cbor;
    use crate::chain::{chain_start, next_head, tracking_code, Status};
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::group::{random_scalar, RistrettoPoint, B};
    use crate::journal::{
        auth_cancel_signature, auth_signature, checkpoint_signature, frame_digest, SessionOpen,
    };
    use crate::registry::sign_registry;
    use crate::tally::{
        fingerprint, indices, judge_cast, split_pooled, sum_ballots, JudgedBallot, Reservations,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    const OPENED_AT: u64 = 1_700_000_000;
    const CHALLENGE: [u8; 16] = [5; 16];
    const S1_MACHINE: &str = "M-S1-01";
    const RESERVE_MACHINE: &str = "M-R-01";
    const SESSION: &str = "S-1";
    /// Measurement approved by the sample manifest (`approved_hashes`).
    const APPROVED: Measurement = Measurement([0xaa; 32]);
    /// A measurement that is not approved.
    const UNAPPROVED: Measurement = Measurement([7; 32]);

    /// The election: manifest with a party key, registry, context, keys.
    struct World {
        manifest: Manifest,
        keys: Keys,
        party_sk: SigningKey,
        context: Context,
        ctx: [u8; 32],
        registry: Registry,
        signed_registry: Value,
        k: RistrettoPoint,
    }

    fn world() -> World {
        let (mut manifest, keys) = sample_manifest(1);
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let party_sk = SigningKey::generate(&mut rng);
        manifest.parties[0].key = Some(party_sk.verifying_key());
        let registry = sample_registry(&manifest, &keys);
        let signed_registry = sign_registry(&registry, &keys.ea);
        let k = random_scalar(&mut rng) * B;
        let context = Context {
            manifest_hash: manifest.hash(),
            transcript_hash: [0; 32],
            k,
            z: vec![k],
        };
        let ctx = context.hash();
        World {
            manifest,
            keys,
            party_sk,
            context,
            ctx,
            registry,
            signed_registry,
            k,
        }
    }

    /// A machine and the poll worker that signs for its section.
    #[derive(Clone)]
    struct Who {
        machine_id: &'static str,
        section_id: &'static str,
        machine_sk: SigningKey,
        pw_sk: SigningKey,
        offered: Vec<u64>,
    }

    fn who_s1(w: &World) -> Who {
        Who {
            machine_id: S1_MACHINE,
            section_id: "S1",
            machine_sk: w.keys.machines[0].clone(),
            pw_sk: w.keys.poll_workers[0].clone(),
            offered: w
                .registry
                .machine(S1_MACHINE)
                .expect("machine")
                .contests
                .clone(),
        }
    }

    /// Choices for the six contests of the sample manifest.
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

    /// Plays a machine's session and keeps the journal as the machine would.
    struct Play<'a> {
        w: &'a World,
        who: Who,
        recs: Vec<Record>,
        last: [u8; 32],
        head: [u8; 32],
        rng: ChaCha20Rng,
        ballots: u64,
        /// Committed ballot waiting for its status: ballot and code.
        pending: Option<(Ballot, [u8; 32])>,
        unused: Option<u64>,
        next_seq: u64,
        /// authorizations, cast
        counts: [u64; 2],
        cast_ballots: Vec<Ballot>,
        session: String,
    }

    impl<'a> Play<'a> {
        /// Opens the session, journals the zerésima and a checkpoint.
        fn new(w: &'a World, who: &Who, session: &str, measurement: Measurement) -> Play<'a> {
            let so = SessionOpen {
                context_hash: w.ctx,
                machine_id: who.machine_id.into(),
                section_id: who.section_id.into(),
                session_id: session.into(),
                measurement,
                opened_at: OPENED_AT,
                opening_challenge: CHALLENGE,
                attestation: None,
            };
            let head = chain_start(
                &so.context_hash,
                &so.machine_id,
                &so.session_id,
                &so.measurement,
                &so.opening_challenge,
            );
            let z = Zeresima {
                context_hash: so.context_hash,
                machine_id: so.machine_id.clone(),
                section_id: so.section_id.clone(),
                session_id: so.session_id.clone(),
                measurement,
                head_0: head,
                session_open_id: record_id(&so.to_value()),
                opened_at: OPENED_AT,
            };
            let zv = z.sign(&who.machine_sk);
            let sig = SectionSig::create(&who.pw_sk, &zv);
            let mut p = Play {
                w,
                who: who.clone(),
                recs: Vec::new(),
                last: [0; 32],
                head,
                rng: ChaCha20Rng::from_seed([9; 32]),
                ballots: 0,
                pending: None,
                unused: None,
                next_seq: 1,
                counts: [0; 2],
                cast_ballots: Vec::new(),
                session: session.into(),
            };
            p.push(Record::SessionOpen(so));
            p.push(Record::ZeresimaSigned {
                zeresima: zv,
                sigs: vec![sig],
            });
            p.checkpoint();
            p
        }

        fn push(&mut self, r: Record) {
            self.last = frame_digest(&self.last, &cbor::encode(&r.to_value()));
            self.recs.push(r);
        }

        fn auth(&mut self) {
            let seq = self.next_seq;
            self.next_seq += 1;
            let pw = &self.who.pw_sk;
            let rec = Record::Authorization {
                seq,
                pw_key: pw.verifying_key(),
                sig: auth_signature(pw, &self.w.ctx, self.who.machine_id, &self.session, seq),
            };
            self.push(rec);
            self.unused = Some(seq);
            self.counts[0] += 1;
        }

        /// Encrypts a ballot under election key `k` (a wrong `k` gives a
        /// ballot whose proofs fail), commits to it and returns its code.
        fn commit(&mut self, row: usize, k: RistrettoPoint) -> [u8; 32] {
            self.ballots += 1;
            let mut rho = [0u8; 32];
            self.rng.fill_bytes(&mut rho);
            let id = BallotId {
                machine_id: self.who.machine_id.into(),
                session_id: self.session.clone(),
                seq: self.ballots,
            };
            let election = Election {
                context_hash: self.w.ctx,
                k,
                manifest: &self.w.manifest,
            };
            let ballot = encrypt_ballot(
                &mut self.rng,
                &election,
                &self.who.offered,
                &id,
                &rho,
                &picks(row),
            )
            .expect("encrypt");
            let code = tracking_code(&self.head, &ballot);
            self.push(Record::Committed {
                ballot: ballot.clone(),
                code,
            });
            self.pending = Some((ballot, code));
            code
        }

        fn cast(&mut self) {
            let (ballot, code) = self.pending.take().expect("pending ballot");
            self.push(Record::Cast { code });
            self.head = next_head(&code, Status::Cast, None);
            self.counts[1] += 1;
            self.unused = None;
            self.cast_ballots.push(ballot);
        }

        fn cancel(&mut self) {
            let seq = self.unused.take().expect("unused authorization");
            let pw = &self.who.pw_sk;
            let sig =
                auth_cancel_signature(pw, &self.w.ctx, self.who.machine_id, &self.session, seq);
            self.push(Record::AuthCancel {
                seq,
                pw_key: pw.verifying_key(),
                sig,
            });
        }

        fn checkpoint(&mut self) {
            let count = self.recs.len() as u64;
            let frame = self.last;
            let head = self.head;
            let sig = checkpoint_signature(
                &self.who.machine_sk,
                &self.w.ctx,
                self.who.machine_id,
                &self.session,
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

        /// Pre-BU over the cast ballots, with the subtotal fingerprint of §18.1
        /// computed as the tally does.
        fn pre_bu(&mut self) {
            let w = self.w;
            let election = Election {
                context_hash: w.ctx,
                k: w.k,
                manifest: &w.manifest,
            };
            let mut reservations = Reservations::new();
            let judged: Vec<JudgedBallot> = self
                .cast_ballots
                .iter()
                .map(|b| judge_cast(&election, &self.who.offered, b, &mut reservations))
                .collect();
            let pairs: Vec<(&Ballot, &JudgedBallot)> =
                self.cast_ballots.iter().zip(&judged).collect();
            let sums = sum_ballots(&election, &pairs);
            let (kept, pooled) = split_pooled(sums, w.manifest.min_section_ballots);
            let pooled_idx = indices(&pooled);
            let fp = fingerprint(
                &w.ctx,
                self.who.machine_id,
                &self.session,
                &[],
                &kept,
                &pooled_idx,
            );
            let pb = PreBu {
                context_hash: w.ctx,
                machine_id: self.who.machine_id.into(),
                section_id: self.who.section_id.into(),
                session_id: self.session.clone(),
                imported: Vec::new(),
                frame_digest: self.last,
                chain_head: self.head,
                authorizations: self.counts[0],
                cast: self.counts[1],
                spoiled: 0,
                abandoned: 0,
                roll_count: 2,
                fingerprint: fp,
                pooled: pooled_idx,
            };
            let pre_bu = pb.sign(&self.who.machine_sk);
            let sig = SectionSig::create(&self.who.pw_sk, &pre_bu);
            self.push(Record::PreBuSigned {
                pre_bu,
                sigs: vec![sig],
            });
        }

        fn close(&mut self) {
            self.push(Record::SessionClose {
                authorizations: self.counts[0],
                cast: self.counts[1],
                spoiled: 0,
                abandoned: 0,
                final_head: self.head,
                closed_at: OPENED_AT + 100,
                attestation: None,
            });
        }

        fn finish(self) -> Vec<Record> {
            self.recs
        }
    }

    /// Two voters, each authorized, committed, cast and checkpointed.
    fn two_voters(p: &mut Play<'_>, k: RistrettoPoint) {
        p.auth();
        p.commit(0, k);
        p.cast();
        p.checkpoint();
        p.auth();
        p.commit(1, k);
        p.cast();
        p.checkpoint();
    }

    /// A complete session: two voters, one cancelled authorization, pre-BU,
    /// checkpoint and session_close.
    fn full_session(w: &World, who: &Who, session: &str, measurement: Measurement) -> Vec<Record> {
        let mut p = Play::new(w, who, session, measurement);
        two_voters(&mut p, w.k);
        p.auth();
        p.cancel();
        p.pre_bu();
        p.checkpoint();
        p.close();
        p.finish()
    }

    /// The journal cut at the last checkpoint before the first cancellation.
    fn recovered_prefix(recs: &[Record]) -> Vec<Record> {
        let end = recs
            .iter()
            .position(|r| matches!(r, Record::AuthCancel { .. }))
            .expect("cancellation");
        let cut = recs[..end]
            .iter()
            .rposition(|r| matches!(r, Record::Checkpoint { .. }))
            .expect("checkpoint");
        recs[..=cut].to_vec()
    }

    fn package_of(w: &World, who: &Who, recs: Vec<Record>, measurement: Measurement) -> Value {
        build_package(
            &Journal::from_records(recs),
            &w.ctx,
            who.machine_id,
            who.section_id,
            SESSION,
            measurement,
            &who.machine_sk,
        )
        .expect("package")
    }

    fn recovered_of(w: &World, who: &Who, recs: &[Record], signer: Option<&SigningKey>) -> Value {
        let mut rp = build_recovered(
            &Journal::from_records(recovered_prefix(recs)),
            &w.ctx,
            who.machine_id,
            who.section_id,
            SESSION,
            APPROVED,
            2,
        )
        .expect("recovered");
        if let Some(sk) = signer {
            rp.add_sig(sk);
        }
        rp.to_value()
    }

    fn polls_open_entry(w: &World) -> Value {
        PollsOpen {
            context_hash: w.ctx,
            registry_id: record_id(&w.signed_registry),
            time: OPENED_AT,
        }
        .sign(&w.keys.ea)
    }

    fn cutoff_entry(w: &World) -> Value {
        TallyCutoff {
            context_hash: w.ctx,
            time: OPENED_AT + 1000,
        }
        .sign(&w.keys.ea)
    }

    fn cert_entry(w: &World, observer: &SigningKey) -> Value {
        ObserverCert {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: observer.verifying_key(),
        }
        .sign(&w.party_sk)
    }

    /// Asserts that `st` accepts `entry`.
    fn accept(st: &mut BoardState<'_>, entry: &Value) {
        match st.ingest(entry) {
            Ingest::Accepted => {}
            Ingest::Rejected(r) => panic!("expected acceptance, got rejection: {r}"),
        }
    }

    /// Asserts that `st` rejects `entry` with a reason containing `needle`.
    fn refuse(st: &mut BoardState<'_>, entry: &Value, needle: &str) {
        match st.ingest(entry) {
            Ingest::Accepted => panic!("expected a rejection containing {needle:?}"),
            Ingest::Rejected(r) => {
                assert!(r.contains(needle), "reason {r:?} lacks {needle:?}")
            }
        }
    }

    /// A board with the registry, one certified observer and polls open.
    fn open_board<'a>(w: &'a World, observer: &SigningKey) -> BoardState<'a> {
        let mut st = BoardState::new(&w.manifest, &w.context);
        accept(&mut st, &w.signed_registry);
        accept(&mut st, &cert_entry(w, observer));
        accept(&mut st, &polls_open_entry(w));
        st
    }

    fn pre_bu_of(recs: &[Record]) -> Value {
        recs.iter()
            .find_map(|r| match r {
                Record::PreBuSigned { pre_bu, .. } => Some(pre_bu.clone()),
                _ => None,
            })
            .expect("pre_bu")
    }

    #[test]
    fn happy_path_is_accepted_and_listed() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        accept(&mut st, &package_of(&w, &who_s1(&w), recs, APPROVED));
        accept(&mut st, &cutoff_entry(&w));
        let pkgs = st.accepted_packages();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].kind, PackageKind::Package);
        assert!(!pkgs[0].superseded);
        assert_eq!(pkgs[0].header.machine_id, S1_MACHINE);
        assert_eq!(pkgs[0].summary.cast, 2);
        assert!(st.cutoff());
    }

    #[test]
    fn unknown_entries_are_accepted_without_checks() {
        let w = world();
        let mut st = BoardState::new(&w.manifest, &w.context);
        accept(
            &mut st,
            &Value::Map(vec![(Value::Uint(0), Value::from("rejection"))]),
        );
    }

    #[test]
    fn registry_after_polls_open_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let mut v2 = w.registry.clone();
        v2.version = 2;
        refuse(&mut st, &sign_registry(&v2, &w.keys.ea), "after polls_open");
    }

    #[test]
    fn observer_cert_after_polls_open_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let late = SigningKey::generate(&mut ChaCha20Rng::from_seed([12; 32]));
        refuse(&mut st, &cert_entry(&w, &late), "after polls_open");
    }

    #[test]
    fn package_before_polls_open_is_rejected() {
        let w = world();
        let mut st = BoardState::new(&w.manifest, &w.context);
        accept(&mut st, &w.signed_registry);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        refuse(
            &mut st,
            &package_of(&w, &who_s1(&w), recs, APPROVED),
            "before polls_open",
        );
    }

    #[test]
    fn package_after_tally_cutoff_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        accept(&mut st, &cutoff_entry(&w));
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        refuse(
            &mut st,
            &package_of(&w, &who_s1(&w), recs, APPROVED),
            "after tally_cutoff",
        );
    }

    #[test]
    fn package_signed_by_wrong_machine_key_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let mut who = who_s1(&w);
        who.machine_sk = w.keys.machines[1].clone();
        let recs = full_session(&w, &who, SESSION, APPROVED);
        let entry = build_package(
            &Journal::from_records(recs),
            &w.ctx,
            S1_MACHINE,
            "S1",
            SESSION,
            APPROVED,
            &who.machine_sk,
        )
        .expect("package");
        refuse(&mut st, &entry, "rule 2");
    }

    #[test]
    fn context_mismatch_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        let entry = build_package(
            &Journal::from_records(recs),
            &[9; 32],
            S1_MACHINE,
            "S1",
            SESSION,
            APPROVED,
            &w.keys.machines[0],
        )
        .expect("package");
        refuse(&mut st, &entry, "rule 3");
    }

    #[test]
    fn unapproved_measurement_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, UNAPPROVED);
        refuse(&mut st, &package_of(&w, &who, recs, UNAPPROVED), "rule 4");
    }

    #[test]
    fn broken_journal_invariant_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let mut recs = full_session(&w, &who, SESSION, APPROVED);
        if let Some(Record::SessionClose { cast, .. }) = recs.last_mut() {
            *cast += 1;
        }
        refuse(
            &mut st,
            &package_of(&w, &who, recs, APPROVED),
            "session_close counts",
        );
    }

    #[test]
    fn duplicate_session_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let entry = package_of(
            &w,
            &who,
            full_session(&w, &who, SESSION, APPROVED),
            APPROVED,
        );
        accept(&mut st, &entry);
        refuse(&mut st, &entry, "rule 9: session already on the board");
    }

    #[test]
    fn exceeding_max_sessions_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        // The sample section allows two sessions per machine.
        for s in ["S-1", "S-2"] {
            let recs = full_session(&w, &who, s, APPROVED);
            let entry = build_package(
                &Journal::from_records(recs),
                &w.ctx,
                S1_MACHINE,
                "S1",
                s,
                APPROVED,
                &who.machine_sk,
            )
            .expect("package");
            accept(&mut st, &entry);
        }
        let recs = full_session(&w, &who, "S-3", APPROVED);
        let entry = build_package(
            &Journal::from_records(recs),
            &w.ctx,
            S1_MACHINE,
            "S1",
            "S-3",
            APPROVED,
            &who.machine_sk,
        )
        .expect("package");
        refuse(&mut st, &entry, "max_sessions");
    }

    #[test]
    fn poll_worker_of_another_section_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let mut who = who_s1(&w);
        // Poll worker 2 belongs to section S2.
        who.pw_sk = w.keys.poll_workers[2].clone();
        let recs = full_session(&w, &who, SESSION, APPROVED);
        refuse(
            &mut st,
            &package_of(&w, &who, recs, APPROVED),
            "no valid poll worker",
        );
    }

    #[test]
    fn ballot_with_broken_proof_still_accepted() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        // Ballot encrypted under another election key: its proofs fail.
        let mut rng = ChaCha20Rng::from_seed([21; 32]);
        let other_k = random_scalar(&mut rng) * B;
        let mut p = Play::new(&w, &who, SESSION, APPROVED);
        p.auth();
        p.commit(0, other_k);
        // The ballot is judged as the tally would judge it.
        let election = Election {
            context_hash: w.ctx,
            k: w.k,
            manifest: &w.manifest,
        };
        let bad = p.pending.as_ref().expect("pending").0.clone();
        let judged = check_ballot(&election, &who.offered, &bad);
        assert!(
            judged.well_formed.is_err()
                || judged
                    .contests
                    .iter()
                    .any(|(_, s)| *s != crate::ballot::ContestStatus::Counted),
            "the broken ballot must not count"
        );
        p.cast();
        p.checkpoint();
        p.auth();
        p.cancel();
        p.pre_bu();
        p.checkpoint();
        p.close();
        accept(&mut st, &package_of(&w, &who, p.finish(), APPROVED));
        assert_eq!(st.accepted_packages().len(), 1);
    }

    #[test]
    fn recovered_package_with_poll_worker_signature_is_accepted() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, APPROVED);
        let pw = w.keys.poll_workers[1].clone();
        accept(&mut st, &recovered_of(&w, &who, &recs, Some(&pw)));
        let pkgs = st.accepted_packages();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].kind, PackageKind::Recovered);
        assert_eq!(pkgs[0].summary.cast, 2);
        assert!(!pkgs[0].summary.complete);
    }

    #[test]
    fn recovered_package_without_poll_worker_signature_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, APPROVED);
        refuse(
            &mut st,
            &recovered_of(&w, &who, &recs, None),
            "section signature",
        );
        // A signature by an observer is not a poll worker signature.
        refuse(
            &mut st,
            &recovered_of(&w, &who, &recs, Some(&w.keys.observers[0])),
            "section signature",
        );
    }

    #[test]
    fn recovered_package_is_superseded_by_the_real_package() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, APPROVED);
        let pw = w.keys.poll_workers[0].clone();
        accept(&mut st, &recovered_of(&w, &who, &recs, Some(&pw)));
        accept(&mut st, &package_of(&w, &who, recs, APPROVED));
        let pkgs = st.accepted_packages();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs[0].superseded);
        assert_eq!(pkgs[0].kind, PackageKind::Recovered);
        assert_eq!(pkgs[1].kind, PackageKind::Package);
        assert!(!pkgs[1].superseded);
    }

    #[test]
    fn recovered_after_package_for_same_session_is_rejected() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, APPROVED);
        accept(&mut st, &package_of(&w, &who, recs.clone(), APPROVED));
        let pw = w.keys.poll_workers[0].clone();
        refuse(
            &mut st,
            &recovered_of(&w, &who, &recs, Some(&pw)),
            "rule 9: session already on the board",
        );
    }

    #[test]
    fn section_attestation_of_pre_bu_by_observer_is_accepted() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        let pb = pre_bu_of(&recs);
        // Registry observer, and the certified one.
        for observer in [&w.keys.observers[0], &certified] {
            let entry = SectionAttestation::create(observer, &pb).to_value();
            accept(&mut st, &entry);
        }
        let atts = st.attestations();
        assert_eq!(atts.len(), 2);
        assert_eq!(atts[0].record_tag, "pre_bu");
        assert_eq!(atts[0].machine_id, S1_MACHINE);
        assert_eq!(atts[0].section_id, "S1");
    }

    #[test]
    fn section_attestation_by_poll_worker_of_zeresima_is_accepted() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        let zv = match &recs[1] {
            Record::ZeresimaSigned { zeresima, .. } => zeresima.clone(),
            _ => panic!("zeresima"),
        };
        accept(
            &mut st,
            &SectionAttestation::create(&w.keys.poll_workers[1], &zv).to_value(),
        );
        assert_eq!(st.attestations()[0].record_tag, "zeresima");
    }

    #[test]
    fn section_attestation_by_unknown_key_is_rejected() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        let stranger = SigningKey::generate(&mut ChaCha20Rng::from_seed([31; 32]));
        let entry = SectionAttestation::create(&stranger, &pre_bu_of(&recs)).to_value();
        refuse(&mut st, &entry, "neither a poll worker");
    }

    #[test]
    fn revoked_observer_attestation_is_rejected_and_earlier_ones_stay_valid() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        let recs = full_session(&w, &who_s1(&w), SESSION, APPROVED);
        let pb = pre_bu_of(&recs);
        let entry = SectionAttestation::create(&certified, &pb).to_value();
        accept(&mut st, &entry);
        let revoke = ObserverRevoke {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: certified.verifying_key(),
        }
        .sign(&w.party_sk);
        accept(&mut st, &revoke);
        refuse(&mut st, &entry, "revoked");
        assert_eq!(st.attestations().len(), 1);
    }

    #[test]
    fn revocation_by_a_party_of_a_registry_key_is_rejected() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        let revoke = ObserverRevoke {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: w.keys.poll_workers[0].verifying_key(),
        }
        .sign(&w.party_sk);
        refuse(&mut st, &revoke, "only observers certified");
    }

    #[test]
    fn revocation_after_tally_cutoff_is_rejected() {
        let w = world();
        let certified = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &certified);
        accept(&mut st, &cutoff_entry(&w));
        let revoke = ObserverRevoke {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: certified.verifying_key(),
        }
        .sign(&w.party_sk);
        refuse(&mut st, &revoke, "after tally_cutoff");
    }

    #[test]
    fn policy_update_adds_and_withdraws_hashes_before_polls_open() {
        let w = world();
        let mut st = BoardState::new(&w.manifest, &w.context);
        let new_hash = [0xbb; 32];
        let update = sign_record(
            &w.keys.ea,
            SIG_POLICY_UPDATE,
            kv(vec![
                (0, Value::from("software_policy_update")),
                (1, Value::Uint(VERSION)),
                (2, Value::from(w.ctx)),
                (3, Value::Array(vec![Value::from(new_hash)])),
                (4, Value::Array(vec![Value::from([0xaa; 32])])),
            ]),
            5,
        );
        accept(&mut st, &update);
        assert!(st.approved.contains(&new_hash));
        assert!(!st.approved.contains(&[0xaa; 32]));
    }

    #[test]
    fn records_round_trip() {
        let w = world();
        let who = who_s1(&w);
        let recs = full_session(&w, &who, SESSION, APPROVED);

        let pkg = Package {
            header: PackageHeader {
                context_hash: w.ctx,
                machine_id: S1_MACHINE.into(),
                section_id: "S1".into(),
                session_id: SESSION.into(),
                measurement: APPROVED,
                attestation: Some(Value::Bytes(vec![1, 2])),
                record_count: recs.len() as u64,
                frame_digest: [1; 32],
                chain_head: [2; 32],
            },
            records: recs.clone(),
        };
        let signed = pkg.sign(&who.machine_sk);
        let decoded = cbor::decode(&cbor::encode(&signed)).expect("cbor");
        assert_eq!(
            Package::from_signed(&decoded, &who.machine_sk.verifying_key()).expect("package"),
            pkg
        );
        assert!(Package::from_signed(&decoded, &w.keys.machines[1].verifying_key()).is_err());

        let mut rp = RecoveredPackage {
            header: pkg.header.clone(),
            records: recovered_prefix(&recs),
            roll_count: 2,
            sigs: Vec::new(),
        };
        rp.add_sig(&w.keys.poll_workers[0]);
        let back = RecoveredPackage::from_value(
            &cbor::decode(&cbor::encode(&rp.to_value())).expect("cbor"),
        )
        .expect("recovered");
        assert_eq!(back, rp);

        let cert = ObserverCert {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: w.keys.observers[0].verifying_key(),
        };
        let cert_v = cert.sign(&w.party_sk);
        assert_eq!(
            ObserverCert::from_signed(&cert_v, &w.party_sk.verifying_key()).expect("cert"),
            cert
        );
        let rev = ObserverRevoke {
            context_hash: w.ctx,
            party_index: 0,
            observer_key: w.keys.observers[0].verifying_key(),
        };
        let rev_v = rev.sign(&w.party_sk);
        assert_eq!(
            ObserverRevoke::from_signed(&rev_v, &w.party_sk.verifying_key()).expect("revoke"),
            rev
        );
        assert!(ObserverCert::from_signed(&cert_v, &w.keys.ea.verifying_key()).is_err());

        let att = SectionAttestation::create(&w.keys.observers[1], &pre_bu_of(&recs));
        assert!(att.verify());
        let att_v = att.to_value();
        assert_eq!(
            SectionAttestation::from_value(&cbor::decode(&cbor::encode(&att_v)).expect("cbor"))
                .expect("attestation"),
            att
        );
        // Only zeresima and pre_bu records may be attested.
        let bad = SectionAttestation::create(&w.keys.observers[1], &cert_v);
        assert!(SectionAttestation::from_value(&bad.to_value()).is_err());
    }

    #[test]
    fn reserve_machine_serves_the_section_it_names() {
        let w = world();
        let observer = SigningKey::generate(&mut ChaCha20Rng::from_seed([11; 32]));
        let mut st = open_board(&w, &observer);
        // The reserve machine offers the same contests as the regular machines.
        let reserve = Who {
            machine_id: RESERVE_MACHINE,
            section_id: "S1",
            machine_sk: w.keys.machines[2].clone(),
            pw_sk: w.keys.poll_workers[0].clone(),
            offered: w
                .registry
                .machine(RESERVE_MACHINE)
                .expect("machine")
                .contests
                .clone(),
        };
        let recs = full_session(&w, &reserve, SESSION, APPROVED);
        accept(&mut st, &package_of(&w, &reserve, recs, APPROVED));
        assert_eq!(st.accepted_packages()[0].summary.section_id, "S1");
        // A second session of the same reserve machine must name the same section.
        let other = Who {
            section_id: "S2",
            pw_sk: w.keys.poll_workers[2].clone(),
            ..reserve.clone()
        };
        let recs = full_session(&w, &other, "S-2", APPROVED);
        refuse(
            &mut st,
            &package_of(&w, &other, recs, APPROVED),
            "same section",
        );
    }

    #[test]
    fn build_package_needs_a_closed_journal() {
        let w = world();
        let who = who_s1(&w);
        let mut p = Play::new(&w, &who, SESSION, APPROVED);
        two_voters(&mut p, w.k);
        let open = Journal::from_records(p.finish());
        assert!(build_package(
            &open,
            &w.ctx,
            S1_MACHINE,
            "S1",
            SESSION,
            APPROVED,
            &who.machine_sk
        )
        .is_err());
    }
}
