//! eg/v1 election verifier (SPEC.md §23).
//!
//! [`verify`] takes a board dump and at least one signed tree head, runs the
//! sixteen steps of §23 in order and returns a [`Report`]. Each step is a
//! function in this crate. A failure names its step, the board entry index where
//! there is one, and the section of this spec it breaks.
//!
//! Deviation (`docs/spec-issues.md` item 9): the verifier reuses the record
//! codecs and `verify` functions of `eg-core`, and the pure post-election
//! pipeline of `eg_core::authority` (board view, section tallies, pool, mix plan,
//! election result). Everything else is recomputed here from the board.
//!
//! Fingerprints in the independence report are the first 8 bytes of SHA-256 over
//! the Ed25519 public key bytes, in lower-case hex (16 characters).
//!
//! The verifier never panics on malformed input: every decode error becomes a
//! [`Finding`].

mod board;
mod packages;
mod result;
mod tally;

use eg_core::board::record_id;
use eg_core::cbor::Value;
use eg_core::ceremony::Context;
use eg_core::journal::Record;
use eg_core::manifest::Manifest;
use eg_core::package::{AcceptedAttestation, AcceptedPackage, BoardState, Ingest};
use eg_core::registry::Registry;
use eg_core::sign::VerifyingKey;
use sha2::{Digest, Sha256};

pub use eg_core::decrypt::ElectionResult;

/// One problem found by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Step of §23 (1 to 16).
    pub step: u8,
    /// Board entry index, if the problem is about one entry.
    pub entry: Option<u64>,
    /// Section of this spec that the problem breaks, e.g. "§12.6".
    pub section: &'static str,
    pub message: String,
}

/// The verifier's output.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Violations. Any failure means FAIL.
    pub failures: Vec<Finding>,
    /// Things that don't break an invariant but need attention, e.g. a pool
    /// smaller than `min_section_ballots`, or a package the board rejected.
    pub warnings: Vec<Finding>,
    /// §23 step 6: every excluded ballot or contest, with its machine and the
    /// failing check.
    pub excluded: Vec<Finding>,
    /// §23 step 16.
    pub independence: Independence,
    /// The election result, recomputed from the board. Set when step 13 runs.
    pub result: Option<ElectionResult>,
    /// `context_hash` recomputed from the key ceremony (step 4).
    pub context_hash: Option<[u8; 32]>,
}

impl Report {
    /// True when no step found a violation.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// What rests on the election authority's word alone (§2.4, §23 step 16).
#[derive(Clone, Debug, Default)]
pub struct Independence {
    /// Trustees, with organisation, bloc and signing key fingerprint.
    pub trustees: Vec<Party>,
    /// Release signers of the software policy, with bloc and fingerprint.
    pub release_signers: Vec<Party>,
    /// Mirrors of the manifest, with operator, bloc and fingerprint.
    pub mirrors: Vec<Party>,
    /// Results of the manifest rules 11, 12 and 13 (§7.2), by rule number.
    pub rules_11_13: Vec<(u8, bool)>,
    /// Every party of the manifest: name and fingerprint of its key, if it has
    /// one.
    pub party_keys: Vec<(String, Option<String>)>,
    /// Sections where no zerésima or pre-BU carries an observer signature.
    pub sections_without_observer: Vec<String>,
    /// Parties of the manifest with no accepted observer certificate. These are
    /// the recommended independent parties that did not take part in observing.
    pub parties_without_observer: Vec<String>,
}

/// A party or an organisation named in the manifest or the ceremony.
#[derive(Clone, Debug)]
pub struct Party {
    pub organisation: String,
    pub bloc: String,
    /// Hex of the first 8 bytes of SHA-256 over the public key bytes.
    pub fingerprint: String,
}

/// Verifies a board dump. `entries` = every board entry in order. `sths` =
/// signed tree heads (at least one) from any source, such as the board or
/// mirrors.
pub fn verify(entries: &[Value], sths: &[Value]) -> Report {
    let mut rep = Report::default();
    let Some(manifest) = board::step2_manifest(entries, &mut rep) else {
        return rep;
    };
    let log = board::build_log(entries);
    board::step1_board(&log, &manifest, sths, &mut rep);
    let Some(context) = board::step3_ceremony(entries, &manifest, &mut rep) else {
        return rep;
    };
    board::step4_context(entries, &manifest, &context, &mut rep);
    let ledger = Ledger::run(entries, &manifest, &context);
    board::step5_freeze(entries, &manifest, &ledger, &mut rep);
    let Some(view) = packages::step6_packages(entries, &manifest, &context, &ledger, &mut rep)
    else {
        return rep;
    };
    packages::step7_completeness(&view, entries, &ledger, &mut rep);
    packages::step8_spoiled(&view, &context, &manifest, &mut rep);
    let homo = tally::step9_homomorphic(&view, entries, &log, &manifest, &mut rep);
    let mix = tally::step10_mixnet(&view, entries, &manifest, &context, &mut rep);
    let sets = tally::step11_decryption(entries, &homo, &mix, &manifest, &context, &mut rep);
    let finals = tally::step12_final_bus(entries, &homo, &manifest, &context, &mut rep);
    let recomputed = result::step13_counts(&view, &homo, &finals, &sets, &mix, &mut rep);
    let published = result::decode_published(entries, &manifest, &mut rep);
    result::step14_apportionment(&published, &manifest, &mut rep);
    result::step15_result(&published, recomputed.as_ref(), &mut rep);
    rep.result = recomputed;
    result::step16_independence(&manifest, &ledger, &mut rep);
    rep
}

/// The board run through the stateful ingester of §17.6 and §17.7, once, in board
/// order. Shared by several steps.
pub(crate) struct Ledger {
    /// Verdict on every entry, in board order.
    pub verdicts: Vec<Ingest>,
    /// Accepted packages and recovered packages, in board order.
    pub packages: Vec<AcceptedPackage>,
    /// Accepted section attestations, in board order.
    pub attestations: Vec<AcceptedAttestation>,
    /// Observer keys in force: registry observers, plus certified observers, less
    /// revoked ones.
    pub observers: Vec<VerifyingKey>,
    /// Indices of parties with at least one accepted observer certificate.
    pub cert_parties: Vec<u64>,
}

impl Ledger {
    pub(crate) fn run(entries: &[Value], manifest: &Manifest, context: &Context) -> Ledger {
        let mut state = BoardState::new(manifest, context);
        let verdicts: Vec<Ingest> = entries.iter().map(|e| state.ingest(e)).collect();
        let packages = state.accepted_packages().to_vec();
        let attestations = state.attestations().to_vec();

        let mut observers: Vec<VerifyingKey> = state
            .registry()
            .map(|r| r.observers.iter().map(|o| o.key).collect())
            .unwrap_or_default();
        let mut cert_parties = Vec::new();
        let mut revoked: Vec<VerifyingKey> = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            if !matches!(verdicts[i], Ingest::Accepted) {
                continue;
            }
            match e.get(0).ok().flatten().and_then(|t| t.as_text().ok()) {
                Some("observer_cert") => {
                    for party in &manifest.parties {
                        let Some(pk) = party.key.as_ref() else {
                            continue;
                        };
                        // The certificate counts only for the party whose key
                        // signed it (§16.3), so a cert can't credit another party.
                        if let Some(cert) = eg_core::package::ObserverCert::from_signed(e, pk)
                            .ok()
                            .filter(|c| c.party_index == party.index)
                        {
                            observers.push(cert.observer_key);
                            cert_parties.push(cert.party_index);
                            break;
                        }
                    }
                }
                Some("observer_revoke") => {
                    for party in &manifest.parties {
                        let Some(pk) = party.key.as_ref() else {
                            continue;
                        };
                        if let Ok(rev) = eg_core::package::ObserverRevoke::from_signed(e, pk) {
                            revoked.push(rev.observer_key);
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        observers.retain(|k| !revoked.contains(k));
        Ledger {
            verdicts,
            packages,
            attestations,
            observers,
            cert_parties,
        }
    }

    /// Whether `key` is an observer in force.
    pub(crate) fn is_observer(&self, key: &VerifyingKey) -> bool {
        self.observers.contains(key)
    }
}

/// Records a finding of the given step.
pub(crate) fn fail(
    rep: &mut Report,
    step: u8,
    entry: Option<u64>,
    section: &'static str,
    message: impl Into<String>,
) {
    rep.failures.push(Finding {
        step,
        entry,
        section,
        message: message.into(),
    });
}

/// Records a warning of the given step.
pub(crate) fn warn(
    rep: &mut Report,
    step: u8,
    entry: Option<u64>,
    section: &'static str,
    message: impl Into<String>,
) {
    rep.warnings.push(Finding {
        step,
        entry,
        section,
        message: message.into(),
    });
}

/// Records an excluded ballot or contest (§23 step 6).
pub(crate) fn exclude(
    rep: &mut Report,
    entry: Option<u64>,
    section: &'static str,
    message: impl Into<String>,
) {
    rep.excluded.push(Finding {
        step: 6,
        entry,
        section,
        message: message.into(),
    });
}

/// Field 0 of a board entry: its type tag.
pub(crate) fn tag(e: &Value) -> Option<&str> {
    e.get(0).ok().flatten().and_then(|t| t.as_text().ok())
}

/// Unsigned integer at field `k` of a record.
pub(crate) fn uint_at(e: &Value, k: u64) -> Option<u64> {
    e.get(k).ok().flatten().and_then(|v| v.as_uint().ok())
}

/// Text at field `k` of a record.
pub(crate) fn text_at(e: &Value, k: u64) -> Option<&str> {
    e.get(k).ok().flatten().and_then(|v| v.as_text().ok())
}

/// The fingerprint of a public key: hex of the first 8 bytes of SHA-256.
pub(crate) fn fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// RecordId of a board entry, as packages and rejections name it (§15.5).
pub(crate) fn entry_id(e: &Value) -> [u8; 32] {
    record_id(e)
}

/// Records of a package or recovered package, decoded with the registered machine
/// key (packages) or without a key (recovered packages, which the poll workers
/// sign separately). `None` if the entry does not decode.
pub(crate) fn records_of(
    entry: &Value,
    recovered: bool,
    machine_id: &str,
    registry: &Registry,
) -> Option<Vec<Record>> {
    if recovered {
        eg_core::package::RecoveredPackage::from_value(entry)
            .ok()
            .map(|r| r.records)
    } else {
        let machine = registry.machine(machine_id)?;
        eg_core::package::Package::from_signed(entry, &machine.key)
            .ok()
            .map(|p| p.records)
    }
}
