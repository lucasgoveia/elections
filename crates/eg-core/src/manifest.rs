//! Election manifest (SPEC.md §7.1–§7.5, §22.2–§22.3, §24.4).
//!
//! The manifest is the public description of an election. The EA signs it and
//! every later record refers to it by hash. Decoding is strict (unknown keys
//! and wrong types are rejected). [`Manifest::validate`] checks the
//! well-formedness rules of §7.2; errors name the first violated rule.

use std::collections::{HashMap, HashSet};

use crate::cbor::{self, CborError, Value};
use crate::ceremony::TrusteeSet;
use crate::error::Error;
use crate::hash::digest;
use crate::sign::{
    sign, signature_from_value, signature_to_value, verify, verifying_key_from_value,
    verifying_key_to_value, SigningKey, VerifyingKey,
};

/// Version carried by the manifest (field 1, SPEC.md §6.3).
const VERSION: u64 = 1;

/// Signature domain tag of the manifest (SPEC.md §7.3).
const SIG_MANIFEST: &str = "eg/v1/sig/manifest";

/// Upper bound on the number of options plus one for mixnet contests (§7.2 rule 6).
const MIXNET_OPTION_BOUND: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Shared decoding helpers (also used by the registry module).
// ---------------------------------------------------------------------------

/// Schema error with a short message.
pub(crate) fn schema(msg: impl Into<String>) -> Error {
    Error::Cbor(CborError::Schema(msg.into()))
}

/// Builds a record map from `(key, value)` pairs with uint keys.
pub(crate) fn record(entries: Vec<(u64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Uint(k), v))
            .collect(),
    )
}

/// Checks that a record's version field is 1 (SPEC.md §6.3).
pub(crate) fn expect_version(v: &Value) -> Result<(), Error> {
    if v.as_uint()? != VERSION {
        return Err(schema("unsupported record version"));
    }
    Ok(())
}

/// Decodes a 32-byte byte string (digest, hash or fixed-size key material).
pub(crate) fn bytes32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()?
        .try_into()
        .map_err(|_| schema("expected a 32-byte byte string"))
}

/// Decodes a CBOR array with at least `min` items, each with `item`.
pub(crate) fn decode_list<T>(
    v: &Value,
    min: usize,
    what: &str,
    item: impl Fn(&Value) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let items = v.as_array()?;
    if items.len() < min {
        return Err(schema(format!("{what} must have at least {min} entries")));
    }
    items.iter().map(item).collect()
}

/// Decodes a uint item.
pub(crate) fn uint_item(v: &Value) -> Result<u64, Error> {
    Ok(v.as_uint()?)
}

/// Decodes an optional uint field (`None` when absent).
fn opt_uint(v: Option<&Value>) -> Result<Option<u64>, Error> {
    Ok(v.map(|x| x.as_uint()).transpose()?)
}

/// Decodes an optional text field (`None` when absent).
fn opt_text(v: Option<&Value>) -> Result<Option<String>, Error> {
    Ok(v.map(|x| x.as_text().map(str::to_owned)).transpose()?)
}

/// Decodes an optional ed25519 public key field (`None` when absent).
fn opt_key(v: Option<&Value>) -> Result<Option<VerifyingKey>, Error> {
    v.map(verifying_key_from_value).transpose()
}

/// Rule-violation error for §7.2, e.g. `rule 11: ...`.
fn rule(n: u32, msg: impl Into<String>) -> Error {
    Error::Manifest(format!("rule {n}: {}", msg.into()))
}

/// Structural error for constraints that are not numbered rules (indices of
/// parties, federations and link groups, cardinalities of CDDL `[+ ...]`).
fn structure(msg: impl Into<String>) -> Error {
    Error::Manifest(format!("structure: {}", msg.into()))
}

// ---------------------------------------------------------------------------
// Enumerations with spec text encodings.
// ---------------------------------------------------------------------------

/// Contest kind (§7.1 field 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContestKind {
    Single,
    Multi,
    Proportional,
}

impl ContestKind {
    fn as_str(self) -> &'static str {
        match self {
            ContestKind::Single => "single",
            ContestKind::Multi => "multi",
            ContestKind::Proportional => "proportional",
        }
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        match v.as_text()? {
            "single" => Ok(ContestKind::Single),
            "multi" => Ok(ContestKind::Multi),
            "proportional" => Ok(ContestKind::Proportional),
            _ => Err(schema("unknown contest kind")),
        }
    }
}

/// Counting method (§7.1 field 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Homomorphic,
    Mixnet,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Homomorphic => "homomorphic",
            Method::Mixnet => "mixnet",
        }
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        match v.as_text()? {
            "homomorphic" => Ok(Method::Homomorphic),
            "mixnet" => Ok(Method::Mixnet),
            _ => Err(schema("unknown method")),
        }
    }
}

/// Option kind (§7.1 option field 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionKind {
    Candidate,
    Party,
    Blank,
    Null,
}

impl OptionKind {
    fn as_str(self) -> &'static str {
        match self {
            OptionKind::Candidate => "candidate",
            OptionKind::Party => "party",
            OptionKind::Blank => "blank",
            OptionKind::Null => "null",
        }
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        match v.as_text()? {
            "candidate" => Ok(OptionKind::Candidate),
            "party" => Ok(OptionKind::Party),
            "blank" => Ok(OptionKind::Blank),
            "null" => Ok(OptionKind::Null),
            _ => Err(schema("unknown option kind")),
        }
    }
}

// ---------------------------------------------------------------------------
// Apportionment rules (§22.2, §22.3).
// ---------------------------------------------------------------------------

/// Apportionment rule of a proportional contest (§22.2 `dhondt_rule`, §22.3 `brazil_rule`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApportionmentRule {
    /// `{ 0: "dhondt", ? 1: uint }`. The threshold is in basis points of V.
    Dhondt { threshold_bp: Option<u64> },
    /// `{ 0: "brazil-2021", 1..4 }`. Parameters are explicit so they can change
    /// without changing code. LEGAL REVIEW REQUIRED (§22.3).
    Brazil2021 {
        /// Field 1: candidate minimum for quotient seats, basis points of QE.
        cand_min_quotient_bp: u64,
        /// Field 2: list minimum for remainder seats, basis points of QE.
        list_min_remainder_bp: u64,
        /// Field 3: candidate minimum for remainder seats, basis points of QE.
        cand_min_remainder_bp: u64,
        /// Field 4: final phase open to all lists without thresholds.
        final_phase_open: bool,
    },
}

impl ApportionmentRule {
    pub fn to_value(&self) -> Value {
        match self {
            ApportionmentRule::Dhondt { threshold_bp } => {
                let mut entries = vec![(0, Value::from("dhondt"))];
                if let Some(t) = threshold_bp {
                    entries.push((1, Value::Uint(*t)));
                }
                record(entries)
            }
            ApportionmentRule::Brazil2021 {
                cand_min_quotient_bp,
                list_min_remainder_bp,
                cand_min_remainder_bp,
                final_phase_open,
            } => record(vec![
                (0, Value::from("brazil-2021")),
                (1, Value::Uint(*cand_min_quotient_bp)),
                (2, Value::Uint(*list_min_remainder_bp)),
                (3, Value::Uint(*cand_min_remainder_bp)),
                (4, Value::Bool(*final_phase_open)),
            ]),
        }
    }

    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let tag = v
            .get(0)?
            .ok_or_else(|| schema("apportionment rule has no type tag"))?
            .as_text()?;
        match tag {
            "dhondt" => {
                let f = cbor::record_fields_opt(v, "dhondt", 1, &[1])?;
                Ok(ApportionmentRule::Dhondt {
                    threshold_bp: opt_uint(f[1])?,
                })
            }
            "brazil-2021" => {
                let f = cbor::record_fields(v, "brazil-2021", 5)?;
                Ok(ApportionmentRule::Brazil2021 {
                    cand_min_quotient_bp: f[1].as_uint()?,
                    list_min_remainder_bp: f[2].as_uint()?,
                    cand_min_remainder_bp: f[3].as_uint()?,
                    final_phase_open: f[4].as_bool()?,
                })
            }
            _ => Err(schema("unknown apportionment rule")),
        }
    }
}

// ---------------------------------------------------------------------------
// Contests and options (§7.1).
// ---------------------------------------------------------------------------

/// One ballot option of a contest (`option`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BallotOption {
    /// Field 1: option index, 0-based within the contest.
    pub index: u64,
    /// Field 2: display name.
    pub name: String,
    /// Field 3: option kind.
    pub kind: OptionKind,
    /// Field 4: ballot number shown to voters, e.g. "4512".
    pub number: Option<String>,
    /// Field 5: party index (candidates and party options in proportional contests).
    pub party_index: Option<u64>,
    /// Field 6: tiebreak rank, lower wins ties (§22.5).
    pub tiebreak_rank: Option<u64>,
}

impl BallotOption {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("option")),
            (1, Value::Uint(self.index)),
            (2, Value::from(self.name.as_str())),
            (3, Value::from(self.kind.as_str())),
        ];
        if let Some(n) = &self.number {
            entries.push((4, Value::from(n.as_str())));
        }
        if let Some(p) = self.party_index {
            entries.push((5, Value::Uint(p)));
        }
        if let Some(t) = self.tiebreak_rank {
            entries.push((6, Value::Uint(t)));
        }
        record(entries)
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields_opt(v, "option", 4, &[4, 5, 6])?;
        Ok(BallotOption {
            index: f[1].ok_or_else(|| schema("option index"))?.as_uint()?,
            name: f[2]
                .ok_or_else(|| schema("option name"))?
                .as_text()?
                .to_owned(),
            kind: OptionKind::from_value(f[3].ok_or_else(|| schema("option kind"))?)?,
            number: opt_text(f[4])?,
            party_index: opt_uint(f[5])?,
            tiebreak_rank: opt_uint(f[6])?,
        })
    }
}

/// One contest of the election (`contest`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contest {
    /// Field 1: contest index, 0-based, equal to its position in the manifest.
    pub index: u64,
    /// Field 2: name, e.g. "Governador".
    pub name: String,
    /// Field 3: contest kind.
    pub kind: ContestKind,
    /// Field 4: counting method.
    pub method: Method,
    /// Field 5: L, the selection limit (1 for single and proportional).
    pub limit: u64,
    /// Field 6: options, at least one.
    pub options: Vec<BallotOption>,
    /// Field 7: apportionment rule, required iff `kind` is proportional.
    pub apportionment: Option<ApportionmentRule>,
    /// Field 8: seats, required iff `kind` is proportional.
    pub seats: Option<u64>,
    /// Field 9 (present = true): mixnet only, mix separately per region (§19.1).
    pub regional_mix: bool,
}

impl Contest {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("contest")),
            (1, Value::Uint(self.index)),
            (2, Value::from(self.name.as_str())),
            (3, Value::from(self.kind.as_str())),
            (4, Value::from(self.method.as_str())),
            (5, Value::Uint(self.limit)),
            (
                6,
                Value::Array(self.options.iter().map(BallotOption::to_value).collect()),
            ),
        ];
        if let Some(a) = &self.apportionment {
            entries.push((7, a.to_value()));
        }
        if let Some(s) = self.seats {
            entries.push((8, Value::Uint(s)));
        }
        if self.regional_mix {
            entries.push((9, Value::Bool(true)));
        }
        record(entries)
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields_opt(v, "contest", 7, &[7, 8, 9])?;
        let regional_mix = match f[9] {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(schema("contest field 9 must be true when present")),
        };
        Ok(Contest {
            index: f[1].ok_or_else(|| schema("contest index"))?.as_uint()?,
            name: f[2]
                .ok_or_else(|| schema("contest name"))?
                .as_text()?
                .to_owned(),
            kind: ContestKind::from_value(f[3].ok_or_else(|| schema("contest kind"))?)?,
            method: Method::from_value(f[4].ok_or_else(|| schema("contest method"))?)?,
            limit: f[5].ok_or_else(|| schema("contest limit"))?.as_uint()?,
            options: decode_list(
                f[6].ok_or_else(|| schema("contest options"))?,
                1,
                "contest options",
                BallotOption::from_value,
            )?,
            apportionment: f[7].map(ApportionmentRule::from_value).transpose()?,
            seats: opt_uint(f[8])?,
            regional_mix,
        })
    }
}

// ---------------------------------------------------------------------------
// Parties, federations, mirrors, link groups, policies (§7.1, §24.4).
// ---------------------------------------------------------------------------

/// A party (`party`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Party {
    /// Field 1: party index, equal to its position in the manifest.
    pub index: u64,
    /// Field 2: name.
    pub name: String,
    /// Field 3: ballot number, e.g. "12".
    pub number: String,
    /// Field 4: party key, which certifies observers (§16.3).
    pub key: Option<VerifyingKey>,
}

impl Party {
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("party")),
            (1, Value::Uint(self.index)),
            (2, Value::from(self.name.as_str())),
            (3, Value::from(self.number.as_str())),
        ];
        if let Some(k) = &self.key {
            entries.push((4, verifying_key_to_value(k)));
        }
        record(entries)
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields_opt(v, "party", 4, &[4])?;
        Ok(Party {
            index: f[1].ok_or_else(|| schema("party index"))?.as_uint()?,
            name: f[2]
                .ok_or_else(|| schema("party name"))?
                .as_text()?
                .to_owned(),
            number: f[3]
                .ok_or_else(|| schema("party number"))?
                .as_text()?
                .to_owned(),
            key: opt_key(f[4])?,
        })
    }
}

/// A federation of parties (`federation`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Federation {
    /// Field 1: federation index, equal to its position in the manifest.
    pub index: u64,
    /// Field 2: name.
    pub name: String,
    /// Field 3: party indices, at least one.
    pub parties: Vec<u64>,
}

impl Federation {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("federation")),
            (1, Value::Uint(self.index)),
            (2, Value::from(self.name.as_str())),
            (
                3,
                Value::Array(self.parties.iter().map(|p| Value::Uint(*p)).collect()),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "federation", 4)?;
        Ok(Federation {
            index: f[1].as_uint()?,
            name: f[2].as_text()?.to_owned(),
            parties: decode_list(f[3], 1, "federation parties", uint_item)?,
        })
    }
}

/// A mirror that checks and gossips tree heads (`mirror`, §7.1, §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirror {
    /// Field 1: operator organisation.
    pub operator: String,
    /// Field 2: bloc label.
    pub bloc: String,
    /// Field 3: URL.
    pub url: String,
    /// Field 4: mirror key, which signs the tree heads it has checked.
    pub key: VerifyingKey,
}

impl Mirror {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("mirror")),
            (1, Value::from(self.operator.as_str())),
            (2, Value::from(self.bloc.as_str())),
            (3, Value::from(self.url.as_str())),
            (4, verifying_key_to_value(&self.key)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "mirror", 5)?;
        Ok(Mirror {
            operator: f[1].as_text()?.to_owned(),
            bloc: f[2].as_text()?.to_owned(),
            url: f[3].as_text()?.to_owned(),
            key: verifying_key_from_value(f[4])?,
        })
    }
}

/// A link group: contests over the same candidates (`link_group`, §7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkGroup {
    /// Field 1: group index, equal to its position in the manifest.
    pub index: u64,
    /// Field 2: contest indices, ascending, at least two.
    pub contests: Vec<u64>,
}

impl LinkGroup {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("link_group")),
            (1, Value::Uint(self.index)),
            (
                2,
                Value::Array(self.contests.iter().map(|c| Value::Uint(*c)).collect()),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "link_group", 3)?;
        Ok(LinkGroup {
            index: f[1].as_uint()?,
            contests: decode_list(f[2], 2, "link group contests", uint_item)?,
        })
    }
}

/// Mixing policy (`mix_policy`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixPolicy {
    /// Field 1: minimum number of distinct trustees mixing each mix unit. Must be in k..=n.
    pub min_mixers: u64,
    /// Field 2: smaller regions are merged before mixing (§19.1). At least 1.
    pub min_region_rows: u64,
}

impl MixPolicy {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("mix_policy")),
            (1, Value::Uint(self.min_mixers)),
            (2, Value::Uint(self.min_region_rows)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "mix_policy", 3)?;
        Ok(MixPolicy {
            min_mixers: f[1].as_uint()?,
            min_region_rows: f[2].as_uint()?,
        })
    }
}

/// A release signer (`release_signer`, §24.4): `[ed25519pk, tstr, tstr]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseSigner {
    pub key: VerifyingKey,
    /// Organisation name.
    pub organisation: String,
    /// Bloc label (§2.4).
    pub bloc: String,
}

impl ReleaseSigner {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            verifying_key_to_value(&self.key),
            Value::from(self.organisation.as_str()),
            Value::from(self.bloc.as_str()),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let items = v.as_array()?;
        let [key, organisation, bloc] = items else {
            return Err(schema("release signer must be a 3-element array"));
        };
        Ok(ReleaseSigner {
            key: verifying_key_from_value(key)?,
            organisation: organisation.as_text()?.to_owned(),
            bloc: bloc.as_text()?.to_owned(),
        })
    }
}

/// Software policy (`software_policy`, §24.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwarePolicy {
    /// Field 1: release signers, at least one.
    pub signers: Vec<ReleaseSigner>,
    /// Field 2: k_r, signatures required on a release.
    pub k_r: u64,
    /// Field 3: release log key.
    pub release_log_key: VerifyingKey,
    /// Field 4: approved machine artifact hashes, at least one.
    pub approved_hashes: Vec<[u8; 32]>,
    /// Field 5: whether attestation is required.
    pub attestation_required: bool,
}

impl SoftwarePolicy {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("software_policy")),
            (
                1,
                Value::Array(self.signers.iter().map(ReleaseSigner::to_value).collect()),
            ),
            (2, Value::Uint(self.k_r)),
            (3, verifying_key_to_value(&self.release_log_key)),
            (
                4,
                Value::Array(
                    self.approved_hashes
                        .iter()
                        .map(|h| Value::from(*h))
                        .collect(),
                ),
            ),
            (5, Value::Bool(self.attestation_required)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "software_policy", 6)?;
        Ok(SoftwarePolicy {
            signers: decode_list(f[1], 1, "release signers", ReleaseSigner::from_value)?,
            k_r: f[2].as_uint()?,
            release_log_key: verifying_key_from_value(f[3])?,
            approved_hashes: decode_list(f[4], 1, "approved hashes", bytes32)?,
            attestation_required: f[5].as_bool()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Trustees (§7.1) are reused from the ceremony module as `TrusteeSet`.
// ---------------------------------------------------------------------------

/// The election manifest (`manifest`, §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Field 2: election identifier, unique, e.g. "BR-2026-SP-PILOT-01".
    pub election_id: String,
    /// Field 3: title.
    pub title: String,
    /// Field 4: contests, at least one.
    pub contests: Vec<Contest>,
    /// Field 5: parties, possibly empty.
    pub parties: Vec<Party>,
    /// Field 6: federations, possibly empty.
    pub federations: Vec<Federation>,
    /// Field 7: trustee set (n, k and trustee entries).
    pub trustees: TrusteeSet,
    /// Field 8: EA signing key.
    pub ea_key: VerifyingKey,
    /// Field 9: board key.
    pub board_key: VerifyingKey,
    /// Field 10: software policy (§24.4).
    pub software_policy: SoftwarePolicy,
    /// Field 11: mixing policy.
    pub mix_policy: MixPolicy,
    /// Field 12: link groups, possibly empty (§7.5).
    pub link_groups: Vec<LinkGroup>,
    /// Field 13: sections with fewer counted ballots are pooled (§18).
    pub min_section_ballots: u64,
    /// Field 14: the EA's own bloc label, e.g. "TSE" (§2.4).
    pub ea_bloc: String,
    /// Field 15: mirrors, at least two (§2.4).
    pub mirrors: Vec<Mirror>,
}

impl Manifest {
    /// Encodes the manifest as the CBOR map of §7.1.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("manifest")),
            (1, Value::Uint(VERSION)),
            (2, Value::from(self.election_id.as_str())),
            (3, Value::from(self.title.as_str())),
            (
                4,
                Value::Array(self.contests.iter().map(Contest::to_value).collect()),
            ),
            (
                5,
                Value::Array(self.parties.iter().map(Party::to_value).collect()),
            ),
            (
                6,
                Value::Array(self.federations.iter().map(Federation::to_value).collect()),
            ),
            (7, self.trustees.to_value()),
            (8, verifying_key_to_value(&self.ea_key)),
            (9, verifying_key_to_value(&self.board_key)),
            (10, self.software_policy.to_value()),
            (11, self.mix_policy.to_value()),
            (
                12,
                Value::Array(self.link_groups.iter().map(LinkGroup::to_value).collect()),
            ),
            (13, Value::Uint(self.min_section_ballots)),
            (14, Value::from(self.ea_bloc.as_str())),
            (
                15,
                Value::Array(self.mirrors.iter().map(Mirror::to_value).collect()),
            ),
        ])
    }

    /// Strict decode of a `manifest` record (SPEC.md §7.1). Checks types, tags,
    /// version and cardinalities. Well-formedness is checked by [`Manifest::validate`].
    pub fn from_value(v: &Value) -> Result<Manifest, Error> {
        let f = cbor::record_fields(v, "manifest", 16)?;
        expect_version(f[1])?;
        Ok(Manifest {
            election_id: f[2].as_text()?.to_owned(),
            title: f[3].as_text()?.to_owned(),
            contests: decode_list(f[4], 1, "contests", Contest::from_value)?,
            parties: decode_list(f[5], 0, "parties", Party::from_value)?,
            federations: decode_list(f[6], 0, "federations", Federation::from_value)?,
            trustees: TrusteeSet::from_value(f[7])?,
            ea_key: verifying_key_from_value(f[8])?,
            board_key: verifying_key_from_value(f[9])?,
            software_policy: SoftwarePolicy::from_value(f[10])?,
            mix_policy: MixPolicy::from_value(f[11])?,
            link_groups: decode_list(f[12], 0, "link groups", LinkGroup::from_value)?,
            min_section_ballots: f[13].as_uint()?,
            ea_bloc: f[14].as_text()?.to_owned(),
            mirrors: decode_list(f[15], 2, "mirrors", Mirror::from_value)?,
        })
    }

    /// `manifest_hash = Digest("eg/v1/manifest", manifest)` (SPEC.md §7.3).
    pub fn hash(&self) -> [u8; 32] {
        digest("eg/v1/manifest", &[self.to_value()])
    }

    /// The contest with index `index`, if any.
    pub fn contest(&self, index: u64) -> Option<&Contest> {
        self.contests.iter().find(|c| c.index == index)
    }

    /// Checks the well-formedness rules of SPEC.md §7.2 (rules 1 to 13), plus
    /// the structural constraints that the spec states without a number. The
    /// error names the first violated rule, e.g. `rule 11: ...`.
    pub fn validate(&self) -> Result<(), Error> {
        self.check_structure()?;
        self.check_parties_and_federations()?;
        for (i, c) in self.contests.iter().enumerate() {
            self.check_contest(i, c)?;
        }
        self.check_link_groups()?;
        self.check_mix_policy()?;
        if self.min_section_ballots < 1 {
            return Err(rule(10, "min_section_ballots must be at least 1"));
        }
        self.check_trustee_independence()?;
        self.check_signer_independence()?;
        let outside = self
            .mirrors
            .iter()
            .filter(|m| m.bloc != self.ea_bloc)
            .count();
        if outside < 2 {
            return Err(rule(
                13,
                format!(
                    "{outside} mirror(s) outside the EA's bloc {:?}, at least 2 required",
                    self.ea_bloc
                ),
            ));
        }
        Ok(())
    }

    /// Non-numbered structure: non-empty lists, positional indices of contests
    /// and options, and the trustee threshold bounds.
    fn check_structure(&self) -> Result<(), Error> {
        if self.contests.is_empty() {
            return Err(structure("manifest has no contests"));
        }
        if self.mirrors.len() < 2 {
            return Err(structure("manifest needs at least two mirrors"));
        }
        if self.software_policy.signers.is_empty() {
            return Err(structure("software policy has no release signers"));
        }
        if self.software_policy.approved_hashes.is_empty() {
            return Err(structure("software policy has no approved hashes"));
        }
        let n = self.trustees.n();
        let k = self.trustees.k;
        if !(2..=n).contains(&k) {
            return Err(structure(format!(
                "trustee threshold k = {k} must satisfy 2 <= k <= n = {n}"
            )));
        }
        for (i, t) in self.trustees.trustees.iter().enumerate() {
            if t.index != i as u64 + 1 {
                return Err(structure("trustee indices must be 1..n in order"));
            }
        }
        for (i, g) in self.link_groups.iter().enumerate() {
            if g.index != i as u64 {
                return Err(structure(format!(
                    "link group index {} at position {i}",
                    g.index
                )));
            }
            if g.contests.len() < 2 {
                return Err(structure(format!(
                    "link group {i} needs at least two contests"
                )));
            }
        }
        Ok(())
    }

    /// Party and federation indices equal their positions. Federations refer to
    /// existing parties, and each party is in at most one federation (rule 4).
    fn check_parties_and_federations(&self) -> Result<(), Error> {
        for (i, p) in self.parties.iter().enumerate() {
            if p.index != i as u64 {
                return Err(structure(format!(
                    "party index {} at position {i}",
                    p.index
                )));
            }
        }
        let mut in_federation = vec![false; self.parties.len()];
        for (i, f) in self.federations.iter().enumerate() {
            if f.index != i as u64 {
                return Err(structure(format!(
                    "federation index {} at position {i}",
                    f.index
                )));
            }
            if f.parties.is_empty() {
                return Err(structure(format!("federation {i} has no parties")));
            }
            for &p in &f.parties {
                let slot = in_federation
                    .get_mut(p as usize)
                    .ok_or_else(|| structure(format!("federation {i} names unknown party {p}")))?;
                if *slot {
                    return Err(rule(
                        4,
                        format!(
                            "party {p} belongs to more than one federation (or is listed twice)"
                        ),
                    ));
                }
                *slot = true;
            }
        }
        Ok(())
    }

    /// Rules 1, 2, 3, 5, 6 and 9 (local part), plus the apportionment and seats
    /// fields, which are present iff the contest is proportional.
    fn check_contest(&self, i: usize, c: &Contest) -> Result<(), Error> {
        if c.index != i as u64 {
            return Err(rule(
                1,
                format!("contest index {} at position {i}", c.index),
            ));
        }
        for (j, o) in c.options.iter().enumerate() {
            if o.index != j as u64 {
                return Err(rule(
                    1,
                    format!("contest {i}: option index {} at position {j}", o.index),
                ));
            }
        }
        if c.options.is_empty() {
            return Err(structure(format!("contest {i} has no options")));
        }

        let is_proportional = c.kind == ContestKind::Proportional;
        if is_proportional != c.apportionment.is_some() || is_proportional != c.seats.is_some() {
            return Err(structure(format!(
                "contest {i}: apportionment and seats must be present iff the contest is proportional"
            )));
        }

        check_option_kinds(i, c, self.parties.len())?;

        if c.kind != ContestKind::Multi && c.limit != 1 {
            return Err(rule(
                3,
                format!("contest {i} is {} but L = {}", c.kind.as_str(), c.limit),
            ));
        }

        let mut numbers = HashSet::new();
        for n in c.options.iter().filter_map(|o| o.number.as_deref()) {
            if !numbers.insert(n) {
                return Err(rule(
                    5,
                    format!("contest {i}: display number {n:?} is used twice"),
                ));
            }
        }

        if c.method == Method::Mixnet && !mixnet_size_ok(c.options.len() as u64) {
            return Err(rule(
                6,
                format!(
                    "contest {i}: mixnet needs options + 1 < 2^20, has {} options",
                    c.options.len()
                ),
            ));
        }

        if c.regional_mix && c.method != Method::Mixnet {
            return Err(rule(
                9,
                format!("contest {i}: regional mixing is only allowed on mixnet contests"),
            ));
        }
        Ok(())
    }

    /// Rule 7 (link groups) and rule 9 (equal regional mixing within a group).
    fn check_link_groups(&self) -> Result<(), Error> {
        let mut grouped = vec![false; self.contests.len()];
        for g in &self.link_groups {
            let gi = g.index;
            if !g.contests.windows(2).all(|w| w[0] < w[1]) {
                return Err(rule(
                    7,
                    format!("link group {gi}: contests must be ascending"),
                ));
            }
            let mut members = Vec::with_capacity(g.contests.len());
            for &ci in &g.contests {
                let c = self
                    .contests
                    .get(ci as usize)
                    .ok_or_else(|| rule(7, format!("link group {gi}: unknown contest {ci}")))?;
                if std::mem::replace(&mut grouped[ci as usize], true) {
                    return Err(rule(
                        7,
                        format!("contest {ci} is in more than one link group"),
                    ));
                }
                members.push(c);
            }
            let first = members[0];
            for c in &members {
                if !matches!(c.kind, ContestKind::Single | ContestKind::Multi) {
                    return Err(rule(
                        7,
                        format!(
                            "link group {gi}: contest {} is not single or multi",
                            c.index
                        ),
                    ));
                }
                if c.kind != first.kind {
                    return Err(rule(
                        7,
                        format!("link group {gi}: contests have different kinds"),
                    ));
                }
                if c.method != first.method {
                    return Err(rule(
                        7,
                        format!("link group {gi}: contests have different methods"),
                    ));
                }
                if c.options != first.options {
                    return Err(rule(
                        7,
                        format!(
                            "link group {gi}: contest {} has different options from contest {}",
                            c.index, first.index
                        ),
                    ));
                }
                if c.regional_mix != first.regional_mix {
                    return Err(rule(
                        9,
                        format!(
                            "link group {gi}: regional mixing differs between contests {} and {}",
                            first.index, c.index
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Rule 8: k ≤ min_mixers ≤ n, and min_region_rows ≥ 1.
    fn check_mix_policy(&self) -> Result<(), Error> {
        let k = self.trustees.k;
        let n = self.trustees.n();
        let mp = &self.mix_policy;
        if !(k..=n).contains(&mp.min_mixers) {
            return Err(rule(
                8,
                format!(
                    "min_mixers = {} must satisfy k = {k} <= min_mixers <= n = {n}",
                    mp.min_mixers
                ),
            ));
        }
        if mp.min_region_rows < 1 {
            return Err(rule(8, "min_region_rows must be at least 1"));
        }
        Ok(())
    }

    /// Rule 11: for every bloc, fewer than k trustees. Trustee signing and HPKE
    /// keys must also be distinct: one key holder listed twice would hold two
    /// shares under two labels, which defeats the bloc count.
    fn check_trustee_independence(&self) -> Result<(), Error> {
        let k = self.trustees.k;
        let mut sig_keys = HashSet::new();
        let mut hpke_keys = HashSet::new();
        for t in &self.trustees.trustees {
            if !sig_keys.insert(t.sig_key.to_bytes()) {
                return Err(rule(
                    11,
                    format!("trustee {} reuses a signing key", t.index),
                ));
            }
            if !hpke_keys.insert(cbor::encode(&t.hpke_key.to_value())) {
                return Err(rule(11, format!("trustee {} reuses an HPKE key", t.index)));
            }
        }
        let counts = bloc_counts(self.trustees.trustees.iter().map(|t| t.bloc.as_str()));
        for t in &self.trustees.trustees {
            let c = counts[t.bloc.as_str()];
            if c >= k {
                return Err(rule(
                    11,
                    format!("bloc {:?} holds {c} trustee shares, k = {k}", t.bloc),
                ));
            }
        }
        Ok(())
    }

    /// Rule 12: 1 ≤ k_r ≤ number of signers, distinct signer keys, and fewer
    /// than k_r signers per bloc.
    fn check_signer_independence(&self) -> Result<(), Error> {
        let sp = &self.software_policy;
        let n = sp.signers.len() as u64;
        if !(1..=n).contains(&sp.k_r) {
            return Err(rule(
                12,
                format!(
                    "k_r = {} must satisfy 1 <= k_r <= {n} release signers",
                    sp.k_r
                ),
            ));
        }
        let mut keys = HashSet::new();
        for s in &sp.signers {
            if !keys.insert(s.key.to_bytes()) {
                return Err(rule(12, "release signer keys must be distinct"));
            }
        }
        let counts = bloc_counts(sp.signers.iter().map(|s| s.bloc.as_str()));
        for s in &sp.signers {
            let c = counts[s.bloc.as_str()];
            if c >= sp.k_r {
                return Err(rule(
                    12,
                    format!(
                        "bloc {:?} holds {c} release signers, k_r = {}",
                        s.bloc, sp.k_r
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Counts of each bloc label.
fn bloc_counts<'a>(blocs: impl Iterator<Item = &'a str>) -> HashMap<&'a str, u64> {
    let mut counts = HashMap::new();
    for b in blocs {
        *counts.entry(b).or_insert(0) += 1;
    }
    counts
}

/// Rule 6: a mixnet contest with `options` options has options + 1 < 2^20.
pub(crate) fn mixnet_size_ok(options: u64) -> bool {
    options + 1 < MIXNET_OPTION_BOUND
}

/// Rule 2 (option kinds per contest kind), including the party_index rules of
/// proportional contests and the "one party option per party" rule.
fn check_option_kinds(i: usize, c: &Contest, n_parties: usize) -> Result<(), Error> {
    let count = |kind: OptionKind| c.options.iter().filter(|o| o.kind == kind).count();
    let candidates = count(OptionKind::Candidate);
    let parties = count(OptionKind::Party);
    let blanks = count(OptionKind::Blank);
    let nulls = count(OptionKind::Null);
    match c.kind {
        ContestKind::Single => {
            if candidates == 0 {
                return Err(rule(
                    2,
                    format!("contest {i}: single contest needs a candidate"),
                ));
            }
            if blanks > 1 || nulls > 1 {
                return Err(rule(
                    2,
                    format!("contest {i}: single contest allows at most one blank and one null"),
                ));
            }
            if parties > 0 {
                return Err(rule(
                    2,
                    format!("contest {i}: single contest has a party option"),
                ));
            }
        }
        ContestKind::Multi => {
            if candidates == 0 {
                return Err(rule(
                    2,
                    format!("contest {i}: multi contest needs a candidate"),
                ));
            }
            if nulls > 1 {
                return Err(rule(
                    2,
                    format!("contest {i}: multi contest allows at most one null"),
                ));
            }
            if parties > 0 || blanks > 0 {
                return Err(rule(
                    2,
                    format!("contest {i}: multi contest has a party or blank option"),
                ));
            }
            if !(1..=candidates as u64).contains(&c.limit) {
                return Err(rule(
                    2,
                    format!(
                        "contest {i}: multi L = {} must be between 1 and {candidates}",
                        c.limit
                    ),
                ));
            }
        }
        ContestKind::Proportional => {
            if blanks > 1 || nulls > 1 {
                return Err(rule(
                    2,
                    format!("contest {i}: at most one blank and one null option"),
                ));
            }
            let mut party_options = HashSet::new();
            for o in &c.options {
                if !matches!(o.kind, OptionKind::Candidate | OptionKind::Party) {
                    continue;
                }
                let p = o.party_index.ok_or_else(|| {
                    rule(
                        2,
                        format!("contest {i}: option {} has no party_index", o.index),
                    )
                })?;
                if p >= n_parties as u64 {
                    return Err(rule(
                        2,
                        format!(
                            "contest {i}: option {} refers to unknown party {p}",
                            o.index
                        ),
                    ));
                }
                if o.kind == OptionKind::Party && !party_options.insert(p) {
                    return Err(rule(
                        2,
                        format!("contest {i}: party {p} has more than one party option"),
                    ));
                }
            }
            // §22.5: every candidate of a proportional contest has a distinct tiebreak_rank.
            let mut ranks = HashSet::new();
            for o in c.options.iter().filter(|o| o.kind == OptionKind::Candidate) {
                let r = o.tiebreak_rank.ok_or_else(|| {
                    structure(format!(
                        "proportional contest {i}: candidate {} has no tiebreak_rank",
                        o.index
                    ))
                })?;
                if !ranks.insert(r) {
                    return Err(structure(format!(
                        "proportional contest {i}: tiebreak_rank {r} is used twice"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Signs a manifest with the EA key (SPEC.md §7.3):
/// `{ 0: "signed_manifest", 1: manifest, 2: Sign(ea_sk, "eg/v1/sig/manifest", manifest) }`.
pub fn sign_manifest(m: &Manifest, ea_sk: &SigningKey) -> Value {
    let body = m.to_value();
    let sig = sign(ea_sk, SIG_MANIFEST, &body);
    record(vec![
        (0, Value::from("signed_manifest")),
        (1, body),
        (2, signature_to_value(&sig)),
    ])
}

/// Decodes a `signed_manifest`, verifies the EA signature with the manifest's
/// own `ea_key`, and validates the manifest (SPEC.md §7.2, §7.3).
pub fn open_signed_manifest(v: &Value) -> Result<Manifest, Error> {
    let f = cbor::record_fields(v, "signed_manifest", 3)?;
    let manifest = Manifest::from_value(f[1])?;
    let sig = signature_from_value(f[2])?;
    if !verify(&manifest.ea_key, SIG_MANIFEST, f[1], &sig) {
        return Err(Error::InvalidSignature);
    }
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{sample_manifest, Keys};
    use crate::sign::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn sample() -> Manifest {
        sample_manifest(1).0
    }

    fn option(index: usize, name: &str, kind: OptionKind, number: Option<&str>) -> BallotOption {
        BallotOption {
            index: index as u64,
            name: name.to_owned(),
            kind,
            number: number.map(str::to_owned),
            party_index: None,
            tiebreak_rank: None,
        }
    }

    /// Replaces (or adds) the entry with uint key `key` in a record map.
    fn put(v: &mut Value, key: u64, val: Value) {
        let Value::Map(entries) = v else {
            panic!("not a map");
        };
        entries.retain(|(k, _)| *k != Value::Uint(key));
        entries.push((Value::Uint(key), val));
    }

    /// Asserts that `m` violates rule `n` and that the error names it first.
    fn assert_rule(m: &Manifest, n: u32) {
        match m.validate() {
            Err(Error::Manifest(msg)) => {
                assert!(
                    msg.starts_with(&format!("rule {n}:")),
                    "expected rule {n}, got: {msg}"
                )
            }
            other => panic!("expected rule {n} violation, got {other:?}"),
        }
    }

    fn keys_for(seed: u64) -> Keys {
        sample_manifest(seed).1
    }

    #[test]
    fn sample_validates() {
        sample().validate().unwrap();
    }

    #[test]
    fn brazil_rule_sample_validates() {
        let mut m = sample();
        m.contests[2].apportionment = Some(ApportionmentRule::Brazil2021 {
            cand_min_quotient_bp: 1000,
            list_min_remainder_bp: 8000,
            cand_min_remainder_bp: 2000,
            final_phase_open: true,
        });
        m.validate().unwrap();
        let back = Manifest::from_value(&m.to_value()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let v = m.to_value();
        assert_eq!(Manifest::from_value(&v).unwrap(), m);
        // Canonical bytes survive decode and re-encode.
        let bytes = cbor::encode(&v);
        assert_eq!(cbor::encode(&cbor::decode(&bytes).unwrap()), bytes);
        assert_eq!(
            Manifest::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
            m
        );
    }

    #[test]
    fn round_trip_with_optional_fields_present() {
        let mut m = sample();
        m.parties[0].key =
            Some(SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(9)).verifying_key());
        m.validate().unwrap();
        assert_eq!(Manifest::from_value(&m.to_value()).unwrap(), m);
    }

    #[test]
    fn signed_manifest_opens() {
        let (m, keys) = sample_manifest(1);
        let signed = sign_manifest(&m, &keys.ea);
        assert_eq!(open_signed_manifest(&signed).unwrap(), m);
    }

    #[test]
    fn signed_manifest_with_wrong_key_fails() {
        let (m, _) = sample_manifest(1);
        let other = SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(77));
        let signed = sign_manifest(&m, &other);
        assert_eq!(open_signed_manifest(&signed), Err(Error::InvalidSignature));
    }

    #[test]
    fn tampered_signed_manifest_fails() {
        let (m, keys) = sample_manifest(1);
        let mut signed = sign_manifest(&m, &keys.ea);
        let mut tampered = m.clone();
        tampered.title = "Outro título".to_owned();
        put(&mut signed, 1, tampered.to_value());
        assert_eq!(open_signed_manifest(&signed), Err(Error::InvalidSignature));
    }

    #[test]
    fn signed_manifest_with_invalid_rule_is_rejected_after_signature() {
        // A correctly signed but ill-formed manifest is rejected by validate().
        let (mut m, keys) = sample_manifest(1);
        m.min_section_ballots = 0;
        let signed = sign_manifest(&m, &keys.ea);
        assert!(matches!(
            open_signed_manifest(&signed),
            Err(Error::Manifest(msg)) if msg.starts_with("rule 10:")
        ));
    }

    #[test]
    fn hash_is_stable_and_follows_content() {
        let m = sample();
        assert_eq!(m.hash(), sample().hash());
        assert_eq!(m.hash(), sample_manifest(1).0.hash());
        assert_ne!(m.hash(), sample_manifest(2).0.hash());
        let mut changed = m.clone();
        changed.title.push('!');
        assert_ne!(m.hash(), changed.hash());
    }

    #[test]
    fn contest_lookup() {
        let m = sample();
        assert_eq!(m.contest(3).unwrap().name, "Prefeito");
        assert!(m.contest(6).is_none());
    }

    #[test]
    fn strict_decode_rejects_wrong_version() {
        let mut v = sample().to_value();
        put(&mut v, 1, Value::Uint(2));
        assert!(matches!(
            Manifest::from_value(&v),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
    }

    #[test]
    fn strict_decode_rejects_unknown_key() {
        let mut v = sample().to_value();
        put(&mut v, 16, Value::Uint(0));
        assert!(matches!(
            Manifest::from_value(&v),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
    }

    #[test]
    fn strict_decode_rejects_bad_tag_and_missing_field() {
        let mut v = sample().to_value();
        put(&mut v, 0, Value::from("registry"));
        assert!(Manifest::from_value(&v).is_err());

        let mut v = sample().to_value();
        if let Value::Map(entries) = &mut v {
            entries.retain(|(k, _)| *k != Value::Uint(14));
        }
        assert!(Manifest::from_value(&v).is_err());
    }

    #[test]
    fn strict_decode_rejects_regional_mix_false() {
        // Field 9 is the constant true or absent (§7.1).
        let mut c = sample().contests[3].to_value();
        put(&mut c, 9, Value::Bool(false));
        assert!(Contest::from_value(&c).is_err());
    }

    #[test]
    fn strict_decode_rejects_unknown_kind_and_option_kind() {
        let mut c = sample().contests[0].to_value();
        put(&mut c, 3, Value::from("ranked"));
        assert!(Contest::from_value(&c).is_err());

        let mut o = sample().contests[0].options[0].to_value();
        put(&mut o, 3, Value::from("write-in"));
        assert!(BallotOption::from_value(&o).is_err());
    }

    #[test]
    fn strict_decode_rejects_bool_in_wrong_place() {
        let mut m = sample().to_value();
        put(&mut m, 13, Value::Bool(true));
        assert!(Manifest::from_value(&m).is_err());
    }

    #[test]
    fn strict_decode_rejects_short_release_signer() {
        let v = Value::Array(vec![Value::Bytes(vec![0; 32]), Value::from("org")]);
        assert!(ReleaseSigner::from_value(&v).is_err());
    }

    #[test]
    fn mixnet_bound_helper() {
        // Rule 6: options + 1 must be below 2^20.
        assert!(mixnet_size_ok((1 << 20) - 2));
        assert!(!mixnet_size_ok((1 << 20) - 1));
    }

    #[test]
    fn rule_1_positional_indices() {
        let mut m = sample();
        m.contests[1].index = 7;
        assert_rule(&m, 1);

        let mut m = sample();
        m.contests[0].options[1].index = 5;
        assert_rule(&m, 1);
    }

    #[test]
    fn rule_2_option_kinds() {
        // Single: a second blank option.
        let mut m = sample();
        let extra = option(5, "Branco 2", OptionKind::Blank, None);
        m.contests[0].options.push(extra);
        assert_rule(&m, 2);

        // Single with no candidate.
        let mut m = sample();
        m.contests[0]
            .options
            .retain(|o| o.kind != OptionKind::Candidate);
        for (i, o) in m.contests[0].options.iter_mut().enumerate() {
            o.index = i as u64;
        }
        assert_rule(&m, 2);

        // Multi with a blank option.
        let mut m = sample();
        m.contests[1]
            .options
            .insert(4, option(4, "Branco", OptionKind::Blank, None));
        m.contests[1].options[5].index = 5;
        assert_rule(&m, 2);

        // Multi with L above the number of candidates.
        let mut m = sample();
        m.contests[1].limit = 5;
        assert_rule(&m, 2);

        // Proportional: candidate party_index refers to a missing party.
        let mut m = sample();
        m.contests[2].options[0].party_index = Some(9);
        assert_rule(&m, 2);

        // Proportional: a candidate without party_index.
        let mut m = sample();
        m.contests[2].options[0].party_index = None;
        assert_rule(&m, 2);

        // Proportional: two party options for the same party.
        let mut m = sample();
        m.contests[2].options[5].party_index = Some(0);
        assert_rule(&m, 2);
    }

    #[test]
    fn rule_3_single_and_proportional_have_l_one() {
        let mut m = sample();
        m.contests[0].limit = 2;
        assert_rule(&m, 3);

        let mut m = sample();
        m.contests[2].limit = 2;
        assert_rule(&m, 3);
    }

    #[test]
    fn rule_4_one_federation_per_party() {
        let mut m = sample();
        m.federations = vec![
            Federation {
                index: 0,
                name: "Fed A".to_owned(),
                parties: vec![0],
            },
            Federation {
                index: 1,
                name: "Fed B".to_owned(),
                parties: vec![0, 1],
            },
        ];
        assert_rule(&m, 4);

        // A federation naming a missing party is a structure error, not rule 4.
        let mut m = sample();
        m.federations = vec![Federation {
            index: 0,
            name: "Fed".to_owned(),
            parties: vec![5],
        }];
        assert!(matches!(m.validate(), Err(Error::Manifest(msg)) if msg.starts_with("structure:")));
    }

    #[test]
    fn rule_5_unique_display_numbers() {
        let mut m = sample();
        m.contests[1].options[1].number = m.contests[1].options[0].number.clone();
        assert_rule(&m, 5);
    }

    #[test]
    fn rule_6_mixnet_size_is_checked_by_helper() {
        // A real contest with 2^20 options would be too large for a unit test;
        // the bound itself is tested through mixnet_size_ok.
        assert!(!mixnet_size_ok(1 << 20));
        assert!(mixnet_size_ok(1000));
    }

    #[test]
    fn rule_7_link_groups() {
        // Contest 5 has a different option list from contest 4.
        let mut m = sample();
        m.contests[5].options[1].number = Some("999".to_owned());
        assert_rule(&m, 7);

        // A contest in two link groups.
        let mut m = sample();
        m.link_groups.push(LinkGroup {
            index: 1,
            contests: vec![0, 4],
        });
        assert_rule(&m, 7);

        // Proportional contests cannot be linked.
        let mut m = sample();
        m.link_groups.push(LinkGroup {
            index: 1,
            contests: vec![2, 3],
        });
        assert_rule(&m, 7);

        // Link groups must have the same method.
        let mut m = sample();
        m.contests[5].method = Method::Mixnet;
        assert_rule(&m, 7);
    }

    #[test]
    fn rule_8_mix_policy() {
        let mut m = sample();
        m.mix_policy.min_mixers = 1; // below k = 2
        assert_rule(&m, 8);

        let mut m = sample();
        m.mix_policy.min_mixers = 4; // above n = 3
        assert_rule(&m, 8);

        let mut m = sample();
        m.mix_policy.min_region_rows = 0;
        assert_rule(&m, 8);
    }

    #[test]
    fn rule_9_regional_mix() {
        // Regional mixing on a homomorphic contest.
        let mut m = sample();
        m.contests[0].regional_mix = true;
        assert_rule(&m, 9);

        // Link group members must agree (both mixnet, so the local check passes).
        let mut m = sample();
        m.contests[4].method = Method::Mixnet;
        m.contests[5].method = Method::Mixnet;
        m.contests[4].regional_mix = true;
        assert_rule(&m, 9);
    }

    #[test]
    fn rule_10_min_section_ballots() {
        let mut m = sample();
        m.min_section_ballots = 0;
        assert_rule(&m, 10);
    }

    #[test]
    fn rule_11_trustee_independence() {
        let mut m = sample();
        m.trustees.trustees[1].bloc = "TSE".to_owned();
        assert_rule(&m, 11);
        let msg = m.validate().unwrap_err().to_string();
        assert!(
            msg.contains("bloc \"TSE\" holds 2 trustee shares, k = 2"),
            "{msg}"
        );
    }

    #[test]
    fn rule_12_signer_independence() {
        let mut m = sample();
        m.software_policy.signers[1].bloc = "TSE".to_owned();
        assert_rule(&m, 12);

        let mut m = sample();
        m.software_policy.k_r = 1;
        assert_rule(&m, 12);

        let mut m = sample();
        m.software_policy.k_r = 4; // more than the 3 signers
        assert_rule(&m, 12);

        let mut m = sample();
        m.software_policy.signers[1].key = m.software_policy.signers[0].key;
        assert_rule(&m, 12);
    }

    #[test]
    fn rule_13_mirror_independence() {
        let mut m = sample();
        m.mirrors[1].bloc = "TSE".to_owned();
        assert_rule(&m, 13);

        let mut m = sample();
        m.mirrors[0].bloc = m.ea_bloc.clone();
        m.mirrors[1].bloc = m.ea_bloc.clone();
        assert_rule(&m, 13);
    }

    #[test]
    fn sample_keys_are_used_for_ea_and_board() {
        let (m, keys) = sample_manifest(3);
        assert_eq!(m.ea_key, keys.ea.verifying_key());
        assert_eq!(m.board_key, keys.board.verifying_key());
        assert_eq!(keys_for(3).ea.verifying_key(), m.ea_key);
    }
}
