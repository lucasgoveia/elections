//! Data transfer objects for the JavaScript side, and the conversions from
//! eg-core values. Every DTO is camelCase on the wire. Byte strings cross the
//! boundary as lower-case hex, and CBOR values as CBOR hex or pretty JSON.

use std::fmt::Write as _;

use eg_core::ballot::ContestPlain;
use eg_core::board::Sth;
use eg_core::cbor::{self, Value};
use eg_core::error::Error;
use eg_core::manifest::{ContestKind, Manifest, Method, OptionKind};
use eg_core::registry::Registry;
use eg_core::sim::{
    Attacks, CeremonyReport, EntrySummary, LookupView, Phase, PreBuView, ResultView, Scenario,
    SlipView, SpoilCheck, SpoilView, ZeresimaView,
};
use eg_verify::{Finding, Independence, Party, Report};
use serde::{Deserialize, Serialize};

/// Byte strings longer than this many bytes are shortened in `entry_json`.
/// A 32-byte digest is always printed in full.
const SHORT_BYTES_OVER: usize = 16;

// -- hex and CBOR helpers ----------------------------------------------------

/// Lower-case hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes hex, reporting a driver error for malformed input.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(s).map_err(|e| Error::Board(format!("invalid hex: {e}")))
}

/// Decodes a 32-byte hex digest.
pub fn parse_digest(s: &str) -> Result<[u8; 32], Error> {
    parse_hex(s)?
        .try_into()
        .map_err(|v: Vec<u8>| Error::Board(format!("expected 32 bytes, got {}", v.len())))
}

/// The phase as a string for the JavaScript side.
pub fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Setup => "setup",
        Phase::CeremonyDone => "ceremony-done",
        Phase::PollsOpen => "polls-open",
        Phase::PollsClosed => "polls-closed",
        Phase::Tallied => "tallied",
    }
}

fn contest_kind_name(k: ContestKind) -> &'static str {
    match k {
        ContestKind::Single => "single",
        ContestKind::Multi => "multi",
        ContestKind::Proportional => "proportional",
    }
}

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Homomorphic => "homomorphic",
        Method::Mixnet => "mixnet",
    }
}

fn option_kind_name(k: OptionKind) -> &'static str {
    match k {
        OptionKind::Candidate => "candidate",
        OptionKind::Party => "party",
        OptionKind::Blank => "blank",
        OptionKind::Null => "null",
    }
}

/// Renders a CBOR value as pretty JSON with two-space indentation. Map keys
/// become strings. With `shorten`, a byte string longer than 16 bytes is cut to
/// its first 16 hex characters, followed by its length, unless it is a 32-byte
/// digest.
pub fn cbor_json(v: &Value, shorten: bool) -> String {
    let mut out = String::new();
    write_json(v, 0, shorten, &mut out);
    out
}

fn write_json(v: &Value, depth: usize, shorten: bool, out: &mut String) {
    match v {
        Value::Uint(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Text(s) => write_json_string(s, out),
        Value::Bytes(b) => write_json_string(&bytes_text(b, shorten), out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                push_indent(out, depth + 1);
                write_json(item, depth + 1, shorten, out);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push(']');
        }
        Value::Map(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                push_indent(out, depth + 1);
                write_json_string(&key_text(key, shorten), out);
                out.push_str(": ");
                write_json(value, depth + 1, shorten, out);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push('}');
        }
    }
}

fn key_text(key: &Value, shorten: bool) -> String {
    match key {
        Value::Text(s) => s.clone(),
        Value::Uint(n) => n.to_string(),
        Value::Bytes(b) => bytes_text(b, shorten),
        Value::Bool(b) => b.to_string(),
        Value::Array(_) | Value::Map(_) => "?".to_owned(),
    }
}

fn bytes_text(b: &[u8], shorten: bool) -> String {
    let h = hex::encode(b);
    if !shorten || b.len() <= SHORT_BYTES_OVER || b.len() == 32 {
        h
    } else {
        format!("{}…({} bytes)", &h[..SHORT_BYTES_OVER], b.len())
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// -- scenarios ---------------------------------------------------------------

/// One selectable election. Wire shape: `{ id, name }`, where `id` is
/// `Scenario::name()` ("pilot" or "star-wars") and `name` is for display.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioDto {
    pub id: String,
    pub name: String,
}

/// The selectable scenarios, in display order.
pub fn scenarios_dto() -> Vec<ScenarioDto> {
    let names = [
        (
            Scenario::StarWars,
            "Star Wars: Galactic Republic General Election",
        ),
        (
            Scenario::Pilot,
            "Brazilian pilot (governor, senate, deputies, mayor)",
        ),
    ];
    names
        .iter()
        .map(|(sc, name)| ScenarioDto {
            id: sc.name().to_owned(),
            name: (*name).to_owned(),
        })
        .collect()
}

// -- election ----------------------------------------------------------------

/// A machine and the contests it offers. Wire shape: `{ id, contests }`, where
/// `contests` lists contest indices in ascending order.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MachineOfferDto {
    pub id: String,
    pub contests: Vec<u64>,
}

/// The election as the UI reads it.
///
/// - `scenario`: the scenario identifier, "pilot" or "star-wars".
/// - `sections[].machines`: machine ids (kept for compatibility).
/// - `sections[].machineContests`: `[{ id, contests }]`, the same machines with
///   their offers.
/// - `reserveMachines`: reserve machine ids (kept for compatibility). Empty in
///   the Star Wars scenario.
/// - `reserveMachineContests`: `[{ id, contests }]` for the reserve machines.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ElectionDto {
    pub id: String,
    pub title: String,
    pub scenario: String,
    pub contests: Vec<ContestDto>,
    pub parties: Vec<PartyDto>,
    pub trustees: Vec<TrusteeDto>,
    pub sections: Vec<SectionDto>,
    pub reserve_machines: Vec<String>,
    pub reserve_machine_contests: Vec<MachineOfferDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContestDto {
    pub index: u64,
    pub name: String,
    pub kind: &'static str,
    pub method: &'static str,
    pub limit: u64,
    pub options: Vec<OptionDto>,
    pub seats: Option<u64>,
    pub link_group: Option<u64>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OptionDto {
    pub index: u64,
    pub name: String,
    pub kind: &'static str,
    pub number: Option<String>,
    /// The name of the party of the option, if any.
    pub party: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PartyDto {
    pub index: u64,
    pub name: String,
    pub number: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrusteeDto {
    pub index: u64,
    pub name: String,
    pub bloc: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SectionDto {
    pub id: String,
    pub region: String,
    pub eligible: u64,
    pub machines: Vec<String>,
    /// The machines of the section with their offered contests.
    pub machine_contests: Vec<MachineOfferDto>,
    pub poll_workers: u64,
}

impl ElectionDto {
    /// The election of `manifest` and `registry`, played as `scenario`.
    pub fn new(manifest: &Manifest, registry: &Registry, scenario: Scenario) -> ElectionDto {
        let offer = |m: &eg_core::registry::MachineEntry| MachineOfferDto {
            id: m.machine_id.clone(),
            contests: m.contests.clone(),
        };
        let contests = manifest
            .contests
            .iter()
            .map(|c| ContestDto {
                index: c.index,
                name: c.name.clone(),
                kind: contest_kind_name(c.kind),
                method: method_name(c.method),
                limit: c.limit,
                options: c
                    .options
                    .iter()
                    .map(|o| OptionDto {
                        index: o.index,
                        name: o.name.clone(),
                        kind: option_kind_name(o.kind),
                        number: o.number.clone(),
                        party: o
                            .party_index
                            .and_then(|p| manifest.parties.iter().find(|x| x.index == p))
                            .map(|x| x.name.clone()),
                    })
                    .collect(),
                seats: c.seats,
                link_group: manifest
                    .link_groups
                    .iter()
                    .find(|g| g.contests.contains(&c.index))
                    .map(|g| g.index),
            })
            .collect();
        ElectionDto {
            id: manifest.election_id.clone(),
            title: manifest.title.clone(),
            scenario: scenario.name().to_owned(),
            contests,
            parties: manifest
                .parties
                .iter()
                .map(|p| PartyDto {
                    index: p.index,
                    name: p.name.clone(),
                    number: p.number.clone(),
                })
                .collect(),
            trustees: manifest
                .trustees
                .trustees
                .iter()
                .map(|t| TrusteeDto {
                    index: t.index,
                    name: t.name.clone(),
                    bloc: t.bloc.clone(),
                })
                .collect(),
            sections: registry
                .sections
                .iter()
                .map(|s| SectionDto {
                    id: s.section_id.clone(),
                    region: s.region.clone(),
                    eligible: s.eligible,
                    machines: registry
                        .machines
                        .iter()
                        .filter(|m| m.section_id == s.section_id)
                        .map(|m| m.machine_id.clone())
                        .collect(),
                    machine_contests: registry
                        .machines
                        .iter()
                        .filter(|m| m.section_id == s.section_id)
                        .map(offer)
                        .collect(),
                    poll_workers: s.poll_worker_keys.len() as u64,
                })
                .collect(),
            reserve_machines: registry
                .machines
                .iter()
                .filter(|m| m.section_id.is_empty())
                .map(|m| m.machine_id.clone())
                .collect(),
            reserve_machine_contests: registry
                .machines
                .iter()
                .filter(|m| m.section_id.is_empty())
                .map(offer)
                .collect(),
        }
    }
}

// -- ballots -----------------------------------------------------------------

/// A contest choice: `selected` holds option indices of the contest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChoiceDto {
    pub contest: u64,
    pub selected: Vec<u64>,
}

impl From<&ContestPlain> for ChoiceDto {
    fn from(c: &ContestPlain) -> Self {
        ChoiceDto {
            contest: c.contest,
            selected: c.selected.clone(),
        }
    }
}

impl From<ChoiceDto> for ContestPlain {
    fn from(c: ChoiceDto) -> Self {
        ContestPlain {
            contest: c.contest,
            selected: c.selected,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ZeresimaDto {
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    pub measurement_hex: String,
    pub head0_hex: String,
    pub contests: Vec<ZeresimaContestDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ZeresimaContestDto {
    pub index: u64,
    pub name: String,
    pub options: Vec<String>,
}

impl From<&ZeresimaView> for ZeresimaDto {
    fn from(v: &ZeresimaView) -> Self {
        ZeresimaDto {
            machine_id: v.machine_id.clone(),
            section_id: v.section_id.clone(),
            session_id: v.session_id.clone(),
            measurement_hex: v.measurement_hex.clone(),
            head0_hex: v.head0_hex.clone(),
            contests: v
                .contests
                .iter()
                .map(|(index, name, options)| ZeresimaContestDto {
                    index: *index,
                    name: name.clone(),
                    options: options.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EncryptDto {
    pub code: String,
    pub short_code: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SlipDto {
    pub short_code: String,
    pub code: String,
    pub machine_id: String,
    pub slip_hex: String,
    pub slip_json: String,
}

impl From<&SlipView> for SlipDto {
    fn from(v: &SlipView) -> Self {
        SlipDto {
            short_code: v.short_code.clone(),
            code: v.code_hex.clone(),
            machine_id: v.machine_id.clone(),
            slip_hex: to_hex(&cbor::encode(&v.slip)),
            slip_json: cbor_json(&v.slip, false),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpoilDto {
    pub short_code: String,
    pub receipt_hex: String,
    pub receipt_json: String,
    pub claimed: Vec<ChoiceDto>,
}

impl From<&SpoilView> for SpoilDto {
    fn from(v: &SpoilView) -> Self {
        SpoilDto {
            short_code: v.short_code.clone(),
            receipt_hex: to_hex(&cbor::encode(&v.receipt)),
            receipt_json: cbor_json(&v.receipt, false),
            claimed: v.claimed.iter().map(ChoiceDto::from).collect(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PreBuDto {
    pub machine_id: String,
    pub section_id: String,
    pub cast: u64,
    pub spoiled: u64,
    pub abandoned: u64,
    pub fingerprint: String,
    pub chain_head_hex: String,
}

impl From<&PreBuView> for PreBuDto {
    fn from(v: &PreBuView) -> Self {
        PreBuDto {
            machine_id: v.machine_id.clone(),
            section_id: v.section_id.clone(),
            cast: v.cast,
            spoiled: v.spoiled,
            abandoned: v.abandoned,
            fingerprint: v.fingerprint.clone(),
            chain_head_hex: v.chain_head_hex.clone(),
        }
    }
}

// -- ceremony, result, STHs --------------------------------------------------

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CeremonyDto {
    pub trustees: Vec<TrusteeDto>,
    pub k: u64,
    pub n: u64,
    pub complaints: Vec<String>,
    pub context_hash_hex: String,
    pub joint_key_hex: String,
}

impl From<&CeremonyReport> for CeremonyDto {
    fn from(r: &CeremonyReport) -> Self {
        CeremonyDto {
            trustees: r
                .trustees
                .iter()
                .map(|(index, name, bloc)| TrusteeDto {
                    index: *index,
                    name: name.clone(),
                    bloc: bloc.clone(),
                })
                .collect(),
            k: r.k,
            n: r.n,
            complaints: r.complaints.clone(),
            context_hash_hex: r.context_hash_hex.clone(),
            joint_key_hex: r.joint_key_hex.clone(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResultDto {
    pub contests: Vec<ResultContestDto>,
    pub sections: Vec<SectionResultDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResultContestDto {
    pub index: u64,
    pub name: String,
    pub options: Vec<VotesDto>,
    pub counted: u64,
    pub invalid: u64,
    pub excluded: u64,
    /// `(candidate, party)` of each elected candidate, for proportional contests.
    pub seats: Option<Vec<SeatDto>>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VotesDto {
    pub name: String,
    pub votes: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SeatDto {
    pub candidate: String,
    pub party: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SectionResultDto {
    pub id: String,
    pub matches: bool,
}

impl From<&ResultView> for ResultDto {
    fn from(r: &ResultView) -> Self {
        ResultDto {
            contests: r
                .contests
                .iter()
                .map(|c| ResultContestDto {
                    index: c.index,
                    name: c.name.clone(),
                    options: c
                        .options
                        .iter()
                        .map(|(name, votes)| VotesDto {
                            name: name.clone(),
                            votes: *votes,
                        })
                        .collect(),
                    counted: c.counted,
                    invalid: c.invalid,
                    excluded: c.excluded,
                    seats: c.seats.as_ref().map(|seats| {
                        seats
                            .iter()
                            .map(|(candidate, party)| SeatDto {
                                candidate: candidate.clone(),
                                party: party.clone(),
                            })
                            .collect()
                    }),
                })
                .collect(),
            sections: r
                .sections
                .iter()
                .map(|(id, matches)| SectionResultDto {
                    id: id.clone(),
                    matches: *matches,
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SthDto {
    pub size: u64,
    pub root_hex: String,
    pub timestamp: u64,
    /// The signed `sth` record, as CBOR hex.
    pub hex: String,
}

impl SthDto {
    /// Checks the board signature of `signed` and summarises it.
    pub fn from_signed(
        signed: &Value,
        board_key: &eg_core::sign::VerifyingKey,
    ) -> Result<SthDto, Error> {
        let sth = Sth::from_signed(signed, board_key)?;
        Ok(SthDto {
            size: sth.size,
            root_hex: to_hex(&sth.root),
            timestamp: sth.timestamp,
            hex: to_hex(&cbor::encode(signed)),
        })
    }
}

// -- lookup, spoil check, board ----------------------------------------------

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LookupDto {
    pub found: bool,
    pub entry_index: Option<u64>,
    pub status: Option<String>,
    pub machine_id: Option<String>,
    pub inclusion_proof_verifies: bool,
    pub contests_counted: Vec<CountedDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CountedDto {
    pub contest: u64,
    /// `None` until the tally has run.
    pub counted: Option<bool>,
}

impl From<&LookupView> for LookupDto {
    fn from(v: &LookupView) -> Self {
        LookupDto {
            found: v.found,
            entry_index: v.entry_index,
            status: v.status.clone(),
            machine_id: v.machine_id.clone(),
            inclusion_proof_verifies: v.inclusion_proof_verifies,
            contests_counted: v
                .contests_counted
                .iter()
                .map(|(contest, counted)| CountedDto {
                    contest: *contest,
                    counted: *counted,
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpoilCheckDto {
    pub ok: bool,
    pub message: String,
    pub claimed: Vec<ChoiceDto>,
}

impl From<&SpoilCheck> for SpoilCheckDto {
    fn from(c: &SpoilCheck) -> Self {
        SpoilCheckDto {
            ok: c.ok,
            message: c.message.clone(),
            claimed: c.claimed.iter().map(ChoiceDto::from).collect(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BoardEntryDto {
    pub index: u64,
    pub kind: String,
    pub detail: String,
    pub leaf_hash: String,
}

impl From<&EntrySummary> for BoardEntryDto {
    fn from(e: &EntrySummary) -> Self {
        BoardEntryDto {
            index: e.index,
            kind: e.kind.clone(),
            detail: e.detail.clone(),
            leaf_hash: e.leaf_hash_hex.clone(),
        }
    }
}

/// The raw board and its STHs, as CBOR hex.
#[derive(Serialize, Clone, Debug)]
pub struct ExportDto {
    pub entries: Vec<String>,
    pub sths: Vec<String>,
}

impl ExportDto {
    pub fn new(entries: &[Value], sths: &[Value]) -> ExportDto {
        ExportDto {
            entries: entries.iter().map(|e| to_hex(&cbor::encode(e))).collect(),
            sths: sths.iter().map(|s| to_hex(&cbor::encode(s))).collect(),
        }
    }
}

// -- attacks -----------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AttacksDto {
    pub machine_flips_votes: bool,
    pub board_drops_package_of: Option<String>,
    pub trustee_lies: bool,
    pub ea_alters_result: bool,
    pub board_equivocates: bool,
    pub bad_dkg_share: bool,
}

impl From<AttacksDto> for Attacks {
    fn from(a: AttacksDto) -> Self {
        Attacks {
            machine_flips_votes: a.machine_flips_votes,
            board_drops_package_of: a.board_drops_package_of,
            trustee_lies: a.trustee_lies,
            ea_alters_result: a.ea_alters_result,
            board_equivocates: a.board_equivocates,
            bad_dkg_share: a.bad_dkg_share,
        }
    }
}

impl From<&Attacks> for AttacksDto {
    fn from(a: &Attacks) -> Self {
        AttacksDto {
            machine_flips_votes: a.machine_flips_votes,
            board_drops_package_of: a.board_drops_package_of.clone(),
            trustee_lies: a.trustee_lies,
            ea_alters_result: a.ea_alters_result,
            board_equivocates: a.board_equivocates,
            bad_dkg_share: a.bad_dkg_share,
        }
    }
}

// -- verifier report ---------------------------------------------------------

/// The name of each step of §23, indexed by step number minus one.
const STEP_NAMES: [&str; 16] = [
    "Board",
    "Manifest",
    "Key ceremony",
    "Context",
    "Registry & freeze",
    "Packages",
    "Completeness",
    "Spoiled ballots",
    "Homomorphic tally",
    "Mixnet",
    "Decryption",
    "Final BUs",
    "Counts",
    "Apportionment",
    "Result",
    "Independence",
];

/// The title of a §23 step, or "" for a number outside 1 to 16.
pub fn step_name(step: u8) -> &'static str {
    STEP_NAMES
        .get(usize::from(step).wrapping_sub(1))
        .copied()
        .unwrap_or("")
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FindingDto {
    pub step: u8,
    pub entry: Option<u64>,
    pub section: String,
    pub message: String,
    pub step_name: &'static str,
}

impl From<&Finding> for FindingDto {
    fn from(f: &Finding) -> Self {
        FindingDto {
            step: f.step,
            entry: f.entry,
            section: f.section.to_owned(),
            message: f.message.clone(),
            step_name: step_name(f.step),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedPartyDto {
    pub organisation: String,
    pub bloc: String,
    pub fingerprint: String,
}

impl From<&Party> for VerifiedPartyDto {
    fn from(p: &Party) -> Self {
        VerifiedPartyDto {
            organisation: p.organisation.clone(),
            bloc: p.bloc.clone(),
            fingerprint: p.fingerprint.clone(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RuleDto {
    pub rule: u8,
    pub ok: bool,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PartyKeyDto {
    pub party: String,
    pub fingerprint: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IndependenceDto {
    pub trustees: Vec<VerifiedPartyDto>,
    pub release_signers: Vec<VerifiedPartyDto>,
    pub mirrors: Vec<VerifiedPartyDto>,
    pub rules: Vec<RuleDto>,
    pub party_keys: Vec<PartyKeyDto>,
    pub sections_without_observer: Vec<String>,
    pub parties_without_observer: Vec<String>,
}

impl From<&Independence> for IndependenceDto {
    fn from(i: &Independence) -> Self {
        IndependenceDto {
            trustees: i.trustees.iter().map(VerifiedPartyDto::from).collect(),
            release_signers: i
                .release_signers
                .iter()
                .map(VerifiedPartyDto::from)
                .collect(),
            mirrors: i.mirrors.iter().map(VerifiedPartyDto::from).collect(),
            rules: i
                .rules_11_13
                .iter()
                .map(|&(rule, ok)| RuleDto { rule, ok })
                .collect(),
            party_keys: i
                .party_keys
                .iter()
                .map(|(party, fingerprint)| PartyKeyDto {
                    party: party.clone(),
                    fingerprint: fingerprint.clone(),
                })
                .collect(),
            sections_without_observer: i.sections_without_observer.clone(),
            parties_without_observer: i.parties_without_observer.clone(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OptionVotesDto {
    pub option: String,
    pub votes: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedContestDto {
    pub index: u64,
    pub name: String,
    pub votes: Vec<OptionVotesDto>,
    pub counted: u64,
    pub invalid: u64,
    pub excluded: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedResultDto {
    pub contests: Vec<VerifiedContestDto>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReportDto {
    pub passed: bool,
    pub failures: Vec<FindingDto>,
    pub warnings: Vec<FindingDto>,
    pub excluded: Vec<FindingDto>,
    pub independence: IndependenceDto,
    pub context_hash: Option<String>,
    pub result: Option<VerifiedResultDto>,
}

impl ReportDto {
    /// Converts a verifier report. `manifest` supplies the contest and option
    /// names. Without it, names are "contest N" and "option N".
    pub fn new(report: &Report, manifest: Option<&Manifest>) -> ReportDto {
        let result = report.result.as_ref().map(|r| VerifiedResultDto {
            contests: r
                .contests
                .iter()
                .map(|c| {
                    let contest = manifest.and_then(|m| m.contest(c.contest));
                    VerifiedContestDto {
                        index: c.contest,
                        name: contest
                            .map_or_else(|| format!("contest {}", c.contest), |k| k.name.clone()),
                        votes: c
                            .votes
                            .iter()
                            .enumerate()
                            .map(|(i, &votes)| OptionVotesDto {
                                option: contest
                                    .and_then(|k| k.options.get(i))
                                    .map_or_else(|| format!("option {i}"), |o| o.name.clone()),
                                votes,
                            })
                            .collect(),
                        counted: c.counted,
                        invalid: c.invalid,
                        excluded: c.excluded,
                    }
                })
                .collect(),
        });
        ReportDto {
            passed: report.passed(),
            failures: report.failures.iter().map(FindingDto::from).collect(),
            warnings: report.warnings.iter().map(FindingDto::from).collect(),
            excluded: report.excluded.iter().map(FindingDto::from).collect(),
            independence: IndependenceDto::from(&report.independence),
            context_hash: report.context_hash.as_ref().map(|h| to_hex(h)),
            result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_bytes_are_shortened_but_digests_are_not() {
        let sig = Value::Bytes(vec![0xab; 64]);
        let text = cbor_json(&sig, true);
        assert_eq!(text, format!("\"abababababababab…(64 bytes)\""));
        let digest = Value::Bytes(vec![0xcd; 32]);
        assert_eq!(cbor_json(&digest, true), format!("\"{}\"", "cd".repeat(32)));
        assert_eq!(cbor_json(&sig, false), format!("\"{}\"", "ab".repeat(64)));
    }
}
