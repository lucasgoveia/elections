//! WebAssembly bindings for the eg/v1 election simulator (test UI).
//!
//! Each exported method is a thin wrapper. It calls a pure-Rust `*_dto` method
//! that returns eg-core errors, so the logic can be tested natively. The
//! wrappers do the JavaScript conversions and map errors to `JsError`.

mod dto;

pub use dto::{scenarios_dto, AttacksDto, FindingDto, MachineOfferDto, ScenarioDto};

use eg_core::board::Log;
use eg_core::cbor;
use eg_core::manifest::{open_signed_manifest, Manifest};
use eg_core::sim::{Attacks, Scenario, Simulation};
use eg_core::Error;
use eg_verify::verify;
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use dto::{
    phase_name, BoardEntryDto, CeremonyDto, ChoiceDto, ElectionDto, EncryptDto, ExportDto,
    LookupDto, PreBuDto, ReportDto, ResultDto, SlipDto, SpoilCheckDto, SpoilDto, SthDto,
    ZeresimaDto,
};

fn js_err(e: Error) -> JsError {
    JsError::new(&e.to_string())
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))
}

/// One election, played step by step. Demo and test tool: every key is in
/// memory, and one process plays every role.
#[wasm_bindgen]
pub struct Sim {
    inner: Simulation,
    /// A copy of the attack switches, because eg-core does not expose them.
    attacks: Attacks,
}

// -- pure-Rust inner methods (tested natively) --------------------------------

impl Sim {
    pub fn phase_name(&self) -> &'static str {
        phase_name(self.inner.phase())
    }

    pub fn election_dto(&self) -> ElectionDto {
        ElectionDto::new(
            self.inner.manifest(),
            self.inner.registry(),
            self.inner.scenario(),
        )
    }

    /// A simulation of the scenario named `scenario` ("pilot" or "star-wars").
    pub fn with_scenario_dto(seed: u32, scenario: &str) -> Result<Sim, Error> {
        let scenario = Scenario::from_name(scenario).ok_or_else(|| {
            let valid: Vec<&str> = Scenario::ALL.iter().map(Scenario::name).collect();
            Error::Board(format!(
                "sim: unknown scenario {scenario:?}, expected one of: {}",
                valid.join(", ")
            ))
        })?;
        Ok(Sim {
            inner: Simulation::with_scenario(u64::from(seed), scenario),
            attacks: Attacks::default(),
        })
    }

    /// The identifier of the scenario: "pilot" or "star-wars".
    pub fn scenario_name(&self) -> &'static str {
        self.inner.scenario().name()
    }

    pub fn run_ceremony_dto(&mut self) -> Result<CeremonyDto, Error> {
        Ok(CeremonyDto::from(&self.inner.run_ceremony()?))
    }

    pub fn open_polls_dto(&mut self) -> Result<(), Error> {
        self.inner.open_polls()
    }

    pub fn open_session_dto(
        &mut self,
        machine_id: &str,
        section: Option<&str>,
    ) -> Result<ZeresimaDto, Error> {
        Ok(ZeresimaDto::from(
            &self.inner.open_session(machine_id, section)?,
        ))
    }

    pub fn authorize_dto(&mut self, machine_id: &str) -> Result<u32, Error> {
        let seq = self.inner.authorize(machine_id)?;
        u32::try_from(seq).map_err(|_| Error::Board("sim: auth_seq does not fit in u32".into()))
    }

    pub fn encrypt_dto(
        &mut self,
        machine_id: &str,
        choices: Vec<ChoiceDto>,
    ) -> Result<EncryptDto, Error> {
        let (code, short_code) = self
            .inner
            .encrypt(machine_id, choices.into_iter().map(Into::into).collect())?;
        Ok(EncryptDto { code, short_code })
    }

    pub fn cast_dto(&mut self, machine_id: &str) -> Result<SlipDto, Error> {
        Ok(SlipDto::from(&self.inner.cast(machine_id)?))
    }

    pub fn spoil_dto(&mut self, machine_id: &str) -> Result<SpoilDto, Error> {
        Ok(SpoilDto::from(&self.inner.spoil(machine_id)?))
    }

    pub fn abandon_dto(&mut self, machine_id: &str) -> Result<(), Error> {
        self.inner.abandon(machine_id)
    }

    pub fn close_session_dto(&mut self, machine_id: &str) -> Result<PreBuDto, Error> {
        Ok(PreBuDto::from(&self.inner.close_session(machine_id)?))
    }

    pub fn cutoff_dto(&mut self) -> Result<(), Error> {
        self.inner.cutoff()
    }

    pub fn tally_dto(&mut self) -> Result<ResultDto, Error> {
        Ok(ResultDto::from(&self.inner.tally()?))
    }

    pub fn sign_sth_dto(&mut self) -> Result<Vec<SthDto>, Error> {
        let board_key = self.inner.manifest().board_key;
        self.inner
            .sign_sth()
            .iter()
            .map(|v| SthDto::from_signed(v, &board_key))
            .collect()
    }

    pub fn lookup_dto(&self, short_code: &str) -> Result<LookupDto, Error> {
        Ok(LookupDto::from(&self.inner.lookup(short_code)?))
    }

    pub fn check_spoil_dto(&self, receipt_hex: &str) -> Result<SpoilCheckDto, Error> {
        let receipt = cbor::decode(&dto::parse_hex(receipt_hex)?)?;
        Ok(SpoilCheckDto::from(&self.inner.check_spoil(&receipt)?))
    }

    pub fn board_dto(&self) -> Vec<BoardEntryDto> {
        self.inner
            .entry_summaries()
            .iter()
            .map(BoardEntryDto::from)
            .collect()
    }

    /// Merkle root of the whole board, as hex.
    pub fn board_root_hex(&self) -> String {
        let mut log = Log::new();
        for entry in self.inner.entries() {
            log.append(entry.clone());
        }
        dto::to_hex(&log.root())
    }

    pub fn entry_json_dto(&self, index: u64) -> Result<String, Error> {
        let entry = self.entry(index)?;
        Ok(dto::cbor_json(entry, true))
    }

    pub fn entry_hex_dto(&self, index: u64) -> Result<String, Error> {
        Ok(dto::to_hex(&cbor::encode(self.entry(index)?)))
    }

    fn entry(&self, index: u64) -> Result<&cbor::Value, Error> {
        self.inner
            .entries()
            .get(usize::try_from(index).unwrap_or(usize::MAX))
            .ok_or_else(|| Error::Board(format!("no board entry {index}")))
    }

    pub fn random_choices_dto(&mut self, machine_id: &str) -> Result<Vec<ChoiceDto>, Error> {
        if self.inner.registry().machine(machine_id).is_none() {
            return Err(Error::Board(format!("no machine {machine_id:?}")));
        }
        Ok(self
            .inner
            .random_choices(machine_id)
            .iter()
            .map(ChoiceDto::from)
            .collect())
    }

    pub fn cast_random_dto(&mut self, machine_id: &str, n: u32) -> Result<(), Error> {
        self.inner.cast_random(machine_id, n as usize)
    }

    pub fn run_all_dto(&mut self) -> Result<ResultDto, Error> {
        Ok(ResultDto::from(&self.inner.run_all()?))
    }

    pub fn set_attacks_dto(&mut self, attacks: AttacksDto) {
        let attacks: Attacks = attacks.into();
        *self.inner.attacks_mut() = attacks.clone();
        self.attacks = attacks;
    }

    pub fn attacks_dto(&self) -> AttacksDto {
        AttacksDto::from(&self.attacks)
    }

    pub fn export_board_dto(&self) -> ExportDto {
        ExportDto::new(self.inner.entries(), self.inner.sths())
    }

    /// Runs the full §23 verifier over this simulation's board and STHs.
    pub fn verify_dto(&self) -> ReportDto {
        ReportDto::new(
            &verify(self.inner.entries(), self.inner.sths()),
            Some(self.inner.manifest()),
        )
    }
}

/// Verifies a board given as CBOR hex strings. Contest and option names come
/// from entry 0 when it is a valid signed manifest.
pub fn verify_board_dto(entries_hex: &[String], sths_hex: &[String]) -> Result<ReportDto, Error> {
    let entries = decode_all(entries_hex)?;
    let sths = decode_all(sths_hex)?;
    let manifest: Option<Manifest> = entries
        .first()
        .and_then(|first| open_signed_manifest(first).ok());
    Ok(ReportDto::new(&verify(&entries, &sths), manifest.as_ref()))
}

fn decode_all(hex_strings: &[String]) -> Result<Vec<cbor::Value>, Error> {
    hex_strings
        .iter()
        .map(|h| Ok(cbor::decode(&dto::parse_hex(h)?)?))
        .collect()
}

/// The short code of a 32-byte code given as hex.
pub fn short_code_of_dto(code_hex: &str) -> Result<String, Error> {
    let code = dto::parse_digest(code_hex)?;
    Ok(eg_core::chain::short_code(&code))
}

// -- JavaScript bindings -----------------------------------------------------

#[wasm_bindgen]
impl Sim {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: u32) -> Sim {
        Sim {
            inner: Simulation::new(u64::from(seed)),
            attacks: Attacks::default(),
        }
    }

    /// A simulation of the named scenario: "star-wars" or "pilot". An unknown
    /// name is an error that lists the valid names.
    pub fn with_scenario(seed: u32, scenario: &str) -> Result<Sim, JsError> {
        Sim::with_scenario_dto(seed, scenario).map_err(js_err)
    }

    /// The identifier of this simulation's scenario: "pilot" or "star-wars".
    pub fn scenario(&self) -> String {
        self.scenario_name().to_owned()
    }

    /// "setup" | "ceremony-done" | "polls-open" | "polls-closed" | "tallied"
    pub fn phase(&self) -> String {
        self.phase_name().to_owned()
    }

    pub fn election(&self) -> Result<JsValue, JsError> {
        to_js(&self.election_dto())
    }

    pub fn run_ceremony(&mut self) -> Result<JsValue, JsError> {
        to_js(&self.run_ceremony_dto().map_err(js_err)?)
    }

    pub fn open_polls(&mut self) -> Result<(), JsError> {
        self.open_polls_dto().map_err(js_err)
    }

    pub fn open_session(
        &mut self,
        machine_id: &str,
        section: Option<String>,
    ) -> Result<JsValue, JsError> {
        to_js(
            &self
                .open_session_dto(machine_id, section.as_deref())
                .map_err(js_err)?,
        )
    }

    pub fn authorize(&mut self, machine_id: &str) -> Result<u32, JsError> {
        self.authorize_dto(machine_id).map_err(js_err)
    }

    /// `choices` is a JS array of `{ contest: number, selected: number[] }`.
    pub fn encrypt(&mut self, machine_id: &str, choices: JsValue) -> Result<JsValue, JsError> {
        let choices: Vec<ChoiceDto> = from_js(choices)?;
        to_js(&self.encrypt_dto(machine_id, choices).map_err(js_err)?)
    }

    pub fn cast(&mut self, machine_id: &str) -> Result<JsValue, JsError> {
        to_js(&self.cast_dto(machine_id).map_err(js_err)?)
    }

    pub fn spoil(&mut self, machine_id: &str) -> Result<JsValue, JsError> {
        to_js(&self.spoil_dto(machine_id).map_err(js_err)?)
    }

    pub fn abandon(&mut self, machine_id: &str) -> Result<(), JsError> {
        self.abandon_dto(machine_id).map_err(js_err)
    }

    pub fn close_session(&mut self, machine_id: &str) -> Result<JsValue, JsError> {
        to_js(&self.close_session_dto(machine_id).map_err(js_err)?)
    }

    pub fn cutoff(&mut self) -> Result<(), JsError> {
        self.cutoff_dto().map_err(js_err)
    }

    pub fn tally(&mut self) -> Result<JsValue, JsError> {
        to_js(&self.tally_dto().map_err(js_err)?)
    }

    pub fn sign_sth(&mut self) -> Result<JsValue, JsError> {
        to_js(&self.sign_sth_dto().map_err(js_err)?)
    }

    pub fn lookup(&self, short_code: &str) -> Result<JsValue, JsError> {
        to_js(&self.lookup_dto(short_code).map_err(js_err)?)
    }

    pub fn check_spoil(&self, receipt_hex: &str) -> Result<JsValue, JsError> {
        to_js(&self.check_spoil_dto(receipt_hex).map_err(js_err)?)
    }

    pub fn board(&self) -> Result<JsValue, JsError> {
        to_js(&self.board_dto())
    }

    pub fn board_root(&self) -> String {
        self.board_root_hex()
    }

    pub fn entry_json(&self, index: u32) -> Result<String, JsError> {
        self.entry_json_dto(u64::from(index)).map_err(js_err)
    }

    pub fn entry_hex(&self, index: u32) -> Result<String, JsError> {
        self.entry_hex_dto(u64::from(index)).map_err(js_err)
    }

    pub fn random_choices(&mut self, machine_id: &str) -> Result<JsValue, JsError> {
        to_js(&self.random_choices_dto(machine_id).map_err(js_err)?)
    }

    pub fn cast_random(&mut self, machine_id: &str, n: u32) -> Result<(), JsError> {
        self.cast_random_dto(machine_id, n).map_err(js_err)
    }

    pub fn run_all(&mut self) -> Result<JsValue, JsError> {
        to_js(&self.run_all_dto().map_err(js_err)?)
    }

    /// `attacks` is `{ machineFlipsVotes, boardDropsPackageOf, trusteeLies,
    /// eaAltersResult, boardEquivocates, badDkgShare }`. Missing fields are off.
    pub fn set_attacks(&mut self, attacks: JsValue) -> Result<(), JsError> {
        let attacks: AttacksDto = from_js(attacks)?;
        self.set_attacks_dto(attacks);
        Ok(())
    }

    pub fn get_attacks(&self) -> Result<JsValue, JsError> {
        to_js(&self.attacks_dto())
    }

    /// The raw board and the STHs, as CBOR hex: `{ entries, sths }`.
    pub fn export_board(&self) -> Result<JsValue, JsError> {
        to_js(&self.export_board_dto())
    }

    /// Runs the full §23 verifier over this simulation's board and STHs.
    pub fn verify(&self) -> Result<JsValue, JsError> {
        to_js(&self.verify_dto())
    }
}

/// Verifies a board given as CBOR hex strings: `entries_hex` and `sths_hex`
/// are JS arrays of strings, as in `export_board`.
#[wasm_bindgen]
pub fn verify_board(entries_hex: JsValue, sths_hex: JsValue) -> Result<JsValue, JsError> {
    let entries: Vec<String> = from_js(entries_hex)?;
    let sths: Vec<String> = from_js(sths_hex)?;
    to_js(&verify_board_dto(&entries, &sths).map_err(js_err)?)
}

/// The short code (`XXXX-XXXX-XXXX-XXXX-XXXX`) of a 32-byte tracking code.
#[wasm_bindgen]
pub fn short_code_of(code_hex: &str) -> Result<String, JsError> {
    short_code_of_dto(code_hex).map_err(js_err)
}

/// The selectable scenarios, as `[{ id, name }]`.
#[wasm_bindgen]
pub fn scenarios() -> JsValue {
    to_js(&scenarios_dto()).unwrap_or(JsValue::NULL)
}
