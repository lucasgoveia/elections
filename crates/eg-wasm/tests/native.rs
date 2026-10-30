//! Native tests of the pure-Rust `*_dto` methods. The JavaScript bindings
//! cannot run outside a browser, so these drive the same logic through the
//! inner methods.

use eg_wasm::{short_code_of_dto, Sim};

#[test]
fn election_dto_lists_six_contests() {
    let sim = Sim::new(1);
    let election = sim.election_dto();
    assert_eq!(election.contests.len(), 6);
    assert_eq!(sim.phase_name(), "setup");
    assert!(!election.sections.is_empty());
}

#[test]
fn run_all_dto_returns_contests_with_votes() {
    let mut sim = Sim::new(1);
    let result = sim.run_all_dto().expect("run_all");
    assert_eq!(sim.phase_name(), "tallied");
    assert_eq!(result.contests.len(), 6);
    assert!(result.contests.iter().all(|c| c.counted > 0));
    assert!(result
        .contests
        .iter()
        .any(|c| c.options.iter().any(|o| o.votes > 0)));
    assert!(result.sections.iter().all(|s| s.matches));
}

#[test]
fn board_dto_is_non_empty_after_run() {
    let mut sim = Sim::new(1);
    assert_eq!(
        sim.board_dto().len(),
        1,
        "only the signed manifest at first"
    );
    sim.run_all_dto().expect("run_all");
    let board = sim.board_dto();
    assert!(!board.is_empty());
    assert_eq!(board[0].index, 0);
    assert_eq!(board[0].leaf_hash.len(), 64);
}

#[test]
fn entry_json_of_entry_zero_is_the_signed_manifest() {
    let sim = Sim::new(1);
    let json = sim.entry_json_dto(0).expect("entry 0");
    assert!(json.contains("signed_manifest"), "{json}");
    assert!(sim.entry_json_dto(1_000_000).is_err());
}

#[test]
fn vote_flow_through_dto_methods() {
    let mut sim = Sim::new(2);
    sim.run_ceremony_dto().expect("ceremony");
    sim.open_polls_dto().expect("polls");

    let election = sim.election_dto();
    let machine = election.sections[0].machines[0].clone();
    let zeresima = sim.open_session_dto(&machine, None).expect("open session");
    assert_eq!(zeresima.machine_id, machine);
    assert_eq!(zeresima.contests.len(), 6);

    let choices = sim.random_choices_dto(&machine).expect("choices");
    assert_eq!(choices.len(), 6);
    sim.authorize_dto(&machine).expect("authorize");
    let encrypted = sim.encrypt_dto(&machine, choices.clone()).expect("encrypt");
    assert_eq!(encrypted.code.len(), 64);
    assert_eq!(
        encrypted.short_code,
        short_code_of_dto(&encrypted.code).expect("short code")
    );

    let slip = sim.cast_dto(&machine).expect("cast");
    assert_eq!(slip.short_code, encrypted.short_code);
    assert!(slip.slip_json.starts_with('{'));

    sim.close_session_dto(&machine).expect("close");
    sim.cutoff_dto().expect("cutoff");
    // The inclusion proof is checked against the latest STH, so sign one first.
    let sths = sim.sign_sth_dto().expect("sth");
    assert_eq!(sths.len(), 1);
    let found = sim.lookup_dto(&slip.short_code).expect("lookup");
    assert!(found.found);
    assert_eq!(found.status.as_deref(), Some("cast"));
    assert!(found.inclusion_proof_verifies);
}

#[test]
fn spoil_receipt_checks_out_through_dto_methods() {
    let mut sim = Sim::new(3);
    sim.run_ceremony_dto().expect("ceremony");
    sim.open_polls_dto().expect("polls");
    let machine = sim.election_dto().sections[0].machines[0].clone();
    sim.open_session_dto(&machine, None).expect("open");
    sim.authorize_dto(&machine).expect("authorize");
    let choices = sim.random_choices_dto(&machine).expect("choices");
    sim.encrypt_dto(&machine, choices).expect("encrypt");
    let spoil = sim.spoil_dto(&machine).expect("spoil");
    sim.close_session_dto(&machine).expect("close");
    sim.cutoff_dto().expect("cutoff");
    let check = sim.check_spoil_dto(&spoil.receipt_hex).expect("check");
    assert!(check.ok, "{}", check.message);
    assert_eq!(check.claimed, spoil.claimed);
}

#[test]
fn attacks_round_trip_and_reach_the_simulation() {
    let mut sim = Sim::new(4);
    let mut attacks = sim.attacks_dto();
    assert!(!attacks.machine_flips_votes);
    attacks.ea_alters_result = true;
    sim.set_attacks_dto(attacks.clone());
    assert_eq!(sim.attacks_dto(), attacks);
    let altered = sim.run_all_dto().expect("run_all");

    // The same seed without the attack gives the honest tally.
    let mut honest = Sim::new(4);
    let result = honest.run_all_dto().expect("run_all");
    assert_eq!(
        altered.contests[0].options[0].votes,
        result.contests[0].options[0].votes + 100
    );
}

#[test]
fn export_board_matches_the_board() {
    let mut sim = Sim::new(5);
    sim.run_all_dto().expect("run_all");
    let export = sim.export_board_dto();
    assert_eq!(export.entries.len(), sim.board_dto().len());
    assert!(!export.sths.is_empty());
    assert_eq!(sim.board_root_hex().len(), 64);
}

#[test]
fn short_code_of_formats_four_groups() {
    let code = "00".repeat(32);
    assert_eq!(
        short_code_of_dto(&code).expect("short code"),
        "0000-0000-0000-0000-0000"
    );
    assert!(short_code_of_dto("abcd").is_err());
}

// -- verifier -------------------------------------------------------------

use eg_wasm::{verify_board_dto, AttacksDto, FindingDto};

fn run_with(seed: u32, attacks: AttacksDto) -> Sim {
    let mut sim = Sim::new(seed);
    sim.set_attacks_dto(attacks);
    sim.run_all_dto().expect("run_all");
    sim
}

fn steps(findings: &[FindingDto]) -> Vec<u8> {
    findings.iter().map(|f| f.step).collect()
}

#[test]
fn verify_honest_run_passes() {
    let sim = run_with(10, AttacksDto::default());
    let report = sim.verify_dto();
    assert!(report.passed, "{:?}", report.failures);
    // Only the standing §24 release-log warning remains.
    assert!(
        report.warnings.iter().all(|w| w.section == "§24"),
        "{:?}",
        report.warnings
    );
    let result = report.result.expect("result");
    assert_eq!(result.contests.len(), 6);
    assert_eq!(
        result.contests[0].votes[0].option,
        sim.election_dto().contests[0].options[0].name
    );
    assert!(report.context_hash.is_some());
    assert_eq!(report.independence.rules.len(), 3);
}

#[test]
fn verify_ea_altered_result_fails_at_step_15() {
    let sim = run_with(
        11,
        AttacksDto {
            ea_alters_result: true,
            ..Default::default()
        },
    );
    let report = sim.verify_dto();
    assert!(!report.passed);
    let f = report
        .failures
        .iter()
        .find(|f| f.step == 15)
        .unwrap_or_else(|| panic!("no step-15 failure: {:?}", report.failures));
    assert_eq!(f.step_name, "Result");
    assert!(
        f.message.contains("published result differs"),
        "{}",
        f.message
    );
}

#[test]
fn verify_trustee_lies_fails_at_step_11_and_keeps_result() {
    let sim = run_with(
        12,
        AttacksDto {
            trustee_lies: true,
            ..Default::default()
        },
    );
    let report = sim.verify_dto();
    assert!(!report.passed);
    assert!(
        steps(&report.failures).contains(&11),
        "{:?}",
        report.failures
    );
    assert!(report.result.is_some());
}

#[test]
fn verify_equivocating_board_fails_at_step_1() {
    let mut sim = Sim::new(13);
    sim.set_attacks_dto(AttacksDto {
        board_equivocates: true,
        ..Default::default()
    });
    sim.run_all_dto().expect("run_all");
    // run_all signed the first STH. This second call signs the conflicting one.
    let second = sim.sign_sth_dto().expect("second sth");
    assert_eq!(second.len(), 2);
    let report = sim.verify_dto();
    assert!(!report.passed);
    assert!(
        steps(&report.failures).contains(&1),
        "{:?}",
        report.failures
    );
}

#[test]
fn verify_dropped_package_is_flagged_at_step_7() {
    let machine = Sim::new(14).election_dto().sections[0].machines[0].clone();
    let sim = run_with(
        14,
        AttacksDto {
            board_drops_package_of: Some(machine),
            ..Default::default()
        },
    );
    let report = sim.verify_dto();
    // Step 7 reports the missing package as a failure, and as a warning for the machine.
    assert!(
        steps(&report.failures).contains(&7),
        "{:?}",
        report.failures
    );
    assert!(
        steps(&report.warnings).contains(&7),
        "{:?}",
        report.warnings
    );
}

#[test]
fn verify_board_standalone_names_contests_from_entry_zero() {
    let sim = run_with(15, AttacksDto::default());
    let export = sim.export_board_dto();
    let report = verify_board_dto(&export.entries, &export.sths).expect("verify_board");
    let result = report.result.expect("result");
    assert_eq!(result.contests[0].name, sim.election_dto().contests[0].name);
}

#[test]
fn verify_board_rejects_bad_hex_and_handles_an_empty_board() {
    assert!(verify_board_dto(&["zz".to_owned()], &[]).is_err());
    let report = verify_board_dto(&[], &[]).expect("empty board");
    assert!(!report.passed);
    assert!(report.result.is_none());
}

// -- scenarios ----------------------------------------------------------------

use eg_wasm::scenarios_dto;

#[test]
fn scenarios_list_star_wars_then_pilot() {
    let ids: Vec<String> = scenarios_dto().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, ["star-wars", "pilot"]);
}

#[test]
fn unknown_scenario_is_an_error_that_lists_the_names() {
    let err = Sim::with_scenario_dto(1, "dune").err().expect("error");
    let msg = err.to_string();
    assert!(msg.contains("pilot") && msg.contains("star-wars"), "{msg}");
}

#[test]
fn pilot_election_dto_offers_every_contest_on_each_machine() {
    let sim = Sim::new(1);
    let election = sim.election_dto();
    assert_eq!(election.scenario, "pilot");
    assert_eq!(sim.scenario_name(), "pilot");
    for s in &election.sections {
        assert_eq!(s.machine_contests.len(), 1);
        assert_eq!(s.machine_contests[0].contests.len(), 6);
    }
    assert_eq!(election.reserve_machine_contests.len(), 1);
    assert_eq!(
        election.reserve_machine_contests[0].id,
        election.reserve_machines[0]
    );
}

#[test]
fn starwars_election_dto_has_eleven_contests_and_ten_sections() {
    let sim = Sim::with_scenario_dto(1, "star-wars").expect("star-wars");
    assert_eq!(sim.scenario_name(), "star-wars");
    let election = sim.election_dto();
    assert_eq!(election.scenario, "star-wars");
    assert_eq!(election.contests.len(), 11);
    assert_eq!(election.sections.len(), 10);
    assert!(election.reserve_machines.is_empty());
    assert!(election.reserve_machine_contests.is_empty());
    for s in &election.sections {
        assert_eq!(s.machines.len(), 1);
        assert_eq!(s.machine_contests.len(), 1);
        assert_eq!(s.machine_contests[0].id, s.machines[0]);
        assert_eq!(s.machine_contests[0].contests.len(), 2);
    }
}

#[test]
fn starwars_run_all_verifies_with_only_the_release_log_warning() {
    let mut sim = Sim::with_scenario_dto(16, "star-wars").expect("star-wars");
    sim.run_all_dto().expect("run_all");
    assert_eq!(sim.phase_name(), "tallied");
    let report = sim.verify_dto();
    assert!(report.passed, "{:?}", report.failures);
    assert!(
        report.warnings.iter().all(|w| w.section == "§24"),
        "{:?}",
        report.warnings
    );
    let result = report.result.expect("result");
    assert_eq!(result.contests.len(), 11);
}
