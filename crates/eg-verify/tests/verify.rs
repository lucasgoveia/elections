//! End-to-end tests of the verifier (SPEC.md §23): an honest board passes, and
//! each tamper is caught by the step that owns it.

mod support;

use std::collections::BTreeSet;

use eg_core::cbor::Value;
use eg_verify::{verify, Report};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use support::*;

/// The steps that have at least one failure.
fn failed_steps(rep: &Report) -> BTreeSet<u8> {
    rep.failures.iter().map(|f| f.step).collect()
}

fn expect_only(rep: &Report, step: u8) {
    assert!(!rep.passed(), "the tampered board must fail");
    assert_eq!(
        failed_steps(rep),
        BTreeSet::from([step]),
        "failures: {:#?}",
        rep.failures
    );
}

#[test]
fn honest_board_passes() {
    let (w, entries, sths) = honest();
    let rep = verify(&entries, &sths);
    assert!(rep.passed(), "failures: {:#?}", rep.failures);
    assert!(rep.excluded.is_empty(), "excluded: {:#?}", rep.excluded);

    assert_eq!(rep.context_hash, Some(w.context.hash()));
    let published = published_result(&w, &entries);
    assert_eq!(rep.result.as_ref(), Some(&published));

    // Six ballots counted: the spoiled one is not.
    let result = rep.result.as_ref().expect("a recomputed result");
    assert!(result.contests.iter().all(|c| c.counted == 6));
    assert!(result.pool.iter().all(|(_, n, _)| *n == 0));

    // Independence report (step 16).
    assert_eq!(rep.independence.trustees.len(), 3);
    assert_eq!(rep.independence.trustees[0].bloc, "TSE");
    assert_eq!(rep.independence.trustees[0].fingerprint.len(), 16);
    assert_eq!(rep.independence.release_signers.len(), 3);
    assert_eq!(rep.independence.mirrors.len(), 2);
    assert_eq!(
        rep.independence.rules_11_13,
        vec![(11, true), (12, true), (13, true)]
    );
    assert_eq!(rep.independence.party_keys.len(), 2);
    assert_eq!(
        rep.independence.sections_without_observer,
        vec!["S1".to_owned(), "S2".to_owned()]
    );
    assert_eq!(rep.independence.parties_without_observer.len(), 2);
}

#[test]
fn altered_result_vote_count_fails_at_step_15() {
    let (w, mut entries, _) = honest();
    let idx = index_of(&entries, "result");
    let mut result = published_result(&w, &entries);
    result.contests[0].votes[0] += 1;
    entries[idx] = result.sign(&w.keys.ea);
    // The board operator signs tree heads over the altered dump.
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 15);
    assert!(rep.failures[0].entry == Some(idx as u64));
}

#[test]
fn sth_with_a_wrong_root_fails_at_step_1() {
    let (w, entries, mut sths) = honest();
    let cutoff = index_of(&entries, "tally_cutoff") as u64;
    sths[0] = eg_core::board::Sth {
        manifest_hash: w.manifest.hash(),
        size: cutoff + 1,
        root: [7; 32],
        timestamp: 9,
    }
    .sign(&w.keys.board);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 1);
}

#[test]
fn corrupted_share_fails_at_step_11_and_decryption_continues() {
    let (w, mut entries, _) = honest();
    let idx = entries
        .iter()
        .position(|e| {
            e.get(0).ok().flatten().and_then(|t| t.as_text().ok()) == Some("decryption_shares")
                && e.get(4).ok().flatten().and_then(|t| t.as_uint().ok()) == Some(1)
        })
        .expect("a share set of trustee 1");
    entries[idx] = resigned_share_set(&w, &entries[idx], |set| {
        set.shares[0].0 += eg_core::group::B;
    });
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 11);
    let finding = rep.failures.iter().find(|f| f.step == 11).expect("step 11");
    assert_eq!(finding.entry, Some(idx as u64));
    assert!(finding.message.contains("trustee 1"), "{}", finding.message);

    // Trustees 2 and 3 still open every target, so the result is unchanged.
    assert_eq!(rep.result.as_ref(), Some(&published_result(&w, &entries)));
}

#[test]
fn registry_after_polls_open_fails_at_step_5() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let packages = honest_packages(&w, &mut rng);
    let mut late = w.registry.clone();
    late.version = 2;
    let late_registry = eg_core::registry::sign_registry(&late, &w.keys.ea);
    let entries = publish(
        &w,
        &mut rng,
        assemble(&w, packages, vec![late_registry], Vec::new()),
    );
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 5);
    let finding = rep.failures.iter().find(|f| f.step == 5).expect("step 5");
    assert!(
        finding.message.contains("after polls_open"),
        "{}",
        finding.message
    );
}

#[test]
fn missing_dkg_round3_fails_at_step_3() {
    let (w, mut entries, _) = honest();
    let idx = index_of(&entries, "dkg_round3");
    entries.remove(idx);
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 3);
}

#[test]
fn pre_bu_fingerprint_mismatch_fails_at_step_9() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let s1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), &s1_voters());
    let s2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), &s2_voters());
    // The machine of S2 publishes a pre-BU whose fingerprint covers other ballots.
    let s2 = reseal(&w, 1, &s2, Edit::PreBuFingerprint([9; 32]));
    let entries = publish(
        &w,
        &mut rng,
        assemble(&w, vec![s1, s2], Vec::new(), Vec::new()),
    );
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 9);
    let finding = rep.failures.iter().find(|f| f.step == 9).expect("step 9");
    assert!(finding.message.contains("M-S2-01"), "{}", finding.message);
}

#[test]
fn spoiled_reveal_that_claims_other_selections_fails_at_step_8() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let s1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), &s1_voters());
    let s2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), &s2_voters());
    // The spoiled ballot of S1 is revealed with a different choice in contest 0.
    let mut claimed = picks(0);
    claimed[0].selected = vec![2];
    let s1 = reseal(&w, 0, &s1, Edit::SpoilSelections(claimed));
    let entries = publish(
        &w,
        &mut rng,
        assemble(&w, vec![s1, s2], Vec::new(), Vec::new()),
    );
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 8);
    let finding = rep.failures.iter().find(|f| f.step == 8).expect("step 8");
    assert!(finding.message.contains("M-S1-01"), "{}", finding.message);
}

#[test]
fn resealing_without_edits_reproduces_the_package() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let s1 = session(&w, &mut rng, 0, 0, ("S1", "S-1"), &s1_voters());
    let again = reseal(&w, 0, &s1, Edit::None);
    assert_eq!(bytes(&again), bytes(&s1));
}

#[test]
fn rejection_naming_an_accepted_package_fails_at_step_6() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let packages = honest_packages(&w, &mut rng);
    let rejection = rejection_of(&w, &packages[0], "the board says so");
    let entries = publish(
        &w,
        &mut rng,
        assemble(&w, packages, Vec::new(), vec![rejection]),
    );
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    expect_only(&rep, 6);
}

#[test]
fn ballot_with_broken_proofs_is_excluded_and_reported() {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([11; 32]);
    let s1 = session(
        &w,
        &mut rng,
        0,
        0,
        ("S1", "S-1"),
        &[voter(0, false), voter(1, false)],
    );
    let s2 = session(&w, &mut rng, 1, 2, ("S2", "S-2"), &[voter(2, false)]);
    // A second S2 session encrypts under a key that is not the election key, so
    // every proof of its ballot fails and the tally excludes it.
    let wrong_k = eg_core::group::Scalar::from(7u64) * eg_core::group::B;
    let mut rng2 = ChaCha20Rng::from_seed([12; 32]);
    let broken = session_under(
        &w,
        &mut rng2,
        1,
        2,
        ("S2", "S-2b"),
        wrong_k,
        &[voter(0, false)],
    );
    let entries = publish(
        &w,
        &mut rng,
        assemble(&w, vec![s1, s2, broken], Vec::new(), Vec::new()),
    );
    let sths = sths(&w, &entries);

    let rep = verify(&entries, &sths);
    assert!(
        rep.excluded.iter().any(|f| f.message.contains("M-S2-01")),
        "excluded: {:#?}",
        rep.excluded
    );
    // The machine's fingerprint for the section no longer matches the board.
    assert!(
        failed_steps(&rep).contains(&9),
        "failures: {:#?}",
        rep.failures
    );
}

#[test]
fn malformed_boards_fail_without_panicking() {
    assert!(!verify(&[], &[]).passed());

    let (_, entries, sths) = honest();
    assert!(!verify(&[Value::Uint(1)], &sths).passed());
    assert!(!verify(&entries[..5], &sths).passed());
    assert!(!verify(&entries, &[]).passed());

    let garbage: Vec<Value> = std::iter::once(entries[0].clone())
        .chain((1..entries.len()).map(|i| Value::from(i as u64)))
        .collect();
    assert!(!verify(&garbage, &sths).passed());

    let tags_only: Vec<Value> = (0..40u64)
        .map(|_| Value::Map(vec![(Value::Uint(0), Value::from("polls_open"))]))
        .collect();
    assert!(!verify(&tags_only, &sths).passed());
}
