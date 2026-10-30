//! Steps 13 to 16 of §23: counts, apportionment, the published result and the
//! independence report.

use std::collections::BTreeMap;

use eg_core::apportionment::{apportion, party_totals};
use eg_core::authority::{election_result, BoardView, TallyInputs};
use eg_core::board::record_id;
use eg_core::cbor::Value;
use eg_core::decrypt::{ElectionResult, FinalBu};
use eg_core::manifest::{ContestKind, Manifest};
use eg_core::mixnet::MixUnit;
use eg_core::shuffle::MixOutput;
use eg_core::sign::VerifyingKey;

use crate::tally::{Homo, MixState, VerifiedSets};
use crate::{fail, fingerprint, tag, warn, Ledger, Party, Report};

/// §23 step 13: the counts of every contest are recomputed: homomorphic contests
/// from the final BUs and the decrypted pool, mixnet contests from the decrypted
/// mix units (§19.6, §21). Errors here mean the counts cannot be recomputed.
pub(crate) fn step13_counts(
    view: &BoardView,
    homo: &Homo,
    finals: &[(FinalBu, [u8; 32])],
    sets: &VerifiedSets,
    mix: &[MixState],
    rep: &mut Report,
) -> Option<ElectionResult> {
    let pool_id = record_id(&homo.pool.to_value());
    let pool_share_sets = sets.get(&pool_id).cloned().unwrap_or_default();
    let mix_inputs: Vec<(MixUnit, Vec<MixOutput>, Vec<Value>)> = mix
        .iter()
        .filter(|m| !m.rows.is_empty())
        .map(|m| {
            let shares = m
                .last_digest
                .and_then(|d| sets.get(&d))
                .cloned()
                .unwrap_or_default();
            (m.unit.clone(), m.outputs.clone(), shares)
        })
        .collect();
    let inputs = TallyInputs {
        final_bus: finals.to_vec(),
        pool_share_sets,
        mix: mix_inputs,
    };
    match election_result(view, &homo.sections, &homo.pool, &inputs) {
        Ok(r) => Some(r),
        Err(e) => {
            fail(
                rep,
                13,
                None,
                "§19.6, §21",
                format!("the counts cannot be recomputed: {e}"),
            );
            None
        }
    }
}

/// The published `result` entries that verify under the EA key (§21), with their
/// entry index. An entry that does not verify is a step 15 failure.
pub(crate) fn decode_published(
    entries: &[Value],
    manifest: &Manifest,
    rep: &mut Report,
) -> Vec<(usize, ElectionResult)> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("result") {
            continue;
        }
        match ElectionResult::from_signed(e, &manifest.ea_key, manifest) {
            Ok(r) => out.push((i, r)),
            Err(err) => fail(
                rep,
                15,
                Some(i as u64),
                "§21",
                format!("published result does not verify: {err}"),
            ),
        }
    }
    out
}

/// §23 step 14: the seats and party totals of every proportional contest in the
/// published result follow from its own vote counts (§22).
pub(crate) fn step14_apportionment(
    published: &[(usize, ElectionResult)],
    manifest: &Manifest,
    rep: &mut Report,
) {
    for (i, result) in published {
        for cr in &result.contests {
            let Some(contest) = manifest.contest(cr.contest) else {
                continue;
            };
            if contest.kind != ContestKind::Proportional {
                continue;
            }
            let totals = party_totals(manifest, contest, &cr.votes);
            let seats = apportion(manifest, contest, &cr.votes);
            match (totals, seats) {
                (Ok(t), Ok(s)) => {
                    if cr.party_totals.as_ref() != Some(&t) {
                        fail(
                            rep,
                            14,
                            Some(*i as u64),
                            "§22",
                            format!(
                                "contest {}: party totals do not follow from the votes",
                                cr.contest
                            ),
                        );
                    }
                    if cr.seats.as_ref() != Some(&s) {
                        fail(
                            rep,
                            14,
                            Some(*i as u64),
                            "§22",
                            format!("contest {}: seats do not follow from the votes", cr.contest),
                        );
                    }
                }
                (Err(e), _) | (_, Err(e)) => fail(
                    rep,
                    14,
                    Some(*i as u64),
                    "§22",
                    format!("contest {}: apportionment fails: {e}", cr.contest),
                ),
            }
        }
    }
}

/// §23 step 15: the published result equals the recomputed one. Any difference is
/// a failure, and the report names the contests that differ.
pub(crate) fn step15_result(
    published: &[(usize, ElectionResult)],
    recomputed: Option<&ElectionResult>,
    rep: &mut Report,
) {
    if published.is_empty() {
        warn(
            rep,
            15,
            None,
            "§21",
            "no published result: the recomputed result is reported without a comparison",
        );
        return;
    }
    let Some(recomputed) = recomputed else {
        // Step 13 already failed; nothing to compare with.
        return;
    };
    for (i, p) in published {
        if p == recomputed {
            continue;
        }
        let mut diffs = Vec::new();
        for (a, b) in recomputed.contests.iter().zip(&p.contests) {
            if a != b {
                diffs.push(format!(
                    "contest {}: votes {:?} vs published {:?}, counted {} vs {}",
                    a.contest, a.votes, b.votes, a.counted, b.counted
                ));
            }
        }
        if p.contests.len() != recomputed.contests.len() {
            diffs.push("different number of contests".to_owned());
        }
        if p.sections != recomputed.sections {
            diffs.push("section results differ".to_owned());
        }
        if p.pool != recomputed.pool {
            diffs.push("pool results differ".to_owned());
        }
        if diffs.is_empty() {
            diffs.push("header fields differ".to_owned());
        }
        fail(
            rep,
            15,
            Some(*i as u64),
            "§21",
            format!(
                "published result differs from the recomputed result: {}",
                diffs.join("; ")
            ),
        );
    }
}

/// §23 step 16: the parties and organisations that rest the election on the
/// authority's word, with their fingerprints, and the results of rules 11 to 13
/// (§7.2). Trustees and sections are filled by steps 3 and 7.
pub(crate) fn step16_independence(manifest: &Manifest, ledger: &Ledger, rep: &mut Report) {
    let k = manifest.trustees.k;
    let k_r = manifest.software_policy.k_r;

    rep.independence.release_signers = manifest
        .software_policy
        .signers
        .iter()
        .map(|s| Party {
            organisation: s.organisation.clone(),
            bloc: s.bloc.clone(),
            fingerprint: fingerprint(&s.key),
        })
        .collect();
    rep.independence.mirrors = manifest
        .mirrors
        .iter()
        .map(|m| Party {
            organisation: m.operator.clone(),
            bloc: m.bloc.clone(),
            fingerprint: fingerprint(&m.key),
        })
        .collect();

    // Rule 11: no bloc holds k or more trustees. Rule 12: no bloc holds k_r or more
    // release signers. Rule 13: at least two mirrors outside the EA's bloc.
    let mut trustee_blocs: BTreeMap<&str, u64> = BTreeMap::new();
    for t in &manifest.trustees.trustees {
        *trustee_blocs.entry(t.bloc.as_str()).or_insert(0) += 1;
    }
    let rule11 = trustee_blocs.values().all(|&n| n < k);
    let mut signer_blocs: BTreeMap<&str, u64> = BTreeMap::new();
    for s in &manifest.software_policy.signers {
        *signer_blocs.entry(s.bloc.as_str()).or_insert(0) += 1;
    }
    let rule12 = signer_blocs.values().all(|&n| n < k_r);
    let outside = manifest
        .mirrors
        .iter()
        .filter(|m| m.bloc != manifest.ea_bloc)
        .count();
    let rule13 = outside >= 2;
    rep.independence.rules_11_13 = vec![(11, rule11), (12, rule12), (13, rule13)];
    for (rule, ok) in [(11, rule11), (12, rule12), (13, rule13)] {
        if !ok {
            fail(
                rep,
                2,
                None,
                "§7.2",
                format!("manifest rule {rule} does not hold"),
            );
        }
    }

    rep.independence.party_keys = manifest
        .parties
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                p.key.as_ref().map(|k: &VerifyingKey| fingerprint(k)),
            )
        })
        .collect();
    rep.independence.parties_without_observer = manifest
        .parties
        .iter()
        .filter(|p| !ledger.cert_parties.contains(&p.index))
        .map(|p| p.name.clone())
        .collect();
}
