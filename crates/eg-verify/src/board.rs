//! Steps 1 to 5 of §23: board, manifest, key ceremony, context, registry and
//! freeze.

use eg_core::board::{check_sth_pair, record_id, Log, PollsOpen, Sth, TallyCutoff};
use eg_core::cbor::Value;
use eg_core::ceremony::{verify_ceremony, Context, Published};
use eg_core::manifest::{open_signed_manifest, Manifest};
use eg_core::package::Ingest;
use eg_core::registry::open_signed_registry;

use crate::{fail, fingerprint, tag, warn, Ledger, Party, Report};

/// Builds the board's Merkle log from the dump (§17.2).
pub(crate) fn build_log(entries: &[Value]) -> Log {
    let mut log = Log::new();
    for e in entries {
        log.append(e.clone());
    }
    log
}

/// §23 step 2: entry 0 is a `signed_manifest` with a valid EA signature, and the
/// manifest is well-formed (§7.2, §7.3). Returns the manifest, or `None` if the
/// rest of the verification cannot proceed.
pub(crate) fn step2_manifest(entries: &[Value], rep: &mut Report) -> Option<Manifest> {
    let Some(first) = entries.first() else {
        fail(
            rep,
            2,
            None,
            "§7.3",
            "the board is empty: entry 0 must be the signed manifest",
        );
        return None;
    };
    if tag(first) != Some("signed_manifest") {
        fail(rep, 2, Some(0), "§7.3", "entry 0 is not a signed_manifest");
        return None;
    }
    match open_signed_manifest(first) {
        Ok(m) => Some(m),
        Err(e) => {
            fail(
                rep,
                2,
                Some(0),
                "§7.2, §7.3",
                format!("the manifest does not verify: {e}"),
            );
            None
        }
    }
}

/// §23 step 1: every STH is signed by the board key, names this manifest, covers
/// no more entries than the dump and has the root of the dump at its size. Every
/// pair of STHs is consistent: same size means same root, and otherwise there is
/// a consistency proof from the dump.
pub(crate) fn step1_board(log: &Log, manifest: &Manifest, sths: &[Value], rep: &mut Report) {
    if sths.is_empty() {
        fail(
            rep,
            1,
            None,
            "§17.3",
            "no signed tree head was given: at least one is needed",
        );
        return;
    }
    let mh = manifest.hash();
    let mut heads: Vec<Sth> = Vec::new();
    for (i, v) in sths.iter().enumerate() {
        // The board signs its heads. A mirror signs the heads it has checked, in
        // the same record format (§17.4, §7.1 mirror key).
        let signed = Sth::from_signed(v, &manifest.board_key).or_else(|e| {
            manifest
                .mirrors
                .iter()
                .find_map(|m| Sth::from_signed(v, &m.key).ok())
                .ok_or(e)
        });
        let sth = match signed {
            Ok(sth) => sth,
            Err(e) => {
                fail(
                    rep,
                    1,
                    None,
                    "§17.3",
                    format!("STH {i} does not verify with the board or a mirror key: {e}"),
                );
                continue;
            }
        };
        if sth.manifest_hash != mh {
            fail(
                rep,
                1,
                None,
                "§17.3",
                format!("STH {i} names another manifest"),
            );
            continue;
        }
        if sth.size > log.len() {
            fail(
                rep,
                1,
                None,
                "§17.3",
                format!(
                    "STH {i} covers {} entries but the dump has {}",
                    sth.size,
                    log.len()
                ),
            );
            continue;
        }
        if sth.root != log.root_at(sth.size) {
            fail(
                rep,
                1,
                None,
                "§17.3",
                format!(
                    "STH {i} at size {} has a root that does not match the dump",
                    sth.size
                ),
            );
            continue;
        }
        heads.push(sth);
    }
    for a in 0..heads.len() {
        for b in a + 1..heads.len() {
            let (x, y) = (&heads[a], &heads[b]);
            let (old, new) = if x.size <= y.size {
                (x.size, y.size)
            } else {
                (y.size, x.size)
            };
            let Some(proof) = log.consistency_proof(old, new) else {
                fail(
                    rep,
                    1,
                    None,
                    "§17.4",
                    format!("no consistency proof from size {old} to size {new}"),
                );
                continue;
            };
            if let Some(eq) = check_sth_pair(x, y, &proof) {
                fail(
                    rep,
                    1,
                    None,
                    "§17.4",
                    format!(
                        "STHs of sizes {old} and {new} are inconsistent ({eq:?}): the board showed different views"
                    ),
                );
            }
        }
    }
}

/// §23 step 3: every round 1, 2, 3, complaint and reveal record of the key
/// ceremony verifies (§8.1 to §8.5), and the joint key and verification keys
/// are recomputed. Also records the trustees' fingerprints for step 16. Returns
/// the election context, or `None` if the ceremony does not verify.
pub(crate) fn step3_ceremony(
    entries: &[Value],
    manifest: &Manifest,
    rep: &mut Report,
) -> Option<Context> {
    for t in &manifest.trustees.trustees {
        rep.independence.trustees.push(Party {
            organisation: t.name.clone(),
            bloc: t.bloc.clone(),
            fingerprint: fingerprint(&t.sig_key),
        });
    }
    let mut published = Published {
        round1: Vec::new(),
        round2: Vec::new(),
        round3: Vec::new(),
        complaints: Vec::new(),
        reveals: Vec::new(),
    };
    for e in entries {
        match tag(e) {
            Some("dkg_round1") => published.round1.push(e.clone()),
            Some("dkg_round2") => published.round2.push(e.clone()),
            Some("dkg_round3") => published.round3.push(e.clone()),
            Some("dkg_complaint") => published.complaints.push(e.clone()),
            Some("dkg_reveal") => published.reveals.push(e.clone()),
            _ => {}
        }
    }
    match verify_ceremony(&manifest.hash(), &manifest.trustees, &published) {
        Ok(context) => Some(context),
        Err(e) => {
            fail(
                rep,
                3,
                None,
                "§8.1–§8.5",
                format!("the key ceremony does not verify: {e}"),
            );
            None
        }
    }
}

/// §23 step 4: the context hash is recomputed from the ceremony. The signed
/// `polls_open` and `tally_cutoff` entries must name it.
pub(crate) fn step4_context(
    entries: &[Value],
    manifest: &Manifest,
    context: &Context,
    rep: &mut Report,
) {
    let h = context.hash();
    rep.context_hash = Some(h);
    for (i, e) in entries.iter().enumerate() {
        let named = match tag(e) {
            Some("polls_open") => {
                PollsOpen::from_signed(e, &manifest.ea_key).map(|p| p.context_hash)
            }
            Some("tally_cutoff") => {
                TallyCutoff::from_signed(e, &manifest.ea_key).map(|t| t.context_hash)
            }
            _ => continue,
        };
        // A record that does not verify is reported by step 5.
        if let Ok(named) = named {
            if named != h {
                fail(
                    rep,
                    4,
                    Some(i as u64),
                    "§9, §17.7",
                    "names a context hash other than the one the ceremony gives",
                );
            }
        }
    }
}

/// §23 step 5: the registry and the software policy are frozen at `polls_open`,
/// `polls_open` names the registry in force, and `tally_cutoff` follows it.
/// Also checks every registry signature (§7.7).
pub(crate) fn step5_freeze(
    entries: &[Value],
    manifest: &Manifest,
    ledger: &Ledger,
    rep: &mut Report,
) {
    let mut polls = Vec::new();
    let mut cutoffs = Vec::new();
    let mut registries = Vec::new();
    let mut policies = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        match tag(e) {
            Some("polls_open") => polls.push(i),
            Some("tally_cutoff") => cutoffs.push(i),
            Some("signed_registry") => registries.push(i),
            Some("software_policy_update") => policies.push(i),
            _ => {}
        }
    }

    match polls.as_slice() {
        [] => fail(rep, 5, None, "§17.7", "the board has no polls_open"),
        [_] => {}
        [_, extra @ ..] => {
            for &i in extra {
                fail(rep, 5, Some(i as u64), "§17.7", "a second polls_open");
            }
        }
    }
    let polls_at = polls.first().copied();

    // Entries that the board refused must be explained. Registry and policy
    // entries after polls_open are board misbehaviour, whatever the reason.
    for &i in registries
        .iter()
        .chain(&policies)
        .chain(&polls)
        .chain(&cutoffs)
    {
        let after_polls = polls_at.is_some_and(|p| i > p);
        let is_freeze_entry = matches!(
            tag(&entries[i]),
            Some("signed_registry" | "software_policy_update")
        );
        if is_freeze_entry && after_polls {
            fail(
                rep,
                5,
                Some(i as u64),
                "§7.7, §24.4",
                "board misbehaviour: signed_registry or software_policy_update after polls_open",
            );
        } else if let Ingest::Rejected(reason) = &ledger.verdicts[i] {
            fail(
                rep,
                5,
                Some(i as u64),
                "§7.7, §17.7, §24.4",
                format!("the board refused this entry: {reason}"),
            );
        }
    }

    for &i in &registries {
        if let Err(e) = open_signed_registry(&entries[i], manifest) {
            fail(
                rep,
                5,
                Some(i as u64),
                "§7.7",
                format!("the registry does not verify: {e}"),
            );
        }
    }

    let registry_in_force = registries
        .iter()
        .copied()
        .rfind(|&i| !polls_at.is_some_and(|p| i >= p));
    match (polls_at, registry_in_force) {
        (_, None) => fail(
            rep,
            5,
            polls_at.map(|p| p as u64),
            "§7.7",
            "no signed_registry before polls_open",
        ),
        (Some(p), Some(r)) => match PollsOpen::from_signed(&entries[p], &manifest.ea_key) {
            Ok(po) => {
                if po.registry_id != record_id(&entries[r]) {
                    fail(
                        rep,
                        5,
                        Some(p as u64),
                        "§17.7",
                        "polls_open does not name the registry in force",
                    );
                }
            }
            Err(e) => fail(
                rep,
                5,
                Some(p as u64),
                "§17.7",
                format!("polls_open does not verify: {e}"),
            ),
        },
        (None, Some(_)) => {}
    }

    match cutoffs.as_slice() {
        [] => fail(rep, 5, None, "§17.7", "the board has no tally_cutoff"),
        [c] => {
            if let Err(e) = TallyCutoff::from_signed(&entries[*c], &manifest.ea_key) {
                fail(
                    rep,
                    5,
                    Some(*c as u64),
                    "§17.7",
                    format!("tally_cutoff does not verify: {e}"),
                );
            }
            if polls_at.is_some_and(|p| *c < p) {
                fail(
                    rep,
                    5,
                    Some(*c as u64),
                    "§17.7",
                    "tally_cutoff comes before polls_open",
                );
            }
        }
        [first, extra @ ..] => {
            fail(
                rep,
                5,
                Some(*first as u64),
                "§17.7",
                "more than one tally_cutoff",
            );
            for &i in extra {
                fail(rep, 5, Some(i as u64), "§17.7", "a second tally_cutoff");
            }
        }
    }

    if !policies.is_empty() {
        warn(
            rep,
            5,
            None,
            "§24.4",
            "software_policy_update adds approved hashes: the release log is not an input to this verifier, so the k_r release signatures behind them are not checked",
        );
    }
    warn(
        rep,
        5,
        None,
        "§24",
        "release records and signatures are not checked: the release log is not an input to this verifier",
    );
}
