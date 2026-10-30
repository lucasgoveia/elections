//! Steps 6 to 8 of §23: packages, completeness and spoiled ballots.

use std::collections::{HashMap, HashSet};

use eg_core::authority::{board_view, BoardView, ViewPackage};
use eg_core::ballot::{check_reveal, ContestStatus, Election};
use eg_core::board::{record_id, Rejection};
use eg_core::cbor::Value;
use eg_core::ceremony::Context;
use eg_core::journal::{PreBu, Record};
use eg_core::manifest::Manifest;
use eg_core::package::{
    Ingest, ObserverCert, ObserverRevoke, Package, PackageHeader, RecoveredPackage,
    SectionAttestation,
};
use eg_core::registry::Registry;
use eg_core::sign::VerifyingKey;

use crate::{entry_id, exclude, fail, records_of, tag, warn, Ledger, Report};

/// The kind tag, machine and session of an attested zerésima or pre-BU (§16.3).
fn attested_fields(record: &Value) -> Option<(String, String, String)> {
    let tag = tag(record)?.to_owned();
    let machine = crate::text_at(record, 3)?.to_owned();
    let session = crate::text_at(record, 5)?.to_owned();
    Some((tag, machine, session))
}

/// Packages that the board refused, by RecordId.
fn rejected_package_ids(entries: &[Value], ledger: &Ledger) -> HashSet<[u8; 32]> {
    entries
        .iter()
        .enumerate()
        .filter(|(i, e)| {
            matches!(tag(e), Some("package" | "recovered_package"))
                && matches!(ledger.verdicts[*i], Ingest::Rejected(_))
        })
        .map(|(_, e)| entry_id(e))
        .collect()
}

/// §23 step 6: every package and recovered package is judged (§17.6, §12.6).
/// Rejected packages are warnings, since a rejection is not always the board's
/// fault. A `rejection` that names a package which passes the rules is a
/// failure. Every excluded ballot and contest is listed as an excluded finding,
/// with its machine and the failing check. Reused α values are reported with both
/// ballots (nonce reuse, `docs/spec-issues.md` item 20).
///
/// Returns the board view (the tally input, §18.1), or `None` if the board cannot
/// be tallied at all.
pub(crate) fn step6_packages<'a>(
    entries: &'a [Value],
    manifest: &'a Manifest,
    context: &'a Context,
    ledger: &Ledger,
    rep: &mut Report,
) -> Option<BoardView<'a>> {
    let view = match board_view(manifest, context, entries) {
        Ok(v) => v,
        Err(e) => {
            fail(
                rep,
                6,
                None,
                "§17.6, §17.7",
                format!("the board cannot be tallied: {e}"),
            );
            return None;
        }
    };

    // Observer certificates and revocations must verify under a party key (§16.3).
    for (i, e) in entries.iter().enumerate() {
        // A party record must verify under the key of the party it names in
        // field 3 (§16.3), not merely under some party's key.
        let named_party = e.get(3).ok().flatten().and_then(|v| v.as_uint().ok());
        let verifies = |check: &dyn Fn(&eg_core::sign::VerifyingKey) -> bool| {
            manifest
                .parties
                .iter()
                .filter(|p| Some(p.index) == named_party)
                .filter_map(|p| p.key.as_ref())
                .any(check)
        };
        match tag(e) {
            Some("observer_cert") => {
                if !verifies(&|pk| ObserverCert::from_signed(e, pk).is_ok()) {
                    fail(
                        rep,
                        6,
                        Some(i as u64),
                        "§16.3",
                        "observer_cert does not verify under any party key",
                    );
                }
            }
            Some("observer_revoke")
                if !verifies(&|pk| ObserverRevoke::from_signed(e, pk).is_ok()) =>
            {
                fail(
                    rep,
                    6,
                    Some(i as u64),
                    "§16.3",
                    "observer_revoke does not verify under any party key",
                );
            }
            _ => {}
        }
    }

    // Entries the board refused, with the reason it gave.
    for (i, e) in entries.iter().enumerate() {
        let Ingest::Rejected(reason) = &ledger.verdicts[i] else {
            continue;
        };
        match tag(e) {
            Some("package" | "recovered_package") => warn(
                rep,
                6,
                Some(i as u64),
                "§17.6",
                format!("package rejected by the board: {reason}"),
            ),
            Some("observer_cert" | "observer_revoke" | "section_attestation") => warn(
                rep,
                6,
                Some(i as u64),
                "§16.3",
                format!("entry rejected by the board: {reason}"),
            ),
            _ => {}
        }
    }

    // A `rejection` must name a package that really fails a rule (§17.6).
    let accepted_ids: HashSet<[u8; 32]> = ledger.packages.iter().map(|p| p.package_id).collect();
    let rejected_ids = rejected_package_ids(entries, ledger);
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("rejection") {
            continue;
        }
        match Rejection::from_signed(e, &manifest.board_key) {
            Err(err) => fail(
                rep,
                6,
                Some(i as u64),
                "§17.6",
                format!("rejection does not verify: {err}"),
            ),
            Ok(r) => {
                if accepted_ids.contains(&r.package_id) {
                    fail(
                        rep,
                        6,
                        Some(i as u64),
                        "§17.6",
                        format!(
                            "rejection names a package that passes the rules: {}",
                            r.reason
                        ),
                    );
                } else if !rejected_ids.contains(&r.package_id) {
                    fail(
                        rep,
                        6,
                        Some(i as u64),
                        "§17.6",
                        "rejection names no package on the board",
                    );
                }
            }
        }
    }

    // Excluded ballots and contests (§12.6), with the α holder for nonce reuse.
    let mut alpha_holder: HashMap<[u8; 32], String> = HashMap::new();
    for p in view.packages.iter().filter(|p| !p.superseded) {
        for (ballot, judged) in &p.cast {
            let who = format!(
                "machine {} session {} ballot {}",
                p.machine_id, p.session_id, ballot.id.seq
            );
            match &judged.well_formed {
                Err(reason) => exclude(
                    rep,
                    Some(p.entry_index),
                    "§12.6",
                    format!("{who}: not well formed, excluded from every contest: {reason}"),
                ),
                Ok(()) => {
                    for (c, status) in &judged.contests {
                        match status {
                            ContestStatus::Excluded(reason) => {
                                let mut msg = format!("{who}, contest {c} excluded: {reason}");
                                if reason.contains("α already reserved") {
                                    let holder = ballot
                                        .alphas(*c)
                                        .iter()
                                        .find_map(|a| alpha_holder.get(&a.compress().to_bytes()));
                                    match holder {
                                        Some(h) => msg.push_str(&format!(
                                            " (nonce reuse: the same α as {h})"
                                        )),
                                        None => msg.push_str(" (nonce reuse, holder not found)"),
                                    }
                                }
                                exclude(rep, Some(p.entry_index), "§12.6", msg);
                            }
                            ContestStatus::Counted => {
                                for a in ballot.alphas(*c) {
                                    alpha_holder
                                        .entry(a.compress().to_bytes())
                                        .or_insert_with(|| format!("{who}, contest {c}"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Some(view)
}

/// The records of a view package, decoded again from its entry.
fn records_of_view(p: &ViewPackage, entries: &[Value], view: &BoardView) -> Option<Vec<Record>> {
    records_of(
        &entries[p.entry_index as usize],
        p.recovered,
        &p.machine_id,
        &view.registry,
    )
}

/// §23 step 7: completeness of the tally (§16.2 to §16.4, §18.1, §7.7). Lists
/// missing sections, attestations without a matching package, pre-BUs that
/// disagree, recovered packages nobody imports, double imports, disagreeing
/// recovered media, reserve machines serving more than one section, cast totals
/// beyond the voter rolls, and sections without an observer signature.
pub(crate) fn step7_completeness(
    view: &BoardView,
    entries: &[Value],
    ledger: &Ledger,
    rep: &mut Report,
) {
    let registry = &view.registry;

    // Every registered section has an accepted package before the cutoff.
    for s in &registry.sections {
        if !view.packages.iter().any(|p| p.section_id == s.section_id) {
            fail(
                rep,
                7,
                None,
                "§7.7, §16.2",
                format!(
                    "section {} has no accepted package before tally_cutoff",
                    s.section_id
                ),
            );
        }
    }
    // A registered regular machine with no package is worth a warning. Reserve
    // machines are idle unless they were needed.
    for m in registry
        .machines
        .iter()
        .filter(|m| !m.section_id.is_empty())
    {
        if !view.packages.iter().any(|p| p.machine_id == m.machine_id) {
            warn(
                rep,
                7,
                None,
                "§7.7",
                format!(
                    "machine {} has no accepted package before tally_cutoff",
                    m.machine_id
                ),
            );
        }
    }

    // Attestations: the attested record must be the one the package holds (§16.3).
    for (i, e) in entries.iter().enumerate() {
        if tag(e) != Some("section_attestation") {
            continue;
        }
        if !matches!(ledger.verdicts[i], Ingest::Accepted) {
            continue;
        }
        let Ok(att) = SectionAttestation::from_value(e) else {
            continue;
        };
        let Some((kind, machine, session)) = attested_fields(&att.record) else {
            continue;
        };
        let candidate = view
            .packages
            .iter()
            .find(|p| p.machine_id == machine && p.session_id == session);
        let Some(p) = candidate else {
            fail(
                rep,
                7,
                Some(i as u64),
                "§16.3",
                format!(
                    "attested {kind} of machine {machine} session {session} has no accepted package (missing or rejected)"
                ),
            );
            continue;
        };
        let attested_id = record_id(&att.record);
        match kind.as_str() {
            "pre_bu" => match &p.pre_bu {
                None => fail(
                    rep,
                    7,
                    Some(i as u64),
                    "§16.3",
                    "attested pre-BU is not in a machine package",
                ),
                Some((_, value)) => {
                    if record_id(value) != attested_id {
                        let attested = machine_key(registry, &machine)
                            .ok_or_else(|| eg_core::Error::Board("unknown machine".into()))
                            .and_then(|k| PreBu::from_signed(&att.record, &k));
                        let detail = match (attested, &p.pre_bu) {
                            (Ok(a), Some((pb, _))) => format!(
                                "chain head {} vs {}, frame digest {} vs {}",
                                hex8(&a.chain_head),
                                hex8(&pb.chain_head),
                                hex8(&a.frame_digest),
                                hex8(&pb.frame_digest)
                            ),
                            _ => "the records differ".to_owned(),
                        };
                        fail(
                            rep,
                            7,
                            Some(i as u64),
                            "§16.3",
                            format!("attested pre-BU differs from the package's pre-BU ({detail})"),
                        );
                    }
                }
            },
            _ => {
                let Some(recs) = records_of_view(p, entries, view) else {
                    continue;
                };
                let zeresima = recs.iter().find_map(|r| match r {
                    Record::ZeresimaSigned { zeresima, .. } => Some(zeresima),
                    _ => None,
                });
                if zeresima.map(record_id) != Some(attested_id) {
                    fail(
                        rep,
                        7,
                        Some(i as u64),
                        "§16.3",
                        "attested zerésima differs from the package's zerésima",
                    );
                }
            }
        }
    }

    // Two different machine-signed pre-BUs for one session (§16.2).
    let mut pre_bus: HashMap<(String, String), HashSet<[u8; 32]>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        match tag(e) {
            Some("package") => {
                let Ok(pkg_fields) = eg_core::cbor::record_fields(e, "package", 5) else {
                    continue;
                };
                let Ok(header) = PackageHeader::from_value(pkg_fields[2]) else {
                    continue;
                };
                let Some(key) = machine_key(registry, &header.machine_id) else {
                    continue;
                };
                let Ok(pkg) = Package::from_signed(e, &key) else {
                    continue;
                };
                for rec in &pkg.records {
                    if let Record::PreBuSigned { pre_bu, .. } = rec {
                        if PreBu::from_signed(pre_bu, &key).is_ok() {
                            pre_bus
                                .entry((header.machine_id.clone(), header.session_id.clone()))
                                .or_default()
                                .insert(record_id(pre_bu));
                        }
                    }
                }
            }
            Some("section_attestation") if matches!(ledger.verdicts[i], Ingest::Accepted) => {
                let Ok(att) = SectionAttestation::from_value(e) else {
                    continue;
                };
                if tag(&att.record) == Some("pre_bu") {
                    if let (Some(m), Some(s)) = (
                        crate::text_at(&att.record, 3),
                        crate::text_at(&att.record, 5),
                    ) {
                        pre_bus
                            .entry((m.to_owned(), s.to_owned()))
                            .or_default()
                            .insert(record_id(&att.record));
                    }
                }
            }
            _ => {}
        }
    }
    let mut sessions: Vec<&(String, String)> = pre_bus.keys().collect();
    sessions.sort();
    for key in sessions {
        if pre_bus[key].len() > 1 {
            fail(
                rep,
                7,
                None,
                "§16.2",
                format!(
                    "machine {} session {} has {} different machine-signed pre-BUs",
                    key.0,
                    key.1,
                    pre_bus[key].len()
                ),
            );
        }
    }

    // Recovered packages: imports (§16.4, spec issue 22).
    let mut imports: HashMap<[u8; 32], u64> = HashMap::new();
    for p in &view.packages {
        if let Some((pb, _)) = &p.pre_bu {
            for imp in &pb.imported {
                *imports.entry(imp.package_id).or_insert(0) += 1;
            }
        }
    }
    for p in view
        .packages
        .iter()
        .filter(|p| p.recovered && !p.superseded)
    {
        if !imports.contains_key(&p.id) {
            fail(
                rep,
                7,
                Some(p.entry_index),
                "§16.4",
                format!(
                    "recovered package of machine {} session {} is imported by no pre-BU",
                    p.machine_id, p.session_id
                ),
            );
        }
    }
    for p in view.packages.iter().filter(|p| p.recovered) {
        if imports.get(&p.id).is_some_and(|&n| n > 1) {
            fail(
                rep,
                7,
                Some(p.entry_index),
                "§16.4, spec issue 22",
                format!(
                    "recovered package of machine {} session {} is imported by {} pre-BUs (double count)",
                    p.machine_id, p.session_id, imports[&p.id]
                ),
            );
        }
    }

    // Disagreeing recovered media: two different recovered packages for one
    // session (§16.4).
    let mut recovered: HashMap<(String, String), HashSet<[u8; 32]>> = HashMap::new();
    for e in entries
        .iter()
        .filter(|e| tag(e) == Some("recovered_package"))
    {
        if let Ok(rp) = RecoveredPackage::from_value(e) {
            recovered
                .entry((rp.header.machine_id.clone(), rp.header.session_id.clone()))
                .or_default()
                .insert(record_id(e));
        }
    }
    for (key, ids) in &recovered {
        if ids.len() > 1 {
            fail(
                rep,
                7,
                None,
                "§16.4",
                format!(
                    "machine {} session {} has {} different recovered packages (disagreeing media)",
                    key.0,
                    key.1,
                    ids.len()
                ),
            );
        }
    }

    // Reserve machines serve one section, with the contests of its regular machines.
    for m in registry.machines.iter().filter(|m| m.section_id.is_empty()) {
        let sections: HashSet<&str> = view
            .packages
            .iter()
            .filter(|p| p.machine_id == m.machine_id)
            .map(|p| p.section_id.as_str())
            .collect();
        if sections.len() > 1 {
            fail(
                rep,
                7,
                None,
                "§7.7",
                format!(
                    "reserve machine {} serves {} sections",
                    m.machine_id,
                    sections.len()
                ),
            );
        }
        for s in &sections {
            let regular: Vec<_> = registry
                .machines
                .iter()
                .filter(|r| r.section_id == *s)
                .collect();
            if regular.iter().any(|r| r.contests != m.contests) {
                fail(
                    rep,
                    7,
                    None,
                    "§7.7",
                    format!(
                        "reserve machine {} offers other contests than section {s}",
                        m.machine_id
                    ),
                );
            }
        }
    }

    // Cast totals against voter rolls and eligible voters (§16.2, §7.7).
    let mut sections_seen: HashSet<&str> = HashSet::new();
    for s in &registry.sections {
        if !sections_seen.insert(s.section_id.as_str()) {
            continue;
        }
        let cast: u64 = view
            .packages
            .iter()
            .filter(|p| p.section_id == s.section_id && !p.superseded)
            .map(|p| p.cast.len() as u64)
            .sum();
        let mut roll_max = 0u64;
        for p in view
            .packages
            .iter()
            .filter(|p| p.section_id == s.section_id)
        {
            if let Some((pb, _)) = &p.pre_bu {
                roll_max = roll_max.max(pb.roll_count);
            }
            if p.recovered {
                if let Ok(rp) = RecoveredPackage::from_value(&entries[p.entry_index as usize]) {
                    roll_max = roll_max.max(rp.roll_count);
                }
            }
        }
        if cast > roll_max {
            fail(
                rep,
                7,
                None,
                "§16.2",
                format!(
                    "section {} has {cast} cast ballots but its largest voter roll is {roll_max}",
                    s.section_id
                ),
            );
        }
        if cast > s.eligible {
            fail(
                rep,
                7,
                None,
                "§7.7",
                format!(
                    "section {} has {cast} cast ballots but {} eligible voters",
                    s.section_id, s.eligible
                ),
            );
        }
    }

    // Observer signatures on zerésimas and pre-BUs (§15.5, §16.3, §28.18).
    for s in &registry.sections {
        let mut observed = false;
        for p in view
            .packages
            .iter()
            .filter(|p| p.section_id == s.section_id)
        {
            let Some(recs) = records_of_view(p, entries, view) else {
                continue;
            };
            for rec in &recs {
                if let Record::ZeresimaSigned { sigs, .. } | Record::PreBuSigned { sigs, .. } = rec
                {
                    observed |= sigs.iter().any(|sg| ledger.is_observer(&sg.key));
                }
            }
        }
        for a in ledger
            .attestations
            .iter()
            .filter(|a| a.section_id == s.section_id)
        {
            observed |= ledger.is_observer(&a.key) && !s.poll_worker_keys.contains(&a.key);
        }
        if !observed {
            rep.independence
                .sections_without_observer
                .push(s.section_id.clone());
        }
    }
}

/// The registered key of a machine, if the registry has it.
fn machine_key(registry: &Registry, machine_id: &str) -> Option<VerifyingKey> {
    registry.machine(machine_id).map(|m| m.key)
}

/// First 4 bytes of a digest, in hex (for messages).
fn hex8(d: &[u8; 32]) -> String {
    d[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// §23 step 8: every spoiled ballot's reveal (§14.2) re-encrypts to the ballot
/// byte for byte. A mismatch names the machine.
pub(crate) fn step8_spoiled(
    view: &BoardView,
    context: &Context,
    manifest: &Manifest,
    rep: &mut Report,
) {
    let election = Election {
        context_hash: context.hash(),
        k: context.k,
        manifest,
    };
    for p in &view.packages {
        for (ballot, reveal) in &p.spoiled {
            let who = format!(
                "machine {} session {} ballot {}",
                p.machine_id, p.session_id, ballot.id.seq
            );
            if reveal.ballot_id != ballot.id {
                fail(
                    rep,
                    8,
                    Some(p.entry_index),
                    "§14.2",
                    format!("{who}: the reveal names another ballot"),
                );
                continue;
            }
            if let Err(reason) = check_reveal(&election, ballot, &reveal.rho, &reveal.selections) {
                fail(
                    rep,
                    8,
                    Some(p.entry_index),
                    "§14.2",
                    format!("{who}: the reveal does not match the ballot: {reason}"),
                );
            }
        }
    }
}
