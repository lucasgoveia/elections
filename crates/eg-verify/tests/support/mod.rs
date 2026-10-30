//! Builds complete, honest election boards for the verifier tests, and reseals
//! packages for the tamper tests.
//!
//! The board is produced the way the reference implementation produces it: a
//! real key ceremony (§8), sessions on the voting machines (§14 to §16), the
//! post-election pipeline of `eg_core::authority` (§16.5 to §22), and signed tree
//! heads at two sizes. Tamper helpers change one thing and re-sign with the key
//! of whoever would have signed it, as a malicious party could.

#![allow(dead_code)]

use eg_core::authority::{
    board_view, election_result, encrypted_tally, final_bu, mix_plan, pool_tally, section_tallies,
    trustee_decrypt, BoardView, TallyInputs, Target,
};
use eg_core::ballot::{ContestPlain, Election};
use eg_core::board::{record_id, Log, PollsOpen, Rejection, Sth, TallyCutoff};
use eg_core::cbor::{self, Value};
use eg_core::ceremony::{
    process_shares, transcript_hash, verify_ceremony, Context, Published, Round1, Round2, Round3,
    ShareOutcome,
};
use eg_core::chain::{next_head, tracking_code, Measurement, Reveal, Status};
use eg_core::decrypt::{pool_tally_items, section_tally_items, DecryptionShareSet, FinalBu};
use eg_core::dkg::Polynomial;
use eg_core::fixtures::{sample_manifest, sample_registry, Keys};
use eg_core::group::{RistrettoPoint, Scalar};
use eg_core::journal::{
    auth_signature, checkpoint_signature, Journal, PreBu, Record, SectionSig, Zeresima,
};
use eg_core::machine::{MachineConfig, Session};
use eg_core::manifest::{sign_manifest, Manifest};
use eg_core::mixnet::{run_mix_chain, MixUnit};
use eg_core::package::{Package, PackageHeader};
use eg_core::registry::{sign_registry, Registry};
use eg_core::shuffle::MixOutput;
use eg_core::sign::SigningKey;
use eg_core::tally::{ContestSum, SectionTally};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Measurement that every machine runs. The sample manifest approves it.
pub const APPROVED: Measurement = Measurement([0xaa; 32]);
const OPENED_AT: u64 = 1_700_000_000;
const CHALLENGE: [u8; 16] = [5; 16];
/// Trustees that open every target. Three are published, k = 2 are needed.
pub const TRUSTEES: [u64; 3] = [1, 2, 3];

/// The election: manifest, keys, registry, the context of a real ceremony and the
/// secret shares z_j of every trustee.
pub struct World {
    pub manifest: Manifest,
    pub keys: Keys,
    pub registry: Registry,
    pub context: Context,
    /// z[j-1] = z_j.
    pub zs: Vec<Scalar>,
    /// The signed ceremony records, in board order: round 1, round 2, round 3.
    pub dkg: Vec<Value>,
}

/// Runs the key ceremony of the sample manifest with the fixtures' trustee keys.
pub fn world() -> World {
    let (manifest, keys) = sample_manifest(1);
    let registry = sample_registry(&manifest, &keys);
    let mh = manifest.hash();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let polys: Vec<Polynomial> = (0..3).map(|_| Polynomial::random(&mut rng, 2)).collect();
    let r1: Vec<Round1> = (1..=3u64)
        .map(|i| Round1::new(&mut rng, &mh, i, &polys[(i - 1) as usize]))
        .collect();
    let r2: Vec<Round2> = (1..=3u64)
        .map(|i| {
            Round2::new(
                &mut rng,
                &mh,
                i,
                &polys[(i - 1) as usize],
                &manifest.trustees,
            )
        })
        .collect();
    let round1: Vec<Value> = r1
        .iter()
        .map(|r| r.sign(&keys.trustee_sig[(r.i - 1) as usize]))
        .collect();
    let round2: Vec<Value> = r2
        .iter()
        .map(|r| r.sign(&keys.trustee_sig[(r.i - 1) as usize]))
        .collect();
    let th = transcript_hash(&mh, &round1, &round2);
    let round3: Vec<Value> = (1..=3u64)
        .map(|j| {
            Round3 {
                manifest_hash: mh,
                j,
                transcript_hash: th,
            }
            .sign(&keys.trustee_sig[(j - 1) as usize])
        })
        .collect();
    let context = verify_ceremony(
        &mh,
        &manifest.trustees,
        &Published {
            round1: round1.clone(),
            round2: round2.clone(),
            round3: round3.clone(),
            complaints: Vec::new(),
            reveals: Vec::new(),
        },
    )
    .expect("the honest ceremony verifies");
    let zs: Vec<Scalar> = (1..=3u64)
        .map(|j| {
            match process_shares(
                &mh,
                j,
                &polys[(j - 1) as usize],
                &keys.trustee_hpke[(j - 1) as usize],
                &r1,
                &r2,
            ) {
                ShareOutcome::Accept { z_j } => z_j,
                other => panic!("trustee {j} complained: {other:?}"),
            }
        })
        .collect();
    let dkg: Vec<Value> = round1.into_iter().chain(round2).chain(round3).collect();
    World {
        manifest,
        keys,
        registry,
        context,
        zs,
        dkg,
    }
}

/// One voter: the choices of all six contests, and whether the voter first spoils
/// a ballot under the same authorization.
pub struct Voter {
    pub choices: Vec<ContestPlain>,
    pub spoil_first: bool,
}

/// Choices for the six contests of the sample manifest, by row.
pub fn picks(row: usize) -> Vec<ContestPlain> {
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

pub fn voter(row: usize, spoil_first: bool) -> Voter {
    Voter {
        choices: picks(row),
        spoil_first,
    }
}

/// Voters of section S1 (machine 0, poll workers 0 and 1). The first one spoils a
/// ballot before casting.
pub fn s1_voters() -> Vec<Voter> {
    vec![voter(0, true), voter(1, false), voter(2, false)]
}

/// Voters of section S2 (machine 1, poll workers 2 and 3).
pub fn s2_voters() -> Vec<Voter> {
    vec![voter(1, false), voter(2, false), voter(0, false)]
}

/// Runs one voting session under the election key and returns its signed package.
pub fn session(
    w: &World,
    rng: &mut ChaCha20Rng,
    machine_idx: usize,
    pw_idx: usize,
    ids: (&str, &str),
    voters: &[Voter],
) -> Value {
    session_under(w, rng, machine_idx, pw_idx, ids, w.context.k, voters)
}

/// Runs one voting session whose machine encrypts under `k`. A key other than the
/// election key makes every proof of the ballots fail (§12.6).
pub fn session_under(
    w: &World,
    rng: &mut ChaCha20Rng,
    machine_idx: usize,
    pw_idx: usize,
    (section, session_id): (&str, &str),
    k: RistrettoPoint,
    voters: &[Voter],
) -> Value {
    let machine_id = w.registry.machines[machine_idx].machine_id.clone();
    let pw = &w.keys.poll_workers[pw_idx];
    let ctx_hash = w.context.hash();
    let cfg = MachineConfig {
        election: Election {
            context_hash: ctx_hash,
            k,
            manifest: &w.manifest,
        },
        registry: &w.registry,
        machine_id: machine_id.clone(),
        machine_sk: w.keys.machines[machine_idx].clone(),
        measurement: APPROVED,
    };
    let (mut s, zeresima) =
        Session::open(cfg, section, session_id, OPENED_AT, CHALLENGE).expect("open");
    s.sign_zeresima(vec![SectionSig::create(pw, &zeresima)])
        .expect("zeresima");
    for v in voters {
        let seq = s.next_auth_seq();
        let sig = auth_signature(pw, &ctx_hash, &machine_id, session_id, seq);
        s.authorize(pw.verifying_key(), sig).expect("authorize");
        if v.spoil_first {
            s.encrypt(rng, v.choices.clone()).expect("encrypt");
            s.spoil().expect("spoil");
        }
        s.encrypt(rng, v.choices.clone()).expect("encrypt");
        s.cast().expect("cast");
    }
    let pb = s
        .prepare_pre_bu(voters.len() as u64)
        .expect("prepare pre-bu");
    s.sign_pre_bu(vec![SectionSig::create(pw, &pb)])
        .expect("sign pre-bu");
    s.close(OPENED_AT + 100).expect("close")
}

fn poll_worker_key(w: &World, key: &eg_core::sign::VerifyingKey) -> SigningKey {
    w.keys
        .poll_workers
        .iter()
        .find(|sk| sk.verifying_key() == *key)
        .cloned()
        .expect("a known poll worker key")
}

/// What a tamper does to a journal. `None` reseals the package unchanged.
pub enum Edit {
    None,
    /// Replace the fingerprint (field 14) of the pre-BU.
    PreBuFingerprint([u8; 32]),
    /// Replace the selections of the first spoiled ballot's reveal.
    SpoilSelections(Vec<ContestPlain>),
}

/// Rebuilds a package after an edit: the chain heads, tracking codes, checkpoints,
/// pre-BU and the section signatures on it are recomputed, and the package is
/// signed again by the machine. The result passes the board's journal checks, as
/// it would if a malicious machine had produced it.
pub fn reseal(w: &World, machine_idx: usize, package: &Value, edit: Edit) -> Value {
    let machine_key = w.registry.machines[machine_idx].key;
    let msk = &w.keys.machines[machine_idx];
    let ctx = w.context.hash();
    let pkg = Package::from_signed(package, &machine_key).expect("a machine-signed package");
    let machine_id = pkg.header.machine_id.clone();
    let session_id = pkg.header.session_id.clone();

    let mut journal = Journal::new();
    let mut head = [0u8; 32];
    let mut code = [0u8; 32];
    let mut out: Vec<Record> = Vec::new();
    for rec in pkg.records {
        let new = match rec {
            Record::ZeresimaSigned { zeresima, sigs } => {
                head = Zeresima::from_signed(&zeresima, &machine_key)
                    .expect("zeresima")
                    .head_0;
                Record::ZeresimaSigned { zeresima, sigs }
            }
            Record::Committed { ballot, .. } => {
                code = tracking_code(&head, &ballot);
                Record::Committed { ballot, code }
            }
            Record::Cast { .. } => {
                head = next_head(&code, Status::Cast, None);
                Record::Cast { code }
            }
            Record::Spoiled { reveal, .. } => {
                let reveal = match &edit {
                    Edit::SpoilSelections(selections) => Reveal {
                        selections: selections.clone(),
                        ..reveal
                    },
                    _ => reveal,
                };
                head = next_head(&code, Status::Spoiled, Some(&reveal));
                Record::Spoiled { code, reveal }
            }
            Record::Abandoned { .. } => {
                head = next_head(&code, Status::Abandoned, None);
                Record::Abandoned { code }
            }
            Record::Checkpoint { .. } => {
                let count = journal.len() as u64;
                let frame_digest = journal.last_digest();
                let sig = checkpoint_signature(
                    msk,
                    &ctx,
                    &machine_id,
                    &session_id,
                    count,
                    &frame_digest,
                    &head,
                );
                Record::Checkpoint {
                    count,
                    frame_digest,
                    chain_head: head,
                    sig,
                }
            }
            Record::PreBuSigned { pre_bu, sigs } => {
                let mut pb = PreBu::from_signed(&pre_bu, &machine_key).expect("pre-bu");
                pb.frame_digest = journal.last_digest();
                pb.chain_head = head;
                if let Edit::PreBuFingerprint(fp) = &edit {
                    pb.fingerprint = *fp;
                }
                let value = pb.sign(msk);
                let sigs = sigs
                    .iter()
                    .map(|s| SectionSig::create(&poll_worker_key(w, &s.key), &value))
                    .collect();
                Record::PreBuSigned {
                    pre_bu: value,
                    sigs,
                }
            }
            Record::SessionClose {
                authorizations,
                cast,
                spoiled,
                abandoned,
                closed_at,
                attestation,
                ..
            } => Record::SessionClose {
                authorizations,
                cast,
                spoiled,
                abandoned,
                final_head: head,
                closed_at,
                attestation,
            },
            other => other,
        };
        journal.append(new.clone());
        out.push(new);
    }
    let header = PackageHeader {
        record_count: journal.len() as u64,
        frame_digest: journal.last_digest(),
        chain_head: head,
        ..pkg.header
    };
    Package {
        header,
        records: out,
    }
    .sign(msk)
}

/// The board in order: manifest, ceremony, registry, `polls_open`, the packages,
/// anything `after_polls` (between `polls_open` and the packages), anything
/// `before_cutoff` (after the packages), and `tally_cutoff`.
pub fn assemble(
    w: &World,
    packages: Vec<Value>,
    after_polls: Vec<Value>,
    before_cutoff: Vec<Value>,
) -> Vec<Value> {
    let reg = sign_registry(&w.registry, &w.keys.ea);
    let polls = PollsOpen {
        context_hash: w.context.hash(),
        registry_id: record_id(&reg),
        time: 1,
    }
    .sign(&w.keys.ea);
    let mut entries = vec![sign_manifest(&w.manifest, &w.keys.ea)];
    entries.extend(w.dkg.iter().cloned());
    entries.push(reg);
    entries.push(polls);
    entries.extend(after_polls);
    entries.extend(packages);
    entries.extend(before_cutoff);
    entries.push(
        TallyCutoff {
            context_hash: w.context.hash(),
            time: 2,
        }
        .sign(&w.keys.ea),
    );
    entries
}

/// Trustees 1, 2 and 3 sign share sets for `target`.
fn shares(
    w: &World,
    rng: &mut ChaCha20Rng,
    view: &BoardView,
    sections: &[(SectionTally, bool, Vec<ContestSum>)],
    target: &Target,
) -> Vec<Value> {
    TRUSTEES
        .iter()
        .map(|&j| {
            trustee_decrypt(
                rng,
                view,
                sections,
                target,
                j,
                &w.zs[(j - 1) as usize],
                &w.keys.trustee_sig[(j - 1) as usize],
            )
            .expect("trustee share sets")
        })
        .collect()
}

/// The EA's tally records, published after the cutoff: section tallies, pool,
/// encrypted tally, mix steps, share sets, final BUs and the signed result. Every
/// value is computed from the board, as the reference tally does.
pub fn publish(w: &World, rng: &mut ChaCha20Rng, mut entries: Vec<Value>) -> Vec<Value> {
    let view = board_view(&w.manifest, &w.context, &entries).expect("the board is tallied");
    let log = build_log(&entries);
    let sections = section_tallies(&view);
    let pool = pool_tally(&view, &sections);
    let encrypted = encrypted_tally(&view, &sections, &pool, log.root_at(view.cutoff_index));

    let mut tail: Vec<Value> = Vec::new();
    for (st, _, _) in &sections {
        tail.push(st.to_value());
    }
    tail.push(pool.to_value());
    tail.push(encrypted.to_value());

    let mut final_bus: Vec<(FinalBu, [u8; 32])> = Vec::new();
    for (st, _, _) in &sections {
        if section_tally_items(st).is_empty() {
            continue;
        }
        let sets = shares(w, rng, &view, &sections, &Target::Section(st.clone()));
        let fb = final_bu(&view, st, &sets).expect("final BU");
        let id = record_id(&fb.to_value());
        tail.extend(sets);
        tail.push(fb.to_value());
        final_bus.push((fb, id));
    }

    let pool_target = Target::Pool(pool.clone());
    let pool_share_sets = if pool_tally_items(&pool).is_empty() {
        Vec::new()
    } else {
        let sets = shares(w, rng, &view, &sections, &pool_target);
        tail.extend(sets.clone());
        sets
    };

    let mut mix: Vec<(MixUnit, Vec<MixOutput>, Vec<Value>)> = Vec::new();
    for (unit, rows) in mix_plan(&view) {
        if rows.is_empty() {
            continue;
        }
        let mixers: Vec<(u64, &SigningKey)> = [1u64, 2]
            .iter()
            .map(|&j| (j, &w.keys.trustee_sig[(j - 1) as usize]))
            .collect();
        let chain = run_mix_chain(rng, &w.context, &unit, &rows, &mixers);
        let outputs: Vec<MixOutput> = chain.iter().map(|(_, mo)| mo.clone()).collect();
        for (value, _) in &chain {
            tail.push(value.clone());
        }
        let target = Target::MixFinal {
            unit: unit.clone(),
            input: rows,
            outputs: outputs.clone(),
            last_output_value: chain.last().expect("a mix step").0.clone(),
        };
        let sets = shares(w, rng, &view, &sections, &target);
        tail.extend(sets.clone());
        mix.push((unit, outputs, sets));
    }

    let inputs = TallyInputs {
        final_bus,
        pool_share_sets,
        mix,
    };
    let result = election_result(&view, &sections, &pool, &inputs).expect("the result");
    tail.push(result.sign(&w.keys.ea));
    entries.extend(tail);
    entries
}

/// The Merkle log of a dump (§17.2).
pub fn build_log(entries: &[Value]) -> Log {
    let mut log = Log::new();
    for e in entries {
        log.append(e.clone());
    }
    log
}

/// Two signed tree heads signed by the board key: one at `tally_cutoff`, one at the
/// end of the dump.
pub fn sths(w: &World, entries: &[Value]) -> Vec<Value> {
    let log = build_log(entries);
    let cutoff = entries
        .iter()
        .position(|e| {
            e.get(0).ok().flatten().and_then(|t| t.as_text().ok()) == Some("tally_cutoff")
        })
        .expect("a tally_cutoff") as u64;
    let mh = w.manifest.hash();
    let at = cutoff + 1;
    vec![
        Sth {
            manifest_hash: mh,
            size: at,
            root: log.root_at(at),
            timestamp: 3,
        }
        .sign(&w.keys.board),
        Sth {
            manifest_hash: mh,
            size: log.len(),
            root: log.root(),
            timestamp: 4,
        }
        .sign(&w.keys.board),
    ]
}

/// The honest packages of the two sections, in order.
pub fn honest_packages(w: &World, rng: &mut ChaCha20Rng) -> Vec<Value> {
    vec![
        session(w, rng, 0, 0, ("S1", "S-1"), &s1_voters()),
        session(w, rng, 1, 2, ("S2", "S-2"), &s2_voters()),
    ]
}

/// A complete honest board with its signed tree heads.
pub fn honest() -> (World, Vec<Value>, Vec<Value>) {
    let w = world();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let packages = honest_packages(&w, &mut rng);
    let entries = publish(&w, &mut rng, assemble(&w, packages, Vec::new(), Vec::new()));
    let sths = sths(&w, &entries);
    (w, entries, sths)
}

/// A `rejection` entry signed by the board key, naming `package`.
pub fn rejection_of(w: &World, package: &Value, reason: &str) -> Value {
    Rejection {
        package_id: record_id(package),
        reason: reason.to_owned(),
    }
    .sign(&w.keys.board)
}

/// Index of the first entry with the given tag.
pub fn index_of(entries: &[Value], tag: &str) -> usize {
    entries
        .iter()
        .position(|e| e.get(0).ok().flatten().and_then(|t| t.as_text().ok()) == Some(tag))
        .unwrap_or_else(|| panic!("no {tag} entry"))
}

/// Encoded bytes of a value, for byte comparisons.
pub fn bytes(v: &Value) -> Vec<u8> {
    cbor::encode(v)
}

/// Re-signs a decryption share set after changing it.
pub fn resigned_share_set(
    w: &World,
    entry: &Value,
    change: impl Fn(&mut DecryptionShareSet),
) -> Value {
    let trustee = entry
        .get(4)
        .expect("field")
        .expect("present")
        .as_uint()
        .expect("uint");
    let key = w.manifest.trustees.get(trustee).expect("a trustee").sig_key;
    let mut set = DecryptionShareSet::from_signed(entry, &key).expect("a valid set");
    change(&mut set);
    set.sign(&w.keys.trustee_sig[(trustee - 1) as usize])
}

/// The election result that the board publishes, decoded and verified.
pub fn published_result(w: &World, entries: &[Value]) -> eg_core::decrypt::ElectionResult {
    let e = &entries[index_of(entries, "result")];
    eg_core::decrypt::ElectionResult::from_signed(e, &w.keys.ea.verifying_key(), &w.manifest)
        .expect("the published result verifies")
}
