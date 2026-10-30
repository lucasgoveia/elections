//! Stateful election simulation driver. It runs a whole sample election step by
//! step, for the web demo and for tests.
//!
//! DEMO AND TEST TOOL. Every random choice (keys, polynomials, nonces, ballots)
//! comes from a ChaCha20 stream seeded by the caller, so the same seed always
//! gives the same election. Nothing here is a secure implementation: all keys
//! sit in memory, and one process plays the EA, the board, the trustees, the
//! machines and the poll workers. The [`Attacks`] switches are deliberate
//! misbehaviour, for the demo and for tests.
//!
//! Driver and phase errors are returned as [`Error::Board`] with a `sim:`
//! prefix. Errors from the protocol modules pass through unchanged.
//!
//! Lifetimes. The manifest and the registry are fixed by [`Simulation::new`],
//! and the context is fixed by [`Simulation::run_ceremony`]. Each is leaked once
//! with `Box::leak`, so the `Session<'static>` and `BoardState<'static>` values
//! can be stored in [`Simulation`]. The leak is a few kilobytes per simulation,
//! which is fine for a driver used in short-lived processes and tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::authority::{self, BoardView, TallyInputs, Target};
use crate::ballot::{check_reveal, Ballot, ContestPlain, ContestStatus, Election};
use crate::board::{
    leaf_hash, record_id, verify_inclusion, Log, PollsOpen, Rejection, Sth, TallyCutoff,
};
use crate::cbor::Value;
use crate::ceremony::{
    self, process_shares, transcript_hash, verify_ceremony, Complaint, Context, Published, Round1,
    Round2, Round3, ShareOutcome,
};
use crate::chain::{parse_short_code, short_code, short_code_matches, Measurement, SpoilReceipt};
use crate::decrypt::{section_tally_items, DecryptionShareSet, ElectionResult};
use crate::dkg::{secret_share, Polynomial};
use crate::error::Error;
use crate::fixtures::{self, Keys};
use crate::group::{Scalar, B};
use crate::journal::{auth_cancel_signature, auth_signature, PreBu, Record, SectionSig};
use crate::machine::{MachineConfig, Session};
use crate::manifest::{sign_manifest, ContestKind, Manifest, OptionKind};
use crate::mixnet::run_mix_chain;
use crate::package::{BoardState, Ingest, Package, PackageHeader, SectionAttestation};
use crate::registry::{sign_registry, Registry};
use crate::share_enc::encrypt_share;
use crate::shuffle::MixOutput;
use crate::sign::{SigningKey, VerifyingKey};
use crate::tally::{ContestSum, SectionTally};

/// The trustee whose decryption shares are corrupted by `trustee_lies`.
const LYING_TRUSTEE: u64 = 3;

/// Sections of a tally: the section tally, whether its fingerprint matches the
/// pre-BU, and the pooled sums.
type Sections = Vec<(SectionTally, bool, Vec<ContestSum>)>;

/// Phase of the simulated election, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Setup,
    CeremonyDone,
    PollsOpen,
    PollsClosed,
    Tallied,
}

/// Deliberate misbehaviour that the simulation can switch on.
#[derive(Clone, Debug, Default)]
pub struct Attacks {
    /// The machine encrypts a different choice for contest 0 than the voter
    /// asked for, and its spoil receipt claims the voter's choice. The spoil
    /// check must catch it.
    pub machine_flips_votes: bool,
    /// The board does not receive this machine's package. The section
    /// attestation of its pre-BU is still posted.
    pub board_drops_package_of: Option<String>,
    /// Trustee 3 signs corrupted decryption shares. They must be rejected.
    pub trustee_lies: bool,
    /// The EA adds 100 votes to option 0 of contest 0 before signing the result.
    pub ea_alters_result: bool,
    /// After the first STH, the board signs a second STH at the same size over
    /// a log with its last entry altered.
    pub board_equivocates: bool,
    /// Trustee 1 sends trustee 2 a share that does not match its commitments.
    /// Trustee 2 complains, and trustee 1 reveals the correct share.
    pub bad_dkg_share: bool,
}

/// Summary of one board entry, for display.
#[derive(Clone, Debug)]
pub struct EntrySummary {
    pub index: u64,
    /// The type tag (field 0) of the entry.
    pub kind: String,
    /// One line describing the entry.
    pub detail: String,
    pub leaf_hash_hex: String,
}

/// Result of the ceremony.
#[derive(Clone, Debug)]
pub struct CeremonyReport {
    /// `(index, organisation, bloc)` of each trustee.
    pub trustees: Vec<(u64, String, String)>,
    pub k: u64,
    pub n: u64,
    /// One line per complaint, each resolved by a reveal.
    pub complaints: Vec<String>,
    pub context_hash_hex: String,
    pub joint_key_hex: String,
}

/// What a poll worker prints when a session opens.
#[derive(Clone, Debug)]
pub struct ZeresimaView {
    pub machine_id: String,
    pub section_id: String,
    pub session_id: String,
    pub measurement_hex: String,
    pub head0_hex: String,
    /// `(index, name, option names)` of each offered contest.
    pub contests: Vec<(u64, String, Vec<String>)>,
}

/// A slip given to the voter after a cast.
#[derive(Clone, Debug)]
pub struct SlipView {
    pub short_code: String,
    pub code_hex: String,
    pub machine_id: String,
    pub slip: Value,
}

/// A spoil receipt, and what the machine says the ballot encrypts.
#[derive(Clone, Debug)]
pub struct SpoilView {
    pub short_code: String,
    pub receipt: Value,
    pub claimed: Vec<ContestPlain>,
}

/// What a closed session reports in its pre-BU.
#[derive(Clone, Debug)]
pub struct PreBuView {
    pub machine_id: String,
    pub section_id: String,
    pub cast: u64,
    pub spoiled: u64,
    pub abandoned: u64,
    /// The subtotal fingerprint, as grouped upper-case hex.
    pub fingerprint: String,
    pub chain_head_hex: String,
}

/// One contest of the published result.
#[derive(Clone, Debug)]
pub struct ContestView {
    pub index: u64,
    pub name: String,
    /// `(option name, votes)` in option order.
    pub options: Vec<(String, u64)>,
    pub counted: u64,
    pub invalid: u64,
    pub excluded: u64,
    /// `(candidate name, party name)` of the elected candidates, for a
    /// proportional contest.
    pub seats: Option<Vec<(String, String)>>,
}

/// The published result.
#[derive(Clone, Debug)]
pub struct ResultView {
    pub contests: Vec<ContestView>,
    /// `(section id, the pre-BU fingerprint matches the recomputed tally)`.
    pub sections: Vec<(String, bool)>,
}

/// Voter lookup by short code (§17.5).
#[derive(Clone, Debug)]
pub struct LookupView {
    pub found: bool,
    pub entry_index: Option<u64>,
    /// "cast", "spoiled" or "abandoned".
    pub status: Option<String>,
    pub machine_id: Option<String>,
    /// The inclusion proof of the entry verifies against the latest STH.
    pub inclusion_proof_verifies: bool,
    /// `(contest index, counted?)`. `None` until the tally has run.
    pub contests_counted: Vec<(u64, Option<bool>)>,
}

/// Result of an independent spoil check (§14.2).
#[derive(Clone, Debug)]
pub struct SpoilCheck {
    pub ok: bool,
    pub message: String,
    pub claimed: Vec<ContestPlain>,
}

/// A voting session that the driver keeps for one machine.
struct MachineState {
    session: Session<'static>,
    machine_sk: SigningKey,
    machine_pk: VerifyingKey,
    section_id: String,
    session_id: String,
    /// The poll worker that authorizes voters and cancels authorizations.
    pw: SigningKey,
    /// True while an authorization is journaled and is neither cast nor cancelled.
    authorized: bool,
    /// The ballot in progress.
    pending: Option<Pending>,
    cast: u64,
    spoiled: u64,
    abandoned: u64,
    open: bool,
}

/// The ballot in progress: its tracking code and the voter's real choices.
struct Pending {
    code: [u8; 32],
    voter: Vec<ContestPlain>,
}

/// A ballot committed in a package on the board.
struct Found {
    entry_index: u64,
    machine_id: String,
    code: [u8; 32],
    /// "pending", "cast", "spoiled" or "abandoned".
    status: &'static str,
    ballot: Ballot,
}

/// The secret material the trustees need, for the authority pipeline.
struct Trustees<'a> {
    keys: &'a Keys,
    /// `zs[j-1]` is the secret share z_j of trustee j.
    zs: &'a [Scalar],
    attacks: &'a Attacks,
}

/// The post-election pipeline, computed from the board before the EA signs.
struct Pipeline {
    /// Records to post, in order, before the result.
    posted: Vec<Value>,
    result: ElectionResult,
}

/// One election, played step by step.
pub struct Simulation {
    rng: ChaCha20Rng,
    manifest: &'static Manifest,
    keys: Keys,
    registry: &'static Registry,
    log: Log,
    context: Option<&'static Context>,
    /// `trustee_shares[j-1]` is z_j.
    trustee_shares: Vec<Scalar>,
    /// Starts with the ceremony, since the ingester needs the context hash.
    board: Option<BoardState<'static>>,
    /// Sessions by machine id. A new session replaces a closed one.
    sessions: BTreeMap<String, MachineState>,
    /// Number of sessions opened on each machine.
    session_count: BTreeMap<String, u64>,
    slips: Vec<SlipView>,
    spoils: Vec<SpoilView>,
    /// Every STH signed so far, in order.
    sths: Vec<Value>,
    /// The result as the authority pipeline computes it, before any EA alteration.
    recount: Option<ElectionResult>,
    attacks: Attacks,
    phase: Phase,
    /// Logical time of the simulation, one tick per record.
    clock: u64,
}

impl Simulation {
    /// Samples the manifest, keys and registry from `seed`, and posts the
    /// signed manifest.
    pub fn new(seed: u64) -> Simulation {
        let (manifest, keys) = fixtures::sample_manifest(seed);
        let manifest: &'static Manifest = Box::leak(Box::new(manifest));
        let registry: &'static Registry =
            Box::leak(Box::new(fixtures::sample_registry(manifest, &keys)));
        let mut log = Log::new();
        log.append(sign_manifest(manifest, &keys.ea));
        Simulation {
            rng: ChaCha20Rng::seed_from_u64(seed),
            manifest,
            keys,
            registry,
            log,
            context: None,
            trustee_shares: Vec::new(),
            board: None,
            sessions: BTreeMap::new(),
            session_count: BTreeMap::new(),
            slips: Vec::new(),
            spoils: Vec::new(),
            sths: Vec::new(),
            recount: None,
            attacks: Attacks::default(),
            phase: Phase::Setup,
            clock: 0,
        }
    }

    pub fn manifest(&self) -> &Manifest {
        self.manifest
    }

    pub fn registry(&self) -> &Registry {
        self.registry
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The board, in order.
    pub fn entries(&self) -> &[Value] {
        self.log.entries()
    }

    /// One summary per board entry.
    pub fn entry_summaries(&self) -> Vec<EntrySummary> {
        self.log
            .entries()
            .iter()
            .enumerate()
            .map(|(i, e)| EntrySummary {
                index: i as u64,
                kind: entry_tag(e).unwrap_or("?").to_owned(),
                detail: self.describe(e),
                leaf_hash_hex: hex(&leaf_hash(e)),
            })
            .collect()
    }

    /// Runs the DKG with the three trustees, posting the round records, and
    /// derives the context with [`verify_ceremony`].
    pub fn run_ceremony(&mut self) -> Result<CeremonyReport, Error> {
        self.expect_phase(Phase::Setup)?;
        let manifest = self.manifest;
        let set = &manifest.trustees;
        let mh = manifest.hash();
        let n = set.n();
        let k = set.k as usize;

        let polys: Vec<Polynomial> = (0..n)
            .map(|_| Polynomial::random(&mut self.rng, k))
            .collect();

        let mut round1 = Vec::new();
        let mut round2 = Vec::new();
        for i in 1..=n {
            let poly = &polys[(i - 1) as usize];
            round1.push(Round1::new(&mut self.rng, &mh, i, poly));
            let mut r2 = Round2::new(&mut self.rng, &mh, i, poly, set);
            if self.attacks.bad_dkg_share && i == 1 {
                // Trustee 1 sends trustee 2 a share that its commitments reject.
                let bad = poly.eval(2) + Scalar::ONE;
                let recipient = set
                    .get(2)
                    .ok_or_else(|| sim_err("trustee 2 is not in the set"))?;
                let forged = encrypt_share(&mut self.rng, &recipient.hpke_key, &mh, 1, 2, &bad);
                if let Some(slot) = r2.shares.iter_mut().find(|s| s.recipient == 2) {
                    *slot = forged;
                }
            }
            round2.push(r2);
        }

        let mut published = Published {
            round1: round1
                .iter()
                .enumerate()
                .map(|(i, r)| r.sign(&self.keys.trustee_sig[i]))
                .collect(),
            round2: round2
                .iter()
                .enumerate()
                .map(|(i, r)| r.sign(&self.keys.trustee_sig[i]))
                .collect(),
            round3: Vec::new(),
            complaints: Vec::new(),
            reveals: Vec::new(),
        };

        let mut complaint_text = Vec::new();
        for j in 1..=n {
            let jdx = (j - 1) as usize;
            let outcome = process_shares(
                &mh,
                j,
                &polys[jdx],
                &self.keys.trustee_hpke[jdx],
                &round1,
                &round2,
            );
            if let ShareOutcome::Complain { accused } = outcome {
                for i in accused {
                    let idx = (i - 1) as usize;
                    published.complaints.push(
                        Complaint {
                            manifest_hash: mh,
                            j,
                            i,
                        }
                        .sign(&self.keys.trustee_sig[jdx]),
                    );
                    let share = polys[idx].eval(j);
                    published.reveals.push(
                        ceremony::Reveal {
                            manifest_hash: mh,
                            i,
                            j,
                            share,
                        }
                        .sign(&self.keys.trustee_sig[idx]),
                    );
                    complaint_text.push(format!(
                        "trustee {j} complained about trustee {i}; trustee {i} revealed its share"
                    ));
                }
            }
        }

        let transcript = transcript_hash(&mh, &published.round1, &published.round2);
        published.round3 = (1..=n)
            .map(|j| {
                Round3 {
                    manifest_hash: mh,
                    j,
                    transcript_hash: transcript,
                }
                .sign(&self.keys.trustee_sig[(j - 1) as usize])
            })
            .collect();

        // z_j = P_j(j) + the shares received from every other trustee.
        let zs: Vec<Scalar> = (1..=n)
            .map(|j| {
                let received: Vec<Scalar> = (1..=n)
                    .filter(|&i| i != j)
                    .map(|i| polys[(i - 1) as usize].eval(j))
                    .collect();
                secret_share(&polys[(j - 1) as usize], j, &received)
            })
            .collect();

        let context = verify_ceremony(&mh, set, &published)?;
        for (idx, z) in zs.iter().enumerate() {
            let expected = *z * B;
            if context.z.get(idx) != Some(&expected) {
                return Err(Error::Ceremony(format!(
                    "the secret share of trustee {} does not match Z_{}",
                    idx + 1,
                    idx + 1
                )));
            }
        }
        let context: &'static Context = Box::leak(Box::new(context));

        // The ceremony is accepted: its records go on the board.
        let ceremony_records = published
            .round1
            .iter()
            .chain(&published.round2)
            .chain(&published.complaints)
            .chain(&published.reveals)
            .chain(&published.round3);
        for v in ceremony_records {
            self.log.append(v.clone());
        }
        let mut board = BoardState::new(manifest, context);
        for entry in self.log.entries() {
            board.ingest(entry);
        }
        self.board = Some(board);
        self.context = Some(context);
        self.trustee_shares = zs;
        self.phase = Phase::CeremonyDone;

        Ok(CeremonyReport {
            trustees: set
                .trustees
                .iter()
                .map(|t| (t.index, t.name.clone(), t.bloc.clone()))
                .collect(),
            k: set.k,
            n,
            complaints: complaint_text,
            context_hash_hex: hex(&context.hash()),
            joint_key_hex: hex(context.k.compress().as_bytes()),
        })
    }

    /// Posts the signed registry and `polls_open`.
    pub fn open_polls(&mut self) -> Result<(), Error> {
        self.expect_phase(Phase::CeremonyDone)?;
        let context = self.context()?;
        let registry = sign_registry(self.registry, &self.keys.ea);
        let registry_id = record_id(&registry);
        self.post(registry)?;
        let time = self.next_time();
        let polls = PollsOpen {
            context_hash: context.hash(),
            registry_id,
            time,
        }
        .sign(&self.keys.ea);
        self.post(polls)?;
        self.phase = Phase::PollsOpen;
        Ok(())
    }

    /// Opens a session on a machine. A reserve machine (empty section in the
    /// registry) needs `section`. The first poll worker of the section signs the
    /// zerésima.
    pub fn open_session(
        &mut self,
        machine_id: &str,
        section: Option<&str>,
    ) -> Result<ZeresimaView, Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let context = self.context()?;
        let manifest = self.manifest;
        let registry = self.registry;
        let entry = registry
            .machines
            .iter()
            .find(|m| m.machine_id == machine_id)
            .ok_or_else(|| sim_err(format!("no machine {machine_id:?} in the registry")))?;
        let section_id = match (entry.section_id.is_empty(), section) {
            (false, Some(s)) if s != entry.section_id.as_str() => {
                return Err(sim_err(format!(
                    "machine {machine_id:?} serves section {:?}, not {s:?}",
                    entry.section_id
                )))
            }
            (false, _) => entry.section_id.clone(),
            (true, Some(s)) => s.to_owned(),
            (true, None) => {
                return Err(sim_err(
                    "a reserve machine needs the section it stands in for",
                ))
            }
        };
        if self.sessions.get(machine_id).is_some_and(|s| s.open) {
            return Err(sim_err(format!(
                "machine {machine_id:?} already has an open session"
            )));
        }
        let section_entry = registry
            .sections
            .iter()
            .find(|s| s.section_id == section_id)
            .ok_or_else(|| sim_err(format!("section {section_id:?} is not in the registry")))?;
        let pw_key = section_entry
            .poll_worker_keys
            .first()
            .ok_or_else(|| sim_err("the section has no poll worker"))?;
        let pw = find_key(&self.keys.poll_workers, pw_key)
            .ok_or_else(|| sim_err("no secret key for the poll worker"))?;
        let machine_sk = find_key(&self.keys.machines, &entry.key)
            .ok_or_else(|| sim_err("no secret key for the machine"))?;
        let approved = manifest
            .software_policy
            .approved_hashes
            .first()
            .copied()
            .ok_or_else(|| sim_err("the software policy approves nothing"))?;

        let number = self.session_count.get(machine_id).copied().unwrap_or(0) + 1;
        let session_id = format!("{machine_id}-{number}");
        let cfg = MachineConfig {
            election: Election {
                context_hash: context.hash(),
                k: context.k,
                manifest,
            },
            registry,
            machine_id: machine_id.to_owned(),
            machine_sk: machine_sk.clone(),
            measurement: Measurement(approved),
        };
        let mut challenge = [0u8; 16];
        self.rng.fill_bytes(&mut challenge);
        let opened_at = self.next_time();
        let (mut session, zeresima) =
            Session::open(cfg, &section_id, &session_id, opened_at, challenge)?;
        session.sign_zeresima(vec![SectionSig::create(&pw, &zeresima)])?;

        let contests = entry
            .contests
            .iter()
            .map(|&c| -> Result<(u64, String, Vec<String>), Error> {
                let contest = manifest
                    .contest(c)
                    .ok_or_else(|| sim_err(format!("unknown contest {c}")))?;
                Ok((
                    c,
                    contest.name.clone(),
                    contest.options.iter().map(|o| o.name.clone()).collect(),
                ))
            })
            .collect::<Result<_, Error>>()?;
        let view = ZeresimaView {
            machine_id: machine_id.to_owned(),
            section_id: section_id.clone(),
            session_id: session_id.clone(),
            measurement_hex: hex(&approved),
            head0_hex: hex(&session.head()),
            contests,
        };
        self.session_count.insert(machine_id.to_owned(), number);
        self.sessions.insert(
            machine_id.to_owned(),
            MachineState {
                session,
                machine_sk,
                machine_pk: entry.key,
                section_id,
                session_id,
                pw,
                authorized: false,
                pending: None,
                cast: 0,
                spoiled: 0,
                abandoned: 0,
                open: true,
            },
        );
        Ok(view)
    }

    /// The poll worker authorizes the next voter on the machine. Returns the
    /// `auth_seq` of the authorization.
    pub fn authorize(&mut self, machine_id: &str) -> Result<u64, Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let context_hash = self.context()?.hash();
        let state = self.open_state(machine_id)?;
        let seq = state.session.next_auth_seq();
        let sig = auth_signature(&state.pw, &context_hash, machine_id, &state.session_id, seq);
        let seq = state.session.authorize(state.pw.verifying_key(), sig)?;
        state.authorized = true;
        Ok(seq)
    }

    /// The machine encrypts the voter's choices, one entry per offered contest,
    /// ascending. Returns the full code (hex) and the short code. With
    /// `machine_flips_votes`, the machine encrypts a different choice for contest 0.
    pub fn encrypt(
        &mut self,
        machine_id: &str,
        choices: Vec<ContestPlain>,
    ) -> Result<(String, String), Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let machine_choices = if self.attacks.machine_flips_votes {
            flip_contest_zero(self.manifest, &choices)
        } else {
            choices.clone()
        };
        let state = self
            .sessions
            .get_mut(machine_id)
            .filter(|s| s.open)
            .ok_or_else(|| no_open_session(machine_id))?;
        let code = state.session.encrypt(&mut self.rng, machine_choices)?;
        state.pending = Some(Pending {
            code,
            voter: choices,
        });
        Ok((hex(&code), short_code(&code)))
    }

    /// Casts the pending ballot and returns the signed slip.
    pub fn cast(&mut self, machine_id: &str) -> Result<SlipView, Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let state = self.open_state(machine_id)?;
        let code = state
            .pending
            .as_ref()
            .map(|p| p.code)
            .ok_or_else(|| sim_err("no ballot is pending on this machine"))?;
        let slip = state.session.cast()?;
        state.pending = None;
        state.authorized = false;
        state.cast += 1;
        let view = SlipView {
            short_code: short_code(&code),
            code_hex: hex(&code),
            machine_id: machine_id.to_owned(),
            slip,
        };
        self.slips.push(view.clone());
        Ok(view)
    }

    /// Spoils the pending ballot. The authorization stays unused.
    pub fn spoil(&mut self, machine_id: &str) -> Result<SpoilView, Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let flip = self.attacks.machine_flips_votes;
        let state = self.open_state(machine_id)?;
        let (code, voter) = state
            .pending
            .as_ref()
            .map(|p| (p.code, p.voter.clone()))
            .ok_or_else(|| sim_err("no ballot is pending on this machine"))?;
        let honest = state.session.spoil()?;
        let receipt = if flip {
            // The lying machine signs a receipt that claims the voter's choices.
            let mut forged = SpoilReceipt::from_signed(&honest, &state.machine_pk)?;
            forged.reveal.selections = voter.clone();
            forged.sign(&state.machine_sk)
        } else {
            honest
        };
        state.pending = None;
        state.spoiled += 1;
        let view = SpoilView {
            short_code: short_code(&code),
            receipt,
            claimed: voter,
        };
        self.spoils.push(view.clone());
        Ok(view)
    }

    /// Abandons the pending ballot without revealing it.
    pub fn abandon(&mut self, machine_id: &str) -> Result<(), Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let state = self.open_state(machine_id)?;
        if state.pending.is_none() {
            return Err(sim_err("no ballot is pending on this machine"));
        }
        state.session.abandon()?;
        state.pending = None;
        state.abandoned += 1;
        Ok(())
    }

    /// Closes a session. Cancels the unused authorization (if any), signs the
    /// pre-BU, closes the journal and posts the package. Unless
    /// `board_drops_package_of` names the machine, the package is ingested by the
    /// board. A second poll worker then posts a section attestation of the pre-BU.
    pub fn close_session(&mut self, machine_id: &str) -> Result<PreBuView, Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let ctx_hash = self.context()?.hash();
        let registry = self.registry;
        let closed_at = self.next_time();
        let state = self.open_state(machine_id)?;
        if state.pending.is_some() {
            return Err(sim_err(
                "a ballot is pending: cast, spoil or abandon it first",
            ));
        }
        if state.authorized {
            let seq = state.session.next_auth_seq() - 1;
            let sig =
                auth_cancel_signature(&state.pw, &ctx_hash, machine_id, &state.session_id, seq);
            state
                .session
                .cancel_authorization(state.pw.verifying_key(), sig)?;
            state.authorized = false;
        }
        let roll_count = state.cast;
        let pre_bu = state.session.prepare_pre_bu(roll_count)?;
        state
            .session
            .sign_pre_bu(vec![SectionSig::create(&state.pw, &pre_bu)])?;
        let package = state.session.close(closed_at)?;
        state.open = false;
        let machine_pk = state.machine_pk;
        let section_id = state.section_id.clone();

        let pb = PreBu::from_signed(&pre_bu, &machine_pk)?;
        let view = PreBuView {
            machine_id: machine_id.to_owned(),
            section_id: section_id.clone(),
            cast: pb.cast,
            spoiled: pb.spoiled,
            abandoned: pb.abandoned,
            fingerprint: grouped(&pb.fingerprint),
            chain_head_hex: hex(&pb.chain_head),
        };

        if self.attacks.board_drops_package_of.as_deref() != Some(machine_id) {
            self.post(package)?;
        }
        let second = second_poll_worker(registry, self.keys.poll_workers.as_slice(), &section_id)?;
        let attestation = SectionAttestation::create(&second, &pre_bu).to_value();
        self.post(attestation)?;
        Ok(view)
    }

    /// Closes any open sessions and posts `tally_cutoff`.
    pub fn cutoff(&mut self) -> Result<(), Error> {
        self.expect_phase(Phase::PollsOpen)?;
        let open: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.open)
            .map(|(id, _)| id.clone())
            .collect();
        for machine_id in open {
            self.close_session(&machine_id)?;
        }
        let context = self.context()?;
        let time = self.next_time();
        let cutoff = TallyCutoff {
            context_hash: context.hash(),
            time,
        }
        .sign(&self.keys.ea);
        self.post(cutoff)?;
        self.phase = Phase::PollsClosed;
        Ok(())
    }

    /// Runs the authority pipeline on the board up to the cutoff, posts its
    /// records and the signed result, and returns the published result.
    pub fn tally(&mut self) -> Result<ResultView, Error> {
        self.expect_phase(Phase::PollsClosed)?;
        let context = self.context()?;
        let manifest = self.manifest;
        let cutoff = self
            .cutoff_index()
            .ok_or_else(|| sim_err("the board has no tally_cutoff"))?;
        // The STH root at tally_cutoff is the root of the log up to that entry.
        let sth_root = self.log.root_at(cutoff + 1);
        let trustees = Trustees {
            keys: &self.keys,
            zs: &self.trustee_shares,
            attacks: &self.attacks,
        };
        let pipeline = run_pipeline(
            &mut self.rng,
            manifest,
            context,
            &trustees,
            self.log.entries(),
            sth_root,
        )?;
        for value in pipeline.posted {
            self.post(value)?;
        }

        let honest = pipeline.result;
        let mut published = honest.clone();
        if self.attacks.ea_alters_result {
            if let Some(c) = published.contests.iter_mut().find(|c| c.contest == 0) {
                if let Some(v) = c.votes.first_mut() {
                    *v += 100;
                    c.counted += 100;
                }
            }
        }
        let signed = published.sign(&self.keys.ea);
        self.post(signed.clone())?;
        let verified = ElectionResult::from_signed(&signed, &manifest.ea_key, manifest)?;
        let view = result_view(manifest, &verified);
        self.recount = Some(honest);
        self.phase = Phase::Tallied;
        Ok(view)
    }

    /// Signs an STH at the current size. Returns the new STHs. With
    /// `board_equivocates`, the second and later calls also return a conflicting
    /// STH: the same size, over a log whose last entry is altered.
    pub fn sign_sth(&mut self) -> Vec<Value> {
        let size = self.log.len();
        let manifest_hash = self.manifest.hash();
        let timestamp = self.next_time();
        let honest = Sth {
            manifest_hash,
            size,
            root: self.log.root(),
            timestamp,
        }
        .sign(&self.keys.board);
        let mut out = vec![honest];
        if self.attacks.board_equivocates && !self.sths.is_empty() && size > 0 {
            let mut altered = Log::new();
            let last = size as usize - 1;
            for (i, entry) in self.log.entries().iter().enumerate() {
                if i == last {
                    altered.append(Value::from("altered by the board"));
                } else {
                    altered.append(entry.clone());
                }
            }
            out.push(
                Sth {
                    manifest_hash,
                    size,
                    root: altered.root(),
                    timestamp,
                }
                .sign(&self.keys.board),
            );
        }
        self.sths.extend(out.iter().cloned());
        out
    }

    /// Every STH signed so far, in order.
    pub fn sths(&self) -> &[Value] {
        &self.sths
    }

    /// Every slip cast so far.
    pub fn slips(&self) -> &[SlipView] {
        &self.slips
    }

    /// Every spoil receipt issued so far.
    pub fn spoils(&self) -> &[SpoilView] {
        &self.spoils
    }

    /// The result as the authority pipeline recomputes it from the board, before
    /// any EA alteration. Set by [`Simulation::tally`].
    pub fn recount(&self) -> Option<&ElectionResult> {
        self.recount.as_ref()
    }

    /// Voter lookup. Finds the ballot with the short code and checks that its
    /// package is on the board under the latest STH.
    pub fn lookup(&self, text: &str) -> Result<LookupView, Error> {
        let short = parse_short_code(text).ok_or_else(|| sim_err("not a short code"))?;
        let Some(hit) = self
            .ballots_on_board()
            .into_iter()
            .find(|f| short_code_matches(&f.code, &short))
        else {
            return Ok(LookupView {
                found: false,
                entry_index: None,
                status: None,
                machine_id: None,
                inclusion_proof_verifies: false,
                contests_counted: Vec::new(),
            });
        };
        Ok(LookupView {
            found: true,
            entry_index: Some(hit.entry_index),
            status: Some(hit.status.to_owned()),
            machine_id: Some(hit.machine_id.clone()),
            inclusion_proof_verifies: self.inclusion_ok(hit.entry_index),
            contests_counted: self.counted_in(&hit)?,
        })
    }

    /// Independent spoil check (§14.2): finds the committed ballot on the
    /// board, checks the receipt signature and re-encrypts the claim.
    pub fn check_spoil(&self, receipt: &Value) -> Result<SpoilCheck, Error> {
        let machine_id = receipt
            .get(3)?
            .and_then(|v| v.as_text().ok())
            .ok_or_else(|| sim_err("not a spoil receipt"))?
            .to_owned();
        let fail = |message: String| SpoilCheck {
            ok: false,
            message,
            claimed: Vec::new(),
        };
        let Some(machine) = self.registry.machine(&machine_id) else {
            return Ok(fail(format!("machine {machine_id:?} is not registered")));
        };
        let spoil = match SpoilReceipt::from_signed(receipt, &machine.key) {
            Ok(s) => s,
            Err(e) => return Ok(fail(format!("the receipt does not verify: {e}"))),
        };
        let Some(hit) = self
            .ballots_on_board()
            .into_iter()
            .find(|f| f.code == spoil.code)
        else {
            return Ok(fail(
                "no committed ballot with this code is on the board".to_owned(),
            ));
        };
        if hit.status != "spoiled" {
            return Ok(fail(format!(
                "the ballot on the board is {}, not spoiled",
                hit.status
            )));
        }
        let context = self.context()?;
        let election = Election {
            context_hash: context.hash(),
            k: context.k,
            manifest: self.manifest,
        };
        let claimed = spoil.reveal.selections.clone();
        Ok(
            match check_reveal(&election, &hit.ballot, &spoil.reveal.rho, &claimed) {
                Ok(()) => SpoilCheck {
                    ok: true,
                    message: "the ballot re-encrypts exactly as the receipt claims".to_owned(),
                    claimed,
                },
                Err(reason) => SpoilCheck {
                    ok: false,
                    message: reason,
                    claimed,
                },
            },
        )
    }

    pub fn attacks_mut(&mut self) -> &mut Attacks {
        &mut self.attacks
    }

    /// Casts `n` random valid ballots on a machine: authorize, encrypt and cast.
    pub fn cast_random(&mut self, machine_id: &str, n: usize) -> Result<(), Error> {
        for _ in 0..n {
            self.vote(machine_id, false)?;
        }
        Ok(())
    }

    /// Runs a full default election. Runs the ceremony, opens the polls, opens
    /// a session on every regular machine, casts 4 random ballots and 1 spoil on
    /// each, closes all sessions, cuts off, tallies and signs an STH.
    pub fn run_all(&mut self) -> Result<ResultView, Error> {
        self.run_ceremony()?;
        self.open_polls()?;
        let machines: Vec<String> = self
            .registry
            .machines
            .iter()
            .filter(|m| !m.section_id.is_empty())
            .map(|m| m.machine_id.clone())
            .collect();
        for machine_id in &machines {
            self.open_session(machine_id, None)?;
            self.vote(machine_id, true)?;
            self.cast_random(machine_id, 3)?;
        }
        for machine_id in &machines {
            self.close_session(machine_id)?;
        }
        self.cutoff()?;
        let view = self.tally()?;
        self.sign_sth();
        Ok(view)
    }

    /// Random valid choices for the contests a machine offers. Single and
    /// proportional contests get one option. Multi contests get up to L candidate
    /// options. A candidate already chosen in a linked contest is not chosen
    /// again (§12.6 link groups).
    pub fn random_choices(&mut self, machine_id: &str) -> Vec<ContestPlain> {
        let manifest = self.manifest;
        let registry = self.registry;
        let Some(machine) = registry.machine(machine_id) else {
            return Vec::new();
        };
        let rng = &mut self.rng;
        let mut out: Vec<ContestPlain> = Vec::new();
        for contest in machine.contests.iter().filter_map(|&c| manifest.contest(c)) {
            let forbidden = linked_candidates(manifest, contest.index, &out);
            let is_free = |o: &crate::manifest::BallotOption| {
                !(o.kind == OptionKind::Candidate && forbidden.contains(&o.index))
            };
            let selected = match contest.kind {
                ContestKind::Multi => {
                    let mut candidates: Vec<u64> = contest
                        .options
                        .iter()
                        .filter(|o| o.kind == OptionKind::Candidate && is_free(o))
                        .map(|o| o.index)
                        .collect();
                    let count = (below(rng, contest.limit + 1) as usize).min(candidates.len());
                    for i in 0..count {
                        let j = i + below(rng, (candidates.len() - i) as u64) as usize;
                        candidates.swap(i, j);
                    }
                    let mut chosen = candidates[..count].to_vec();
                    chosen.sort_unstable();
                    chosen
                }
                _ => {
                    let allowed: Vec<u64> = contest
                        .options
                        .iter()
                        .filter(|o| is_free(o))
                        .map(|o| o.index)
                        .collect();
                    if allowed.is_empty() {
                        Vec::new()
                    } else {
                        let pick = below(rng, allowed.len() as u64) as usize;
                        vec![allowed[pick]]
                    }
                }
            };
            out.push(ContestPlain {
                contest: contest.index,
                selected,
            });
        }
        out
    }

    // -- internals ---------------------------------------------------------

    /// One full vote on a machine. With `spoil_first`, the voter first spoils a
    /// ballot under the same authorization.
    fn vote(&mut self, machine_id: &str, spoil_first: bool) -> Result<(), Error> {
        self.authorize(machine_id)?;
        let choices = self.random_choices(machine_id);
        if spoil_first {
            self.encrypt(machine_id, choices.clone())?;
            self.spoil(machine_id)?;
        }
        self.encrypt(machine_id, choices)?;
        self.cast(machine_id)?;
        Ok(())
    }

    fn expect_phase(&self, want: Phase) -> Result<(), Error> {
        if self.phase == want {
            Ok(())
        } else {
            Err(sim_err(format!(
                "this step needs phase {want:?}, but the election is in {:?}",
                self.phase
            )))
        }
    }

    fn context(&self) -> Result<&'static Context, Error> {
        self.context
            .ok_or_else(|| sim_err("the ceremony has not run"))
    }

    fn next_time(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn open_state(&mut self, machine_id: &str) -> Result<&mut MachineState, Error> {
        self.sessions
            .get_mut(machine_id)
            .filter(|s| s.open)
            .ok_or_else(|| no_open_session(machine_id))
    }

    /// Index of the accepted `tally_cutoff` entry.
    fn cutoff_index(&self) -> Option<u64> {
        self.log
            .entries()
            .iter()
            .position(|e| entry_tag(e) == Some("tally_cutoff"))
            .map(|i| i as u64)
    }

    /// Feeds an entry to the board and appends it to the log. A refused entry
    /// stays on the log, and a board-signed `rejection` follows it.
    fn post(&mut self, entry: Value) -> Result<(), Error> {
        let board = self
            .board
            .as_mut()
            .ok_or_else(|| sim_err("the board opens with the ceremony"))?;
        let verdict = board.ingest(&entry);
        let id = record_id(&entry);
        self.log.append(entry);
        if let Ingest::Rejected(reason) = verdict {
            let rejection = Rejection {
                package_id: id,
                reason,
            }
            .sign(&self.keys.board);
            self.post(rejection)?;
        }
        Ok(())
    }

    /// The latest STH: the largest size, the first one signed at that size.
    fn latest_sth(&self) -> Option<Sth> {
        let board_pk = self.keys.board.verifying_key();
        let mut best: Option<Sth> = None;
        for v in &self.sths {
            if let Ok(sth) = Sth::from_signed(v, &board_pk) {
                let better = match &best {
                    None => true,
                    Some(b) => sth.size > b.size,
                };
                if better {
                    best = Some(sth);
                }
            }
        }
        best
    }

    fn inclusion_ok(&self, index: u64) -> bool {
        let Some(sth) = self.latest_sth() else {
            return false;
        };
        let Some(entry) = self.log.entry(index) else {
            return false;
        };
        if index >= sth.size {
            return false;
        }
        match self.log.inclusion_proof(index, sth.size) {
            Some(proof) => verify_inclusion(&leaf_hash(entry), index, sth.size, &proof, &sth.root),
            None => false,
        }
    }

    /// Whether each contest offered to the ballot's machine counted it, from the
    /// tally. `None` before the tally has run.
    fn counted_in(&self, hit: &Found) -> Result<Vec<(u64, Option<bool>)>, Error> {
        let machine = self
            .registry
            .machine(&hit.machine_id)
            .ok_or_else(|| sim_err("the machine of the ballot is not registered"))?;
        let offered: Vec<u64> = machine.contests.clone();
        if self.phase != Phase::Tallied {
            return Ok(offered.iter().map(|&c| (c, None)).collect());
        }
        let all_false =
            || -> Vec<(u64, Option<bool>)> { offered.iter().map(|&c| (c, Some(false))).collect() };
        if hit.status != "cast" {
            return Ok(all_false());
        }
        let context = self.context()?;
        let view = authority::board_view(self.manifest, context, self.log.entries())?;
        let judged = view
            .packages
            .iter()
            .find(|p| p.entry_index == hit.entry_index)
            .and_then(|p| p.cast.iter().find(|(b, _)| b.id == hit.ballot.id))
            .map(|(_, j)| j);
        Ok(match judged {
            Some(j) if j.well_formed.is_ok() => j
                .contests
                .iter()
                .map(|(c, s)| (*c, Some(matches!(s, ContestStatus::Counted))))
                .collect(),
            _ => all_false(),
        })
    }

    /// Every committed ballot in a package on the board, with its status.
    fn ballots_on_board(&self) -> Vec<Found> {
        let mut out: Vec<Found> = Vec::new();
        for (i, entry) in self.log.entries().iter().enumerate() {
            if entry_tag(entry) != Some("package") {
                continue;
            }
            let machine_id = match entry.get(2).ok().flatten().map(PackageHeader::from_value) {
                Some(Ok(header)) => header.machine_id,
                _ => continue,
            };
            let Some(machine) = self.registry.machine(&machine_id) else {
                continue;
            };
            let Ok(package) = Package::from_signed(entry, &machine.key) else {
                continue;
            };
            for rec in &package.records {
                match rec {
                    Record::Committed { ballot, code } => out.push(Found {
                        entry_index: i as u64,
                        machine_id: machine_id.clone(),
                        code: *code,
                        status: "pending",
                        ballot: ballot.clone(),
                    }),
                    Record::Cast { code } => set_status(&mut out, code, "cast"),
                    Record::Spoiled { code, .. } => set_status(&mut out, code, "spoiled"),
                    Record::Abandoned { code } => set_status(&mut out, code, "abandoned"),
                    _ => {}
                }
            }
        }
        out
    }

    /// A one-line description of a board entry, for display.
    fn describe(&self, entry: &Value) -> String {
        let board_pk = self.keys.board.verifying_key();
        match entry_tag(entry).unwrap_or("") {
            "package" => match entry.get(2).ok().flatten().map(PackageHeader::from_value) {
                Some(Ok(header)) => {
                    let cast = self
                        .registry
                        .machine(&header.machine_id)
                        .and_then(|m| Package::from_signed(entry, &m.key).ok())
                        .map(|p| {
                            p.records
                                .iter()
                                .filter(|r| matches!(r, Record::Cast { .. }))
                                .count()
                        });
                    match cast {
                        Some(n) => format!(
                            "machine {} session {}: {n} cast",
                            header.machine_id, header.session_id
                        ),
                        None => format!("package of machine {}", header.machine_id),
                    }
                }
                _ => "package".to_owned(),
            },
            "section_attestation" => match SectionAttestation::from_value(entry) {
                Ok(att) => {
                    let record_tag = field_text(&att.record, 0);
                    let machine = field_text(&att.record, 3);
                    format!("attests the {record_tag} of machine {machine}")
                }
                Err(_) => "section attestation".to_owned(),
            },
            "rejection" => match Rejection::from_signed(entry, &board_pk) {
                Ok(r) => format!("refused an entry: {}", r.reason),
                Err(_) => "rejection".to_owned(),
            },
            "sth" => match Sth::from_signed(entry, &board_pk) {
                Ok(s) => format!("tree of size {}", s.size),
                Err(_) => "sth".to_owned(),
            },
            _ => String::new(),
        }
    }
}

/// The authority pipeline of §16 to §21, run on the board up to the cutoff.
fn run_pipeline(
    rng: &mut ChaCha20Rng,
    manifest: &Manifest,
    context: &Context,
    trustees: &Trustees,
    entries: &[Value],
    sth_root: [u8; 32],
) -> Result<Pipeline, Error> {
    let view = authority::board_view(manifest, context, entries)?;
    let sections = authority::section_tallies(&view);
    let pool = authority::pool_tally(&view, &sections);
    let index = authority::encrypted_tally(&view, &sections, &pool, sth_root);
    let mut posted: Vec<Value> = sections.iter().map(|(st, _, _)| st.to_value()).collect();
    posted.push(pool.to_value());
    posted.push(index.to_value());

    let k = manifest.trustees.k;
    let mut final_bus = Vec::new();
    for (st, _, _) in &sections {
        if section_tally_items(st).is_empty() {
            continue;
        }
        let sets = trustee_sets(
            rng,
            &view,
            &sections,
            &Target::Section(st.clone()),
            trustees,
        )?;
        let fb = authority::final_bu(&view, st, &sets)?;
        posted.extend(sets);
        let fb_value = fb.to_value();
        let id = record_id(&fb_value);
        posted.push(fb_value);
        final_bus.push((fb, id));
    }

    let pool_target = Target::Pool(pool.clone());
    let pool_share_sets = if pool_target.items().is_empty() {
        Vec::new()
    } else {
        let sets = trustee_sets(rng, &view, &sections, &pool_target, trustees)?;
        posted.extend(sets.iter().cloned());
        sets
    };

    let mut mix = Vec::new();
    for (unit, rows) in authority::mix_plan(&view) {
        if rows.is_empty() {
            continue;
        }
        // Trustees 1 to k mix, in order.
        let mixers: Vec<(u64, &SigningKey)> = (1..=k)
            .map(|j| (j, &trustees.keys.trustee_sig[(j - 1) as usize]))
            .collect();
        let chain = run_mix_chain(rng, context, &unit, &rows, &mixers);
        let outputs: Vec<MixOutput> = chain.iter().map(|(_, mo)| mo.clone()).collect();
        posted.extend(chain.iter().map(|(v, _)| v.clone()));
        let last_output_value = chain
            .last()
            .map(|(v, _)| v.clone())
            .ok_or_else(|| sim_err("a unit with rows has no mix step"))?;
        let target = Target::MixFinal {
            unit: unit.clone(),
            input: rows,
            outputs: outputs.clone(),
            last_output_value,
        };
        let sets = trustee_sets(rng, &view, &sections, &target, trustees)?;
        posted.extend(sets.iter().cloned());
        mix.push((unit, outputs, sets));
    }

    let inputs = TallyInputs {
        final_bus,
        pool_share_sets,
        mix,
    };
    let result = authority::election_result(&view, &sections, &pool, &inputs)?;
    Ok(Pipeline { posted, result })
}

/// Every trustee signs a share set for `target`. Trustee 3 corrupts its sets
/// with `trustee_lies`.
fn trustee_sets(
    rng: &mut ChaCha20Rng,
    view: &BoardView,
    sections: &Sections,
    target: &Target,
    trustees: &Trustees,
) -> Result<Vec<Value>, Error> {
    let n = view.manifest.trustees.n();
    let mut out = Vec::new();
    for j in 1..=n {
        let idx = (j - 1) as usize;
        let sk = &trustees.keys.trustee_sig[idx];
        let mut value =
            authority::trustee_decrypt(rng, view, sections, target, j, &trustees.zs[idx], sk)?;
        if trustees.attacks.trustee_lies && j == LYING_TRUSTEE {
            value = corrupt_set(&value, sk)?;
        }
        out.push(value);
    }
    Ok(out)
}

/// Re-signs a share set with its first share moved off the curve point it should
/// be. The signature is valid, but the proof is not.
fn corrupt_set(value: &Value, sk: &SigningKey) -> Result<Value, Error> {
    let mut set = DecryptionShareSet::from_signed(value, &sk.verifying_key())?;
    if let Some(share) = set.shares.first_mut() {
        share.0 += B;
    }
    Ok(set.sign(sk))
}

/// The published result, with names and party names.
fn result_view(manifest: &Manifest, r: &ElectionResult) -> ResultView {
    let contests = r
        .contests
        .iter()
        .map(|cr| {
            let contest = manifest.contest(cr.contest);
            let name = contest.map(|c| c.name.clone()).unwrap_or_default();
            let options: Vec<(String, u64)> = contest
                .map(|c| {
                    c.options
                        .iter()
                        .enumerate()
                        .map(|(i, o)| (o.name.clone(), cr.votes.get(i).copied().unwrap_or(0)))
                        .collect()
                })
                .unwrap_or_default();
            let seats: Option<Vec<(String, String)>> = match (cr.seats.as_ref(), contest) {
                (Some(alloc), Some(c)) => Some(
                    alloc
                        .elected
                        .iter()
                        .filter_map(|&opt| {
                            let o = c.options.get(usize::try_from(opt).ok()?)?;
                            let party = o
                                .party_index
                                .and_then(|p| manifest.parties.iter().find(|x| x.index == p))
                                .map(|x| x.name.clone())
                                .unwrap_or_default();
                            Some((o.name.clone(), party))
                        })
                        .collect(),
                ),
                _ => None,
            };
            ContestView {
                index: cr.contest,
                name,
                options,
                counted: cr.counted,
                invalid: cr.invalid,
                excluded: cr.excluded,
                seats,
            }
        })
        .collect();
    ResultView {
        contests,
        sections: r
            .sections
            .iter()
            .map(|s| (s.section_id.clone(), s.matches))
            .collect(),
    }
}

/// Returns a copy of `choices` where contest 0 selects the next option.
fn flip_contest_zero(manifest: &Manifest, choices: &[ContestPlain]) -> Vec<ContestPlain> {
    let options = manifest
        .contest(0)
        .map(|c| c.options.len() as u64)
        .unwrap_or(0);
    choices
        .iter()
        .map(|cp| {
            let mut out = cp.clone();
            if cp.contest == 0 && options > 1 {
                if let Some(sel) = out.selected.first_mut() {
                    *sel = (*sel + 1) % options;
                }
            }
            out
        })
        .collect()
}

/// Candidates already chosen in the contests linked to `contest` by a link group
/// (§12.6). Option indices are used as candidate identities, which holds in the
/// fixtures because linked contests share their option lists.
fn linked_candidates(manifest: &Manifest, contest: u64, chosen: &[ContestPlain]) -> Vec<u64> {
    let mut out = Vec::new();
    for group in manifest
        .link_groups
        .iter()
        .filter(|g| g.contests.contains(&contest))
    {
        for other in group.contests.iter().filter(|&&c| c != contest) {
            let Some(pick) = chosen.iter().find(|p| p.contest == *other) else {
                continue;
            };
            let Some(other_contest) = manifest.contest(*other) else {
                continue;
            };
            for sel in &pick.selected {
                let is_candidate = other_contest
                    .options
                    .iter()
                    .any(|o| o.index == *sel && o.kind == OptionKind::Candidate);
                if is_candidate {
                    out.push(*sel);
                }
            }
        }
    }
    out
}

/// The second poll worker of a section (the first one if there is only one).
fn second_poll_worker(
    registry: &Registry,
    poll_workers: &[SigningKey],
    section_id: &str,
) -> Result<SigningKey, Error> {
    let section = registry
        .section(section_id)
        .ok_or_else(|| sim_err(format!("section {section_id:?} is not in the registry")))?;
    let vk = section
        .poll_worker_keys
        .get(1)
        .or_else(|| section.poll_worker_keys.first())
        .ok_or_else(|| sim_err("the section has no poll worker"))?;
    find_key(poll_workers, vk).ok_or_else(|| sim_err("no secret key for the poll worker"))
}

/// Looks up the secret key of a public key.
fn find_key(keys: &[SigningKey], vk: &VerifyingKey) -> Option<SigningKey> {
    keys.iter().find(|k| k.verifying_key() == *vk).cloned()
}

fn no_open_session(machine_id: &str) -> Error {
    sim_err(format!("machine {machine_id:?} has no open session"))
}

/// Records the status of a ballot found in a package, by its tracking code.
fn set_status(found: &mut [Found], code: &[u8; 32], status: &'static str) {
    if let Some(f) = found.iter_mut().rev().find(|f| f.code == *code) {
        f.status = status;
    }
}

/// The type tag (field 0) of a record.
fn entry_tag(entry: &Value) -> Option<&str> {
    entry.get(0).ok().flatten().and_then(|t| t.as_text().ok())
}

/// The text of field `key` of a record, or "?".
fn field_text(record: &Value, key: u64) -> String {
    record
        .get(key)
        .ok()
        .flatten()
        .and_then(|t| t.as_text().ok())
        .unwrap_or("?")
        .to_owned()
}

/// A uniform value in `0..n`. `n` must be nonzero.
fn below(rng: &mut ChaCha20Rng, n: u64) -> u64 {
    rng.next_u64() % n
}

/// Error for a driver step that cannot run in the current state.
fn sim_err(msg: impl Into<String>) -> Error {
    Error::Board(format!("sim: {}", msg.into()))
}

/// Lower-case hex.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Upper-case hex in groups of four, separated by hyphens.
fn grouped(bytes: &[u8]) -> String {
    let h = hex(bytes).to_ascii_uppercase();
    h.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::{check_sth_pair, Equivocation};

    fn board_pk(sim: &Simulation) -> VerifyingKey {
        sim.keys.board.verifying_key()
    }

    /// Runs the full default election and checks the honest outcome.
    #[test]
    fn run_all_without_attacks_tallies_and_verifies() {
        let mut sim = Simulation::new(7);
        let view = sim.run_all().expect("run_all");
        assert_eq!(sim.phase(), Phase::Tallied);

        // Two machines, 4 cast ballots each.
        for c in &view.contests {
            let votes: u64 = c.options.iter().map(|(_, v)| v).sum();
            let limit = sim.manifest().contest(c.index).expect("contest").limit;
            assert_eq!(c.counted, 8, "contest {} counted", c.index);
            if limit == 1 {
                assert_eq!(votes, c.counted, "contest {} votes", c.index);
            } else {
                assert!(votes <= c.counted * limit, "contest {} votes", c.index);
            }
        }
        assert_eq!(view.sections.len(), 2);
        assert!(view.sections.iter().all(|(_, m)| *m));

        let slip = sim.slips()[0].clone();
        let found = sim.lookup(&slip.short_code).expect("lookup");
        assert!(found.found);
        assert_eq!(found.status.as_deref(), Some("cast"));
        assert!(found.inclusion_proof_verifies);
        assert!(found.contests_counted.iter().all(|(_, c)| *c == Some(true)));

        let spoil = sim.spoils()[0].clone();
        let check = sim.check_spoil(&spoil.receipt).expect("check");
        assert!(check.ok, "{}", check.message);
        assert_eq!(check.claimed, spoil.claimed);
    }

    #[test]
    fn machine_that_flips_votes_fails_the_spoil_check() {
        let mut sim = Simulation::new(8);
        sim.attacks_mut().machine_flips_votes = true;
        sim.run_ceremony().expect("ceremony");
        sim.open_polls().expect("polls");
        sim.open_session("M-S1-01", None).expect("session");
        let choices = sim.random_choices("M-S1-01");
        sim.authorize("M-S1-01").expect("authorize");
        sim.encrypt("M-S1-01", choices.clone()).expect("encrypt");
        let spoil = sim.spoil("M-S1-01").expect("spoil");
        assert_eq!(spoil.claimed, choices);
        // The spoiled ballot must reach the board, so that the check compares
        // the receipt with the committed ballot and not with a missing one.
        sim.close_session("M-S1-01").expect("close");
        sim.cutoff().expect("cutoff");
        let check = sim.check_spoil(&spoil.receipt).expect("check");
        assert!(!check.ok, "the flipped ballot must not verify");
        assert!(
            !check.message.starts_with("no committed"),
            "the check must run against the committed ballot: {}",
            check.message
        );
    }

    #[test]
    fn ea_alteration_differs_from_the_recount() {
        let mut sim = Simulation::new(9);
        sim.attacks_mut().ea_alters_result = true;
        let view = sim.run_all().expect("run_all");
        let recount = sim.recount().expect("recount").clone();
        let published = &view.contests[0];
        let honest = &recount.contests[0];
        assert_eq!(published.options[0].1, honest.votes[0] + 100);
        assert_ne!(
            published
                .options
                .iter()
                .map(|(_, v)| *v)
                .collect::<Vec<_>>(),
            honest.votes
        );
    }

    #[test]
    fn lying_trustee_is_rejected_and_tally_completes() {
        let mut sim = Simulation::new(10);
        sim.attacks_mut().trustee_lies = true;
        let view = sim.run_all().expect("run_all");
        assert_eq!(sim.phase(), Phase::Tallied);
        assert!(view.sections.iter().all(|(_, m)| *m));
    }

    #[test]
    fn dropped_package_leaves_its_attestation_on_the_board() {
        let mut sim = Simulation::new(11);
        sim.attacks_mut().board_drops_package_of = Some("M-S2-01".to_owned());
        sim.run_all().expect("run_all");
        let summaries = sim.entry_summaries();
        let packages: Vec<&EntrySummary> =
            summaries.iter().filter(|s| s.kind == "package").collect();
        assert_eq!(packages.len(), 1, "only the S1 package is on the board");
        assert!(!packages[0].detail.contains("M-S2-01"));
        assert!(summaries
            .iter()
            .any(|s| s.kind == "section_attestation" && s.detail.contains("M-S2-01")));
    }

    #[test]
    fn bad_dkg_share_is_complained_about_and_resolved() {
        let mut sim = Simulation::new(12);
        sim.attacks_mut().bad_dkg_share = true;
        let report = sim.run_ceremony().expect("ceremony completes");
        assert_eq!(report.complaints.len(), 1);
        assert_eq!(sim.phase(), Phase::CeremonyDone);
        let kinds: Vec<String> = sim.entry_summaries().into_iter().map(|s| s.kind).collect();
        assert!(kinds.iter().any(|k| k == "dkg_complaint"));
        assert!(kinds.iter().any(|k| k == "dkg_reveal"));
    }

    #[test]
    fn equivocating_board_is_detected() {
        let mut sim = Simulation::new(13);
        sim.attacks_mut().board_equivocates = true;
        sim.run_ceremony().expect("ceremony");
        sim.open_polls().expect("polls");
        let first = sim.sign_sth();
        assert_eq!(first.len(), 1);
        let second = sim.sign_sth();
        assert_eq!(second.len(), 2);
        let pk = board_pk(&sim);
        let a = Sth::from_signed(&second[0], &pk).expect("sth");
        let b = Sth::from_signed(&second[1], &pk).expect("sth");
        assert_eq!(a.size, b.size);
        assert_ne!(a.root, b.root);
        assert_eq!(
            check_sth_pair(&a, &b, &[]),
            Some(Equivocation::SameSizeDifferentRoots)
        );
    }
}
