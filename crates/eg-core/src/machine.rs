//! Voting-machine session state machine (SPEC.md §13.1, §14.1, §15, §16.1 to
//! §16.4 and §18.1).
//!
//! A [`Session`] runs one polling session of one machine. Every step is
//! journaled (§15) before its output is shown: the code before it is displayed,
//! the cast record before the slip is printed, and so on. The journal is kept
//! in memory here. The host MUST persist `session.journal().to_bytes()` after
//! each call and before showing or printing anything that depends on it (§15.1).
//!
//! [`Session::restart`] rebuilds a session from journal bytes (§15.4). It drops
//! a torn final frame, finishes an unfinished record (checkpoint, abandonment of
//! an unfinished ballot) and checks the result with
//! [`journal::check_journal`]. Recovered packages of dead machines (§16.4) are
//! imported with [`Session::import_recovered`].
//!
//! Each import is journaled as an `import` record (§16.4). The journal keeps
//! only the package's RecordId, cast count and last head, not its ballots, so
//! after a restart the host must import the same packages again, in the same
//! order, before [`Session::prepare_pre_bu`] will run.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::ballot::{encrypt_ballot, Ballot, BallotId, ContestPlain, Election};
use crate::board::record_id;
use crate::cbor::Value;
use crate::chain::{
    chain_start, next_head, tracking_code, Measurement, Reveal, Slip, SpoilReceipt, Status,
};
use crate::error::Error;
use crate::journal::{
    check_journal, checkpoint_signature, Journal, PreBu, Record, SectionSig, SessionKeys,
    SessionOpen, Zeresima,
};
use crate::package::{build_package, RecoveredPackage};
use crate::registry::{Registry, SectionEntry};
use crate::sign::{self, Signature, SigningKey, VerifyingKey};
use crate::tally::{
    fingerprint, indices, judge_cast, split_pooled, sum_ballots, ContestSum, Imported,
    JudgedBallot, Reservations,
};

/// Signature tags of authorizations and cancellations (§15.2).
const SIG_AUTH: &str = "eg/v1/sig/auth";
const SIG_AUTH_CANCEL: &str = "eg/v1/sig/auth-cancel";

fn journal_err(msg: impl Into<String>) -> Error {
    Error::Journal(msg.into())
}

/// `[context_hash, machine_id, session_id, auth_seq]`, the object that poll
/// workers sign for authorizations and cancellations (§15.2). The journal
/// module builds the same object internally.
fn auth_message(context_hash: &[u8; 32], machine_id: &str, session_id: &str, seq: u64) -> Value {
    Value::Array(vec![
        Value::from(*context_hash),
        Value::from(machine_id),
        Value::from(session_id),
        Value::Uint(seq),
    ])
}

/// Everything a session needs to know about its machine and election.
pub struct MachineConfig<'a> {
    /// Context hash, joint key and manifest of the election.
    pub election: Election<'a>,
    /// The registry in force. Machine, section and contest data come from it.
    pub registry: &'a Registry,
    /// Machine identifier, as in the registry.
    pub machine_id: String,
    /// Machine signing key. Must match the registry key of `machine_id`.
    pub machine_sk: SigningKey,
    /// Software measurement of this machine (§24.4).
    pub measurement: Measurement,
}

/// A committed ballot waiting for its status. ρ lives here until cast, spoil
/// or abandon erases it.
struct Pending {
    ballot: Ballot,
    code: [u8; 32],
    rho: Zeroizing<[u8; 32]>,
    choices: Vec<ContestPlain>,
}

/// One voting-machine session (§13 to §16).
pub struct Session<'a> {
    cfg: MachineConfig<'a>,
    section_id: String,
    session_id: String,
    journal: Journal,
    /// Chain head after the latest decision (§13.1). Starts at `head_0`.
    head: [u8; 32],
    /// The signed zerésima (§15.5). Journaled by `sign_zeresima`.
    zeresima: Value,
    zeresima_signed: bool,
    /// Authorizations journaled so far. The next one is `auth_count + 1`.
    auth_count: u64,
    /// The journaled authorization that is neither cast nor cancelled.
    unused: Option<u64>,
    /// Cancellations journaled so far.
    cancelled: u64,
    /// Committed ballots so far. The next ballot is `ballot_count + 1`.
    ballot_count: u64,
    pending: Option<Pending>,
    /// Cast ballots of this session, in journal order (§18.1).
    cast_ballots: Vec<Ballot>,
    spoiled: u64,
    abandoned: u64,
    /// Recovered packages imported (§16.4), in import order.
    imports: Vec<Imported>,
    /// Cast ballots of the imported packages, in import order.
    imported_ballots: Vec<Ballot>,
    /// Imports recorded in the journal. `imports` is always a prefix of it; it
    /// is shorter only after a restart, until the host imports them again.
    journaled_imports: Vec<Imported>,
    /// The pre-BU built by `prepare_pre_bu`, waiting for its signatures. Any
    /// journal append clears it, so a stale pre-BU can't be signed.
    prepared: Option<Value>,
    pre_bu_signed: bool,
    closed: bool,
}

impl<'a> Session<'a> {
    /// §15.5 steps 1 and 2: journals `session_open` and returns the machine-signed
    /// zerésima for printing. `section_id` is the machine's section. A reserve
    /// machine (registry section "") takes the section it is bound to today.
    pub fn open(
        cfg: MachineConfig<'a>,
        section_id: &str,
        session_id: &str,
        opened_at: u64,
        opening_challenge: [u8; 16],
    ) -> Result<(Session<'a>, Value), Error> {
        let so = SessionOpen {
            context_hash: cfg.election.context_hash,
            machine_id: cfg.machine_id.clone(),
            section_id: section_id.to_owned(),
            session_id: session_id.to_owned(),
            measurement: cfg.measurement,
            opened_at,
            opening_challenge,
            attestation: None,
        };
        let mut session = Session::start(cfg, &so)?;
        session.append(Record::SessionOpen(so));
        let zeresima = session.zeresima.clone();
        Ok((session, zeresima))
    }

    /// An empty session for `so`: the head is `head_0` and the zerésima is signed,
    /// but nothing is journaled yet.
    fn start(cfg: MachineConfig<'a>, so: &SessionOpen) -> Result<Session<'a>, Error> {
        if so.context_hash != cfg.election.context_hash
            || so.machine_id != cfg.machine_id
            || so.measurement != cfg.measurement
        {
            return Err(journal_err(
                "session_open does not match this machine, election or software",
            ));
        }
        check_identity(&cfg, &so.section_id)?;
        let head_0 = chain_start(
            &so.context_hash,
            &so.machine_id,
            &so.session_id,
            &so.measurement,
            &so.opening_challenge,
        );
        let zeresima = Zeresima {
            context_hash: so.context_hash,
            machine_id: so.machine_id.clone(),
            section_id: so.section_id.clone(),
            session_id: so.session_id.clone(),
            measurement: so.measurement,
            head_0,
            session_open_id: record_id(&so.to_value()),
            opened_at: so.opened_at,
        }
        .sign(&cfg.machine_sk);
        Ok(Session {
            section_id: so.section_id.clone(),
            session_id: so.session_id.clone(),
            cfg,
            journal: Journal::new(),
            head: head_0,
            zeresima,
            zeresima_signed: false,
            auth_count: 0,
            unused: None,
            cancelled: 0,
            ballot_count: 0,
            pending: None,
            cast_ballots: Vec::new(),
            spoiled: 0,
            abandoned: 0,
            imports: Vec::new(),
            imported_ballots: Vec::new(),
            journaled_imports: Vec::new(),
            prepared: None,
            pre_bu_signed: false,
            closed: false,
        })
    }

    /// §15.5 step 3: journals `zeresima_signed` with the poll worker signatures
    /// on the zerésima, then a checkpoint. Every signature must be by a poll
    /// worker of the section and must verify.
    pub fn sign_zeresima(&mut self, sigs: Vec<SectionSig>) -> Result<(), Error> {
        if self.zeresima_signed {
            return Err(journal_err("the zerésima is already signed"));
        }
        if self.closed {
            return Err(journal_err("the session is closed"));
        }
        self.check_section_sigs(&sigs, &self.zeresima)?;
        let zeresima = self.zeresima.clone();
        self.append(Record::ZeresimaSigned { zeresima, sigs });
        self.zeresima_signed = true;
        self.checkpoint();
        Ok(())
    }

    /// The `auth_seq` that the next [`Session::authorize`] will use.
    pub fn next_auth_seq(&self) -> u64 {
        self.auth_count + 1
    }

    /// §15.2: journals an authorization. `sig` must be a poll worker's signature
    /// on the next `auth_seq`, made on the poll terminal with
    /// `journal::auth_signature`. Refused while another authorization is unused.
    pub fn authorize(&mut self, pw_key: VerifyingKey, sig: Signature) -> Result<u64, Error> {
        self.ensure_open()?;
        if let Some(seq) = self.unused {
            return Err(journal_err(format!(
                "authorization {seq} is still unused: cast or cancel it first"
            )));
        }
        self.check_poll_worker(&pw_key)?;
        let seq = self.auth_count + 1;
        let msg = auth_message(
            &self.cfg.election.context_hash,
            &self.cfg.machine_id,
            &self.session_id,
            seq,
        );
        if !sign::verify(&pw_key, SIG_AUTH, &msg, &sig) {
            return Err(journal_err("authorization signature does not verify"));
        }
        self.append(Record::Authorization { seq, pw_key, sig });
        self.auth_count = seq;
        self.unused = Some(seq);
        Ok(seq)
    }

    /// §14.1 `encrypt()`: builds a ballot from `choices` with a fresh ρ, journals
    /// it as `committed` and returns its full tracking code. Needs an unused
    /// authorization and no pending ballot.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        choices: Vec<ContestPlain>,
    ) -> Result<[u8; 32], Error> {
        self.ensure_open()?;
        if self.unused.is_none() {
            return Err(journal_err("encrypt needs an unused authorization"));
        }
        if self.pending.is_some() {
            return Err(journal_err("a ballot is already pending"));
        }
        let offered = self.offered()?;
        let id = BallotId {
            machine_id: self.cfg.machine_id.clone(),
            session_id: self.session_id.clone(),
            seq: self.ballot_count + 1,
        };
        let election = &self.cfg.election;
        let mut rho = Zeroizing::new([0u8; 32]);
        let ballot = loop {
            rng.fill_bytes(&mut rho[..]);
            match encrypt_ballot(rng, election, &offered, &id, &rho, &choices) {
                Ok(ballot) => break ballot,
                // A zero nonce is astronomically rare; draw another ρ.
                Err(Error::ZeroNonce) => continue,
                Err(e) => return Err(e),
            }
        };
        let code = tracking_code(&self.head, &ballot);
        self.append(Record::Committed {
            ballot: ballot.clone(),
            code,
        });
        self.ballot_count += 1;
        self.pending = Some(Pending {
            ballot,
            code,
            rho,
            choices,
        });
        Ok(code)
    }

    /// §14.1 `cast()`: journals `cast` and a checkpoint, erases ρ, consumes the
    /// authorization and returns the signed slip. The slip is printed only after
    /// this returns.
    pub fn cast(&mut self) -> Result<Value, Error> {
        self.ensure_open()?;
        if self.unused.is_none() {
            return Err(journal_err("cast needs an unused authorization"));
        }
        let Some(Pending {
            ballot,
            code,
            rho,
            choices,
        }) = self.pending.take()
        else {
            return Err(journal_err("nothing to cast: no ballot is pending"));
        };
        self.append(Record::Cast { code });
        self.head = next_head(&code, Status::Cast, None);
        self.unused = None;
        self.cast_ballots.push(ballot);
        self.checkpoint();
        // ρ is erased once the cast is journaled. `Zeroizing` wipes it on drop.
        drop(rho);
        drop(choices);
        Ok(Slip {
            context_hash: self.cfg.election.context_hash,
            machine_id: self.cfg.machine_id.clone(),
            code,
        }
        .sign(&self.cfg.machine_sk))
    }

    /// §14.1 `spoil()`: journals the reveal and a checkpoint, and returns the
    /// signed spoil receipt. The authorization is not consumed.
    pub fn spoil(&mut self) -> Result<Value, Error> {
        self.ensure_open()?;
        let Some(Pending {
            ballot,
            code,
            rho,
            choices,
        }) = self.pending.take()
        else {
            return Err(journal_err("nothing to spoil: no ballot is pending"));
        };
        let reveal = Reveal {
            ballot_id: ballot.id.clone(),
            rho: *rho,
            selections: choices,
        };
        self.append(Record::Spoiled {
            code,
            reveal: reveal.clone(),
        });
        self.head = next_head(&code, Status::Spoiled, Some(&reveal));
        self.spoiled += 1;
        self.checkpoint();
        drop(rho);
        Ok(SpoilReceipt {
            context_hash: self.cfg.election.context_hash,
            machine_id: self.cfg.machine_id.clone(),
            code,
            reveal,
        }
        .sign(&self.cfg.machine_sk))
    }

    /// Abandons the pending ballot, for a voter who walked away: journals
    /// `abandoned` and a checkpoint, and erases ρ without revealing it. The
    /// authorization stays unused, so the poll worker decides whether to cancel it.
    pub fn abandon(&mut self) -> Result<(), Error> {
        self.ensure_open()?;
        let Some(Pending { code, rho, .. }) = self.pending.take() else {
            return Err(journal_err("nothing to abandon: no ballot is pending"));
        };
        self.append(Record::Abandoned { code });
        self.head = next_head(&code, Status::Abandoned, None);
        self.abandoned += 1;
        self.checkpoint();
        drop(rho);
        Ok(())
    }

    /// §15.2: journals a poll worker's cancellation of the unused authorization.
    /// Refused while a ballot is pending.
    pub fn cancel_authorization(
        &mut self,
        pw_key: VerifyingKey,
        sig: Signature,
    ) -> Result<(), Error> {
        self.ensure_open()?;
        let Some(seq) = self.unused else {
            return Err(journal_err("no unused authorization to cancel"));
        };
        if self.pending.is_some() {
            return Err(journal_err(
                "a ballot is pending: cast, spoil or abandon it first",
            ));
        }
        self.check_poll_worker(&pw_key)?;
        let msg = auth_message(
            &self.cfg.election.context_hash,
            &self.cfg.machine_id,
            &self.session_id,
            seq,
        );
        if !sign::verify(&pw_key, SIG_AUTH_CANCEL, &msg, &sig) {
            return Err(journal_err("cancellation signature does not verify"));
        }
        self.append(Record::AuthCancel { seq, pw_key, sig });
        self.unused = None;
        self.cancelled += 1;
        Ok(())
    }

    /// §16.4: imports a recovered package of a dead machine of this section.
    ///
    /// The package must have a poll worker signature, and its journal must pass
    /// [`check_journal`] in recovered mode against the dead machine's registry
    /// key. Its section must be this section, and it must offer the same contests
    /// as this machine. Its cast ballots join the section tally. Must be called
    /// before [`Session::prepare_pre_bu`].
    pub fn import_recovered(&mut self, recovered: &Value) -> Result<(), Error> {
        self.ensure_open()?;
        if self.pre_bu_signed {
            return Err(journal_err("the pre-BU is already signed: no more imports"));
        }
        let rp = RecoveredPackage::from_value(recovered)?;
        let registry: &'a Registry = self.cfg.registry;
        let section = self.section()?;
        let unsigned = rp.unsigned_value();
        let signed = rp
            .sigs
            .iter()
            .any(|s| section.poll_worker_keys.contains(&s.key) && s.verify(&unsigned));
        if !signed {
            return Err(journal_err(
                "recovered package has no signature by a poll worker of this section",
            ));
        }
        let dead = registry.machine(&rp.header.machine_id).ok_or_else(|| {
            journal_err(format!(
                "machine {:?} is not registered",
                rp.header.machine_id
            ))
        })?;
        let journal = Journal::from_records(rp.records.clone());
        let keys = SessionKeys {
            context_hash: self.cfg.election.context_hash,
            machine_key: dead.key,
            poll_worker_keys: &section.poll_worker_keys,
            min_section_ballots: self.cfg.election.manifest.min_section_ballots,
        };
        let summary = check_journal(&keys, &journal, false)?;
        let h = &rp.header;
        if summary.machine_id != h.machine_id
            || summary.section_id != h.section_id
            || summary.session_id != h.session_id
            || summary.measurement != h.measurement
            || h.record_count != journal.len() as u64
            || h.frame_digest != journal.last_digest()
            || h.chain_head != summary.final_head
        {
            return Err(journal_err(
                "recovered package header does not match its journal",
            ));
        }
        if summary.section_id != self.section_id {
            return Err(journal_err(format!(
                "recovered package is for section {:?}, not {:?}",
                summary.section_id, self.section_id
            )));
        }
        if dead.contests != self.offered()? {
            return Err(journal_err(
                "recovered machine offers other contests than this machine",
            ));
        }
        if summary.machine_id == self.cfg.machine_id && summary.session_id == self.session_id {
            return Err(journal_err("a session cannot import its own journal"));
        }
        let package_id = record_id(recovered);
        if self.imports.iter().any(|i| i.package_id == package_id) {
            return Err(journal_err("recovered package is already imported"));
        }
        let mut open: Option<&Ballot> = None;
        let mut ballots = Vec::new();
        for rec in journal.records() {
            match rec {
                Record::Committed { ballot, .. } => open = Some(ballot),
                Record::Cast { .. } => ballots.extend(open.take().cloned()),
                Record::Spoiled { .. } | Record::Abandoned { .. } => open = None,
                _ => {}
            }
        }
        let imported = Imported {
            package_id,
            cast: summary.cast,
            last_head: summary.final_head,
        };
        // After a restart the journal already lists some imports: they must be
        // re-imported first, in journal order, and are not journaled again.
        let k = self.imports.len();
        match self.journaled_imports.get(k) {
            Some(expected) if *expected == imported => {}
            Some(_) => {
                return Err(journal_err(format!(
                    "the journal records a different recovered package as import {}: import that one first",
                    k + 1
                )))
            }
            None => {
                self.append(Record::Import(imported.clone()));
                self.journaled_imports.push(imported.clone());
            }
        }
        self.imports.push(imported);
        self.imported_ballots.extend(ballots);
        self.prepared = None;
        Ok(())
    }

    /// §16.2 steps 1 to 3: computes the section tally over this session's cast
    /// ballots and the imported ones, splits off the pooled contests, computes
    /// the fingerprint and returns the machine-signed pre-BU. Journals nothing.
    /// Refused while a ballot is pending or an authorization is unused.
    ///
    /// Judging order: the imported ballots first, in import order, then this
    /// session's cast ballots in journal order. One [`Reservations`] covers both.
    pub fn prepare_pre_bu(&mut self, roll_count: u64) -> Result<Value, Error> {
        self.ensure_open()?;
        if self.pending.is_some() {
            return Err(journal_err(
                "a ballot is pending: cast, spoil or abandon it first",
            ));
        }
        if let Some(seq) = self.unused {
            return Err(journal_err(format!(
                "authorization {seq} is unused: cancel it before the pre-BU"
            )));
        }
        if self.imports.len() < self.journaled_imports.len() {
            return Err(journal_err(format!(
                "the journal records {} recovered imports and {} are loaded: import the rest again before the pre-BU",
                self.journaled_imports.len(),
                self.imports.len()
            )));
        }
        let offered = self.offered()?;
        let min = self.cfg.election.manifest.min_section_ballots;
        let own: Vec<&Ballot> = self.cast_ballots.iter().collect();
        let imported: Vec<&Ballot> = self.imported_ballots.iter().collect();
        let (kept, pooled) = section_sums(&self.cfg.election, &offered, &imported, &own, min);
        let pooled_indices = indices(&pooled);
        let context_hash = self.cfg.election.context_hash;
        let fp = fingerprint(
            &context_hash,
            &self.cfg.machine_id,
            &self.session_id,
            &self.imports,
            &kept,
            &pooled_indices,
        );
        let pre_bu = PreBu {
            context_hash,
            machine_id: self.cfg.machine_id.clone(),
            section_id: self.section_id.clone(),
            session_id: self.session_id.clone(),
            imported: self.imports.clone(),
            frame_digest: self.journal.last_digest(),
            chain_head: self.head,
            authorizations: self.auth_count,
            cast: self.cast_ballots.len() as u64,
            spoiled: self.spoiled,
            abandoned: self.abandoned,
            roll_count,
            fingerprint: fp,
            pooled: pooled_indices,
        };
        let value = pre_bu.sign(&self.cfg.machine_sk);
        self.prepared = Some(value.clone());
        Ok(value)
    }

    /// §16.2 step 4: journals `pre_bu_signed` with the poll worker signatures on
    /// the prepared pre-BU, then a checkpoint.
    pub fn sign_pre_bu(&mut self, sigs: Vec<SectionSig>) -> Result<(), Error> {
        self.ensure_open()?;
        let Some(pre_bu) = self.prepared.clone() else {
            return Err(journal_err("no prepared pre-BU: call prepare_pre_bu first"));
        };
        self.check_section_sigs(&sigs, &pre_bu)?;
        self.append(Record::PreBuSigned { pre_bu, sigs });
        self.pre_bu_signed = true;
        self.checkpoint();
        Ok(())
    }

    /// §16.1: journals `session_close` and returns the signed package. The pre-BU
    /// must already be signed, and every authorization must be cast or cancelled.
    pub fn close(&mut self, closed_at: u64) -> Result<Value, Error> {
        if self.closed {
            return Err(journal_err("the session is already closed"));
        }
        if !self.pre_bu_signed {
            return Err(journal_err(
                "the pre-BU must be signed before the session closes",
            ));
        }
        if let Some(seq) = self.unused {
            return Err(journal_err(format!(
                "authorization {seq} is unused: the poll worker must cancel it first"
            )));
        }
        let cast = self.cast_ballots.len() as u64;
        if self.auth_count != cast + self.cancelled {
            return Err(journal_err(
                "authorizations must equal cast plus cancellations",
            ));
        }
        let record = Record::SessionClose {
            authorizations: self.auth_count,
            cast,
            spoiled: self.spoiled,
            abandoned: self.abandoned,
            final_head: self.head,
            closed_at,
            attestation: None,
        };
        self.append(record);
        self.closed = true;
        build_package(
            &self.journal,
            &self.cfg.election.context_hash,
            &self.cfg.machine_id,
            &self.section_id,
            &self.session_id,
            self.cfg.measurement,
            &self.cfg.machine_sk,
        )
    }

    /// The journal, for persisting it (§15.1).
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// The section of this session.
    pub fn section_id(&self) -> &str {
        &self.section_id
    }

    /// The session identifier.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The current chain head (§13.1).
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// §15.4 restart: rebuilds a session from its journal bytes.
    ///
    /// - A torn final frame is dropped by [`Journal::from_bytes`]. Any other
    ///   damage is an error.
    /// - A `cast`, `spoiled`, `abandoned`, `zeresima_signed` or `pre_bu_signed`
    ///   without a checkpoint after it gets one now. For a `cast`, the reprinted
    ///   slip is returned. It is byte-identical to the original, because Ed25519
    ///   signatures are deterministic.
    /// - A committed ballot with no status becomes abandoned, and ρ is not
    ///   recovered.
    ///
    /// The result is checked with [`check_journal`] before it is returned.
    pub fn restart(
        cfg: MachineConfig<'a>,
        journal_bytes: &[u8],
    ) -> Result<(Session<'a>, Option<Value>), Error> {
        let (journal, _torn) = Journal::from_bytes(journal_bytes)?;
        let so = match journal.records().first() {
            Some(Record::SessionOpen(so)) => so.clone(),
            _ => return Err(journal_err("a journal must begin with session_open")),
        };
        let mut s = Session::start(cfg, &so)?;

        // Replay the state. Nothing is checked here: `check_journal` does that below.
        let mut open: Option<(Ballot, [u8; 32])> = None;
        for rec in journal.records().iter().skip(1) {
            match rec {
                Record::SessionOpen(_) => return Err(journal_err("session_open appears twice")),
                Record::ZeresimaSigned { zeresima, .. } => {
                    s.zeresima = zeresima.clone();
                    s.zeresima_signed = true;
                }
                Record::Authorization { seq, .. } => {
                    s.auth_count += 1;
                    s.unused = Some(*seq);
                }
                Record::AuthCancel { .. } => {
                    s.unused = None;
                    s.cancelled += 1;
                }
                Record::Committed { ballot, code } => {
                    s.ballot_count += 1;
                    open = Some((ballot.clone(), *code));
                }
                Record::Cast { code } => {
                    let (ballot, _) = open
                        .take()
                        .ok_or_else(|| journal_err("cast without a committed ballot"))?;
                    s.cast_ballots.push(ballot);
                    s.head = next_head(code, Status::Cast, None);
                    s.unused = None;
                }
                Record::Spoiled { code, reveal } => {
                    open.take()
                        .ok_or_else(|| journal_err("spoiled without a committed ballot"))?;
                    s.spoiled += 1;
                    s.head = next_head(code, Status::Spoiled, Some(reveal));
                }
                Record::Abandoned { code } => {
                    open.take()
                        .ok_or_else(|| journal_err("abandoned without a committed ballot"))?;
                    s.abandoned += 1;
                    s.head = next_head(code, Status::Abandoned, None);
                }
                Record::Checkpoint { .. } => {}
                Record::Import(imported) => s.journaled_imports.push(imported.clone()),
                Record::PreBuSigned { .. } => s.pre_bu_signed = true,
                Record::SessionClose { .. } => s.closed = true,
            }
        }
        s.journal = journal;

        // A cast that was journaled but whose slip may not have been printed.
        let reprint = match s.journal.records().last() {
            Some(Record::Cast { code }) => Some(
                Slip {
                    context_hash: s.cfg.election.context_hash,
                    machine_id: s.cfg.machine_id.clone(),
                    code: *code,
                }
                .sign(&s.cfg.machine_sk),
            ),
            _ => None,
        };

        // Finish what the crash interrupted.
        if let Some((_, code)) = open {
            s.append(Record::Abandoned { code });
            s.head = next_head(&code, Status::Abandoned, None);
            s.abandoned += 1;
            s.checkpoint();
        } else if matches!(
            s.journal.records().last(),
            Some(
                Record::ZeresimaSigned { .. }
                    | Record::Cast { .. }
                    | Record::Spoiled { .. }
                    | Record::Abandoned { .. }
                    | Record::PreBuSigned { .. }
            )
        ) {
            s.checkpoint();
        }

        // Verify the whole journal. Only a live journal may end without a
        // checkpoint, such as after an authorization. A probe checkpoint lets
        // the recovered-mode checker accept that.
        if s.closed {
            check_journal(&s.session_keys()?, &s.journal, true)?;
        } else if s.journal.len() > 1 {
            let mut probe = s.journal.clone();
            if !matches!(probe.records().last(), Some(Record::Checkpoint { .. })) {
                let cp = checkpoint_record(&s.cfg, &s.session_id, &probe, &s.head);
                probe.append(cp);
            }
            check_journal(&s.session_keys()?, &probe, false)?;
        }
        Ok((s, reprint))
    }

    // -- internals ---------------------------------------------------------

    /// Journal append. Clears any prepared pre-BU, because it is stale now.
    fn append(&mut self, record: Record) {
        self.prepared = None;
        self.journal.append(record);
    }

    /// Journals a checkpoint over the current head (§15.2).
    fn checkpoint(&mut self) {
        let record = checkpoint_record(&self.cfg, &self.session_id, &self.journal, &self.head);
        self.append(record);
    }

    /// Fails unless the zerésima is signed and no pre-BU or close has happened.
    fn ensure_open(&self) -> Result<(), Error> {
        if !self.zeresima_signed {
            return Err(journal_err("the zerésima must be signed before voting"));
        }
        if self.pre_bu_signed || self.closed {
            return Err(journal_err("the session is past its pre-BU"));
        }
        Ok(())
    }

    /// The registry section of this session.
    fn section(&self) -> Result<&'a SectionEntry, Error> {
        let registry: &'a Registry = self.cfg.registry;
        registry
            .section(&self.section_id)
            .ok_or_else(|| journal_err(format!("section {:?} is not registered", self.section_id)))
    }

    /// The contests this machine offers (its registry entry, §7.7).
    fn offered(&self) -> Result<Vec<u64>, Error> {
        let registry: &'a Registry = self.cfg.registry;
        registry
            .machine(&self.cfg.machine_id)
            .map(|m| m.contests.clone())
            .ok_or_else(|| {
                journal_err(format!(
                    "machine {:?} is not registered",
                    self.cfg.machine_id
                ))
            })
    }

    fn check_poll_worker(&self, key: &VerifyingKey) -> Result<(), Error> {
        if self.section()?.poll_worker_keys.contains(key) {
            Ok(())
        } else {
            Err(journal_err("key is not a poll worker of this section"))
        }
    }

    /// At least one signature, and every one by a poll worker of the section
    /// and valid over `record`.
    fn check_section_sigs(&self, sigs: &[SectionSig], record: &Value) -> Result<(), Error> {
        if sigs.is_empty() {
            return Err(journal_err(
                "at least one poll worker signature is required",
            ));
        }
        for sig in sigs {
            self.check_poll_worker(&sig.key)?;
            if !sig.verify(record) {
                return Err(journal_err("section signature does not verify"));
            }
        }
        Ok(())
    }

    /// The session's keys for [`check_journal`].
    fn session_keys(&self) -> Result<SessionKeys<'a>, Error> {
        let registry: &'a Registry = self.cfg.registry;
        let machine = registry.machine(&self.cfg.machine_id).ok_or_else(|| {
            journal_err(format!(
                "machine {:?} is not registered",
                self.cfg.machine_id
            ))
        })?;
        let section = self.section()?;
        Ok(SessionKeys {
            context_hash: self.cfg.election.context_hash,
            machine_key: machine.key,
            poll_worker_keys: &section.poll_worker_keys,
            min_section_ballots: self.cfg.election.manifest.min_section_ballots,
        })
    }
}

/// Checks that the machine is registered with this key, and that `section_id`
/// is a section it may serve (§7.7).
fn check_identity(cfg: &MachineConfig, section_id: &str) -> Result<(), Error> {
    let machine = cfg
        .registry
        .machine(&cfg.machine_id)
        .ok_or_else(|| journal_err(format!("machine {:?} is not registered", cfg.machine_id)))?;
    if machine.key != cfg.machine_sk.verifying_key() {
        return Err(journal_err("machine key does not match the registry"));
    }
    if cfg.registry.section(section_id).is_none() {
        return Err(journal_err(format!(
            "section {section_id:?} is not registered"
        )));
    }
    if !machine.section_id.is_empty() && machine.section_id != section_id {
        return Err(journal_err(format!(
            "machine {:?} serves section {:?}, not {section_id:?}",
            cfg.machine_id, machine.section_id
        )));
    }
    Ok(())
}

/// A checkpoint record over `journal` and `head` (§15.2).
fn checkpoint_record(
    cfg: &MachineConfig,
    session_id: &str,
    journal: &Journal,
    head: &[u8; 32],
) -> Record {
    let count = journal.len() as u64;
    let frame_digest = journal.last_digest();
    let sig = checkpoint_signature(
        &cfg.machine_sk,
        &cfg.election.context_hash,
        &cfg.machine_id,
        session_id,
        count,
        &frame_digest,
        head,
    );
    Record::Checkpoint {
        count,
        frame_digest,
        chain_head: *head,
        sig,
    }
}

/// The section tally of §18.1, shared by the machine and by verifiers.
///
/// `imported_ballots` are the cast ballots of the imported recovered packages
/// (pre-BU field 6), and `own_ballots` the cast ballots of the pre-BU's session.
/// Both lists have the offered contests `offered`. Ballots are judged with one
/// [`Reservations`], imports first and then own ballots, each in the order given.
///
/// Returns `(kept, pooled)`. `kept` is the section tally (contests with at least
/// `min_section_ballots` counted ballots), and `pooled` holds the others. Both
/// are ascending by contest.
pub fn section_sums(
    election: &Election,
    offered: &[u64],
    imported_ballots: &[&Ballot],
    own_ballots: &[&Ballot],
    min_section_ballots: u64,
) -> (Vec<ContestSum>, Vec<ContestSum>) {
    let mut reservations = Reservations::new();
    let ordered: Vec<&Ballot> = imported_ballots
        .iter()
        .chain(own_ballots.iter())
        .copied()
        .collect();
    let judged: Vec<JudgedBallot> = ordered
        .iter()
        .map(|b| judge_cast(election, offered, b, &mut reservations))
        .collect();
    let pairs: Vec<(&Ballot, &JudgedBallot)> = ordered.iter().copied().zip(judged.iter()).collect();
    let sums = sum_ballots(election, &pairs);
    split_pooled(sums, min_section_ballots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::Election;
    use crate::board::record_id;
    use crate::board::PollsOpen;
    use crate::ceremony::Context;
    use crate::chain::SpoilReceipt;
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::group::{random_scalar, B};
    use crate::journal::{
        auth_cancel_signature, auth_signature, Journal, PreBu, Record, SectionSig,
    };
    use crate::manifest::Manifest;
    use crate::package::{build_recovered, BoardState, Ingest, Package, PackageKind};
    use crate::registry::sign_registry;
    use crate::tally::{fingerprint, indices, Imported};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const MACHINE: &str = "M-S1-01";
    const RESERVE: &str = "M-R-01";
    const SECTION: &str = "S1";
    const SESSION: &str = "S-1";
    const OPENED_AT: u64 = 1_700_000_000;
    const CHALLENGE: [u8; 16] = [5; 16];
    const APPROVED: Measurement = Measurement([0xaa; 32]);

    struct World {
        manifest: Manifest,
        keys: Keys,
        registry: Registry,
        ctx: Context,
    }

    fn world(min_section_ballots: u64) -> World {
        let (mut manifest, keys) = sample_manifest(1);
        manifest.min_section_ballots = min_section_ballots;
        let registry = sample_registry(&manifest, &keys);
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let ctx = Context {
            manifest_hash: manifest.hash(),
            transcript_hash: [2; 32],
            k: random_scalar(&mut rng) * B,
            z: Vec::new(),
        };
        World {
            manifest,
            keys,
            registry,
            ctx,
        }
    }

    impl World {
        fn election(&self) -> Election<'_> {
            Election {
                context_hash: self.ctx.hash(),
                k: self.ctx.k,
                manifest: &self.manifest,
            }
        }

        fn cfg(&self, machine_idx: usize, machine_id: &str) -> MachineConfig<'_> {
            MachineConfig {
                election: self.election(),
                registry: &self.registry,
                machine_id: machine_id.to_owned(),
                machine_sk: self.keys.machines[machine_idx].clone(),
                measurement: APPROVED,
            }
        }

        fn section_pws(&self) -> Vec<VerifyingKey> {
            self.registry
                .section(SECTION)
                .expect("section")
                .poll_worker_keys
                .clone()
        }
    }

    /// Choices for the six contests of the sample manifest.
    fn picks(row: usize) -> Vec<ContestPlain> {
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

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([8; 32])
    }

    /// Opens the session and signs the zerésima with poll worker `pw`.
    fn open_signed<'a>(
        w: &'a World,
        machine_idx: usize,
        machine: &str,
        session: &str,
    ) -> Session<'a> {
        let (mut s, zv) = Session::open(
            w.cfg(machine_idx, machine),
            SECTION,
            session,
            OPENED_AT,
            CHALLENGE,
        )
        .expect("open");
        s.sign_zeresima(vec![SectionSig::create(&w.keys.poll_workers[0], &zv)])
            .expect("zeresima");
        s
    }

    /// Authorizes the next voter with poll worker `pw`.
    fn authorize(s: &mut Session, w: &World, machine: &str, pw: usize) -> u64 {
        let seq = s.next_auth_seq();
        let key = &w.keys.poll_workers[pw];
        let sig = auth_signature(key, &w.ctx.hash(), machine, s.session_id(), seq);
        s.authorize(key.verifying_key(), sig).expect("authorize")
    }

    /// Full cast of one voter: authorize, encrypt, cast.
    fn vote(s: &mut Session, w: &World, machine: &str, row: usize) -> Value {
        authorize(s, w, machine, 0);
        s.encrypt(&mut rng(), picks(row)).expect("encrypt");
        s.cast().expect("cast")
    }

    fn committed_ballot(records: &[Record], code: [u8; 32]) -> Ballot {
        records
            .iter()
            .find_map(|r| match r {
                Record::Committed { ballot, code: c } if *c == code => Some(ballot.clone()),
                _ => None,
            })
            .expect("committed ballot")
    }

    /// Ballots of the cast records of a journal, in order.
    fn cast_ballots(records: &[Record]) -> Vec<Ballot> {
        let mut open = None;
        let mut out = Vec::new();
        for r in records {
            match r {
                Record::Committed { ballot, .. } => open = Some(ballot.clone()),
                Record::Cast { .. } => out.extend(open.take()),
                Record::Spoiled { .. } | Record::Abandoned { .. } => open = None,
                _ => {}
            }
        }
        out
    }

    /// Finishes a session: pre-BU with one poll worker signature, then close.
    fn finish(s: &mut Session, w: &World, roll: u64) -> (Value, Value) {
        let pb = s.prepare_pre_bu(roll).expect("prepare");
        s.sign_pre_bu(vec![SectionSig::create(&w.keys.poll_workers[0], &pb)])
            .expect("sign pre-bu");
        let pkg = s.close(OPENED_AT + 100).expect("close");
        (pb, pkg)
    }

    fn board_registry_open(w: &World) -> BoardState<'_> {
        let mut board = BoardState::new(&w.manifest, &w.ctx);
        let reg = sign_registry(&w.registry, &w.keys.ea);
        assert_eq!(board.ingest(&reg), Ingest::Accepted);
        let po = PollsOpen {
            context_hash: w.ctx.hash(),
            registry_id: record_id(&reg),
            time: 1,
        }
        .sign(&w.keys.ea);
        assert_eq!(board.ingest(&po), Ingest::Accepted);
        board
    }

    fn truncate(s: &Session, keep: usize) -> Vec<u8> {
        Journal::from_records(s.journal().records()[..keep].to_vec()).to_bytes()
    }

    fn last_index(s: &Session, pred: impl Fn(&Record) -> bool) -> usize {
        s.journal()
            .records()
            .iter()
            .rposition(pred)
            .expect("record present")
    }

    #[test]
    fn full_session_closes_and_the_board_accepts_its_package() {
        let w = world(1);
        let machine_pk = w.keys.machines[0].verifying_key();
        let mut s = open_signed(&w, 0, MACHINE, SESSION);

        // Voter 1 spoils, then casts under the same authorization.
        authorize(&mut s, &w, MACHINE, 0);
        let code1 = s.encrypt(&mut rng(), picks(0)).expect("encrypt");
        let receipt = s.spoil().expect("spoil");
        let r = SpoilReceipt::from_signed(&receipt, &machine_pk).expect("receipt");
        assert_eq!(r.code, code1);
        let spoiled_ballot = committed_ballot(s.journal().records(), code1);
        crate::ballot::check_reveal(
            &w.election(),
            &spoiled_ballot,
            &r.reveal.rho,
            &r.reveal.selections,
        )
        .expect("reveal matches the ballot");
        let code2 = s.encrypt(&mut rng(), picks(1)).expect("encrypt again");
        let slip = Slip::from_signed(&s.cast().expect("cast"), &machine_pk).expect("slip");
        assert_eq!(slip.code, code2);

        // Voter 2 abandons, then re-votes under the same authorization.
        authorize(&mut s, &w, MACHINE, 1);
        s.encrypt(&mut rng(), picks(1)).expect("encrypt");
        s.abandon().expect("abandon");
        s.encrypt(&mut rng(), picks(2)).expect("re-vote");
        s.cast().expect("cast");

        // Voter 3 casts plainly.
        vote(&mut s, &w, MACHINE, 2);

        // An authorization that is cancelled.
        let seq = authorize(&mut s, &w, MACHINE, 0);
        let pw = &w.keys.poll_workers[0];
        let cancel = auth_cancel_signature(pw, &w.ctx.hash(), MACHINE, SESSION, seq);
        s.cancel_authorization(pw.verifying_key(), cancel)
            .expect("cancel");

        let (pb, pkg) = finish(&mut s, &w, 3);

        // Pre-BU counts and fingerprint, recomputed from the package's ballots.
        let pre = PreBu::from_signed(&pb, &machine_pk).expect("pre-bu");
        assert_eq!(
            (pre.authorizations, pre.cast, pre.spoiled, pre.abandoned),
            (4, 3, 1, 1)
        );
        assert_eq!(pre.roll_count, 3);
        let package = Package::from_signed(&pkg, &machine_pk).expect("package");
        let ballots = cast_ballots(&package.records);
        assert_eq!(ballots.len(), 3);
        let offered = w
            .registry
            .machine(MACHINE)
            .expect("machine")
            .contests
            .clone();
        let own: Vec<&Ballot> = ballots.iter().collect();
        let (kept, pooled) = section_sums(&w.election(), &offered, &[], &own, 1);
        assert!(pooled.is_empty());
        assert_eq!(
            kept.iter()
                .find(|c| c.contest == 0)
                .expect("contest 0")
                .counted,
            3
        );
        let expected = fingerprint(
            &w.ctx.hash(),
            MACHINE,
            SESSION,
            &[],
            &kept,
            &indices(&pooled),
        );
        assert_eq!(pre.fingerprint, expected);

        // The journal passes the complete check and the board accepts the package.
        let keys = SessionKeys {
            context_hash: w.ctx.hash(),
            machine_key: machine_pk,
            poll_worker_keys: &w.section_pws(),
            min_section_ballots: 1,
        };
        check_journal(&keys, &Journal::from_records(package.records.clone()), true)
            .expect("complete");
        let mut board = board_registry_open(&w);
        assert_eq!(board.ingest(&pkg), Ingest::Accepted);
        assert_eq!(board.accepted_packages().len(), 1);
    }

    #[test]
    fn refuses_encrypt_without_authorization() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        assert!(s.encrypt(&mut rng(), picks(0)).is_err());
    }

    #[test]
    fn refuses_second_authorization_while_one_is_unused() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        authorize(&mut s, &w, MACHINE, 0);
        let seq = s.next_auth_seq();
        let key = &w.keys.poll_workers[1];
        let sig = auth_signature(key, &w.ctx.hash(), MACHINE, SESSION, seq);
        assert!(s.authorize(key.verifying_key(), sig).is_err());
    }

    #[test]
    fn refuses_cast_with_nothing_pending() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        authorize(&mut s, &w, MACHINE, 0);
        assert!(s.cast().is_err());
    }

    #[test]
    fn refuses_close_and_pre_bu_with_an_unused_authorization() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        vote(&mut s, &w, MACHINE, 0);
        authorize(&mut s, &w, MACHINE, 0);
        assert!(s.prepare_pre_bu(1).is_err());
        assert!(s.close(OPENED_AT).is_err());
    }

    #[test]
    fn refuses_zeresima_signed_by_a_poll_worker_of_another_section() {
        let w = world(1);
        let (mut s, zv) =
            Session::open(w.cfg(0, MACHINE), SECTION, SESSION, OPENED_AT, CHALLENGE).expect("open");
        let other = SectionSig::create(&w.keys.poll_workers[2], &zv);
        assert!(s.sign_zeresima(vec![other]).is_err());
        // Nothing was journaled, so the right signature still works.
        s.sign_zeresima(vec![SectionSig::create(&w.keys.poll_workers[0], &zv)])
            .expect("zeresima");
    }

    #[test]
    fn refuses_authorization_by_a_key_that_is_not_a_poll_worker() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        let machine_key = &w.keys.machines[0];
        let sig = auth_signature(machine_key, &w.ctx.hash(), MACHINE, SESSION, 1);
        assert!(s.authorize(machine_key.verifying_key(), sig).is_err());
    }

    #[test]
    fn restart_after_cast_before_checkpoint_reprints_the_same_slip() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        let slip = vote(&mut s, &w, MACHINE, 0);
        // The cut keeps the cast but drops its checkpoint.
        let cast_at = last_index(&s, |r| matches!(r, Record::Cast { .. }));
        let bytes = truncate(&s, cast_at + 1);

        let (mut s2, reprint) = Session::restart(w.cfg(0, MACHINE), &bytes).expect("restart");
        assert_eq!(reprint, Some(slip));
        assert_eq!(s2.head(), s.head());
        assert!(matches!(
            s2.journal().records().last(),
            Some(Record::Checkpoint { .. })
        ));

        // The session carries on and closes.
        vote(&mut s2, &w, MACHINE, 1);
        let (_, pkg) = finish(&mut s2, &w, 2);
        let package =
            Package::from_signed(&pkg, &w.keys.machines[0].verifying_key()).expect("package");
        let keys = SessionKeys {
            context_hash: w.ctx.hash(),
            machine_key: w.keys.machines[0].verifying_key(),
            poll_worker_keys: &w.section_pws(),
            min_section_ballots: 1,
        };
        check_journal(&keys, &Journal::from_records(package.records), true).expect("complete");
    }

    #[test]
    fn restart_after_committed_abandons_the_ballot() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        authorize(&mut s, &w, MACHINE, 0);
        let code = s.encrypt(&mut rng(), picks(0)).expect("encrypt");
        let committed_at = last_index(&s, |r| matches!(r, Record::Committed { .. }));
        let bytes = truncate(&s, committed_at + 1);

        let (mut s2, reprint) = Session::restart(w.cfg(0, MACHINE), &bytes).expect("restart");
        assert_eq!(reprint, None);
        let abandoned = s2
            .journal()
            .records()
            .iter()
            .any(|r| matches!(r, Record::Abandoned { code: c } if *c == code));
        assert!(abandoned);
        // The authorization is still unused, so the voter can vote again.
        assert_eq!(s2.next_auth_seq(), 2);
        vote_unused(&mut s2);
        let (_, pkg) = finish(&mut s2, &w, 1);
        assert!(Package::from_signed(&pkg, &w.keys.machines[0].verifying_key()).is_ok());
    }

    /// Encrypts and casts under the authorization that is already unused.
    fn vote_unused(s: &mut Session) {
        s.encrypt(&mut rng(), picks(1)).expect("encrypt");
        s.cast().expect("cast");
    }

    #[test]
    fn restart_drops_a_torn_final_frame() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        let slip = vote(&mut s, &w, MACHINE, 0);
        // Cut a few bytes off the final checkpoint: a torn write.
        let full = s.journal().to_bytes();
        let torn = &full[..full.len() - 5];
        assert!(Journal::from_bytes(torn).expect("parse").1, "tail is torn");

        let (mut s2, reprint) = Session::restart(w.cfg(0, MACHINE), torn).expect("restart");
        assert_eq!(reprint, Some(slip));
        assert_eq!(s2.head(), s.head());
        vote(&mut s2, &w, MACHINE, 1);
        finish(&mut s2, &w, 2);
    }

    #[test]
    fn restart_refuses_a_corrupted_middle_frame() {
        let w = world(1);
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        vote(&mut s, &w, MACHINE, 0);
        let bytes = s.journal().to_bytes();
        // Offset of frame 1 (the zerésima): frame 0 is u32 length, body, digest.
        let len0 = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
        let body1 = 4 + len0 + 32 + 4;
        let mut bad = bytes.clone();
        bad[body1 + 5] ^= 0x01;
        assert!(Session::restart(w.cfg(0, MACHINE), &bad).is_err());
    }

    #[test]
    fn recovered_package_is_imported_and_counted_in_the_pre_bu() {
        let w = world(1);
        let reserve_pk = w.keys.machines[2].verifying_key();

        // Machine A casts two ballots, then dies without closing.
        let mut a = open_signed(&w, 0, MACHINE, "S-A");
        vote(&mut a, &w, MACHINE, 0);
        vote(&mut a, &w, MACHINE, 1);
        let mut rp = build_recovered(
            &a.journal().clone(),
            &w.ctx.hash(),
            MACHINE,
            SECTION,
            "S-A",
            APPROVED,
            2,
        )
        .expect("recovered");
        rp.add_sig(&w.keys.poll_workers[1]);
        let rec_value = rp.to_value();

        // The reserve machine imports it, casts one ballot and closes.
        let mut r = open_signed(&w, 2, RESERVE, "S-R");
        r.import_recovered(&rec_value).expect("import");
        vote(&mut r, &w, RESERVE, 2);
        let (pb, pkg) = finish(&mut r, &w, 3);

        let pre = PreBu::from_signed(&pb, &reserve_pk).expect("pre-bu");
        assert_eq!(
            pre.imported,
            vec![Imported {
                package_id: record_id(&rec_value),
                cast: 2,
                last_head: a.head(),
            }]
        );
        assert_eq!(pre.cast, 1, "pre-BU counts are for this session only");

        // The section tally covers all three ballots.
        let imported = cast_ballots(&rp.records);
        let own = cast_ballots(r.journal().records());
        let imported_refs: Vec<&Ballot> = imported.iter().collect();
        let own_refs: Vec<&Ballot> = own.iter().collect();
        let offered = w
            .registry
            .machine(RESERVE)
            .expect("reserve")
            .contests
            .clone();
        let (kept, _) = section_sums(&w.election(), &offered, &imported_refs, &own_refs, 1);
        assert_eq!(
            kept.iter()
                .find(|c| c.contest == 0)
                .expect("contest 0")
                .counted,
            3
        );
        let expected = fingerprint(&w.ctx.hash(), RESERVE, "S-R", &pre.imported, &kept, &[]);
        assert_eq!(pre.fingerprint, expected);

        // The board accepts both entries.
        let mut board = board_registry_open(&w);
        assert_eq!(board.ingest(&rec_value), Ingest::Accepted);
        assert_eq!(board.ingest(&pkg), Ingest::Accepted);
        let kinds: Vec<PackageKind> = board.accepted_packages().iter().map(|p| p.kind).collect();
        assert_eq!(kinds, vec![PackageKind::Recovered, PackageKind::Package]);

        // Spec issue 22: a second session importing the same recovered package
        // would count its ballots twice. The board refuses it (§17.6 rule 10).
        let mut r2 = open_signed(&w, 2, RESERVE, "S-R2");
        r2.import_recovered(&rec_value).expect("the machine itself cannot know");
        vote(&mut r2, &w, RESERVE, 0);
        let (_, pkg2) = finish(&mut r2, &w, 3);
        match board.ingest(&pkg2) {
            Ingest::Rejected(reason) => assert!(reason.contains("rule 10"), "{reason}"),
            Ingest::Accepted => panic!("a double import was accepted"),
        }
    }

    #[test]
    fn imports_are_journaled_and_must_be_reloaded_after_a_restart() {
        // Spec issue 17: imports used to live only in memory, so a restart
        // before the pre-BU silently dropped the dead machine's ballots.
        let w = world(1);
        let mut a = open_signed(&w, 0, MACHINE, "S-A");
        vote(&mut a, &w, MACHINE, 0);
        let mut rp = build_recovered(
            &a.journal().clone(),
            &w.ctx.hash(),
            MACHINE,
            SECTION,
            "S-A",
            APPROVED,
            2,
        )
        .expect("recovered");
        rp.add_sig(&w.keys.poll_workers[1]);
        let rec_value = rp.to_value();

        let mut r = open_signed(&w, 2, RESERVE, "S-R");
        r.import_recovered(&rec_value).expect("import");
        vote(&mut r, &w, RESERVE, 2);
        let imports = |s: &Session| {
            s.journal()
                .records()
                .iter()
                .filter(|x| matches!(x, Record::Import(_)))
                .count()
        };
        assert_eq!(imports(&r), 1, "the import is journaled");
        let before = r.prepare_pre_bu(2).expect("pre-BU before the crash");

        // Crash and restart: the pre-BU is refused until the package is loaded again.
        let bytes = r.journal().to_bytes();
        let (mut r2, _) = Session::restart(w.cfg(2, RESERVE), &bytes).expect("restart");
        match r2.prepare_pre_bu(2) {
            Err(Error::Journal(msg)) => assert!(msg.contains("import"), "{msg}"),
            other => panic!("expected a missing-import error, got {other:?}"),
        }
        r2.import_recovered(&rec_value).expect("re-import");
        assert_eq!(imports(&r2), 1, "re-importing does not journal it again");
        assert_eq!(r2.prepare_pre_bu(2).expect("pre-BU after restart"), before);
        assert!(r2.import_recovered(&rec_value).is_err(), "no double import");
    }

    #[test]
    fn small_section_pools_every_homomorphic_contest() {
        let w = world(5);
        let machine_pk = w.keys.machines[0].verifying_key();
        let mut s = open_signed(&w, 0, MACHINE, SESSION);
        for row in 0..3 {
            vote(&mut s, &w, MACHINE, row);
        }
        let (pb, _) = finish(&mut s, &w, 3);
        let pre = PreBu::from_signed(&pb, &machine_pk).expect("pre-bu");
        // Contest 3 is mixnet and never enters a homomorphic tally.
        assert_eq!(pre.pooled, vec![0, 1, 2, 4, 5]);

        let ballots = cast_ballots(s.journal().records());
        let own: Vec<&Ballot> = ballots.iter().collect();
        let offered = w
            .registry
            .machine(MACHINE)
            .expect("machine")
            .contests
            .clone();
        let (kept, pooled) = section_sums(&w.election(), &offered, &[], &own, 5);
        assert!(kept.is_empty());
        assert_eq!(
            pooled.iter().map(|c| c.counted).collect::<Vec<_>>(),
            vec![3, 3, 3, 3, 3]
        );
        let expected = fingerprint(
            &w.ctx.hash(),
            MACHINE,
            SESSION,
            &[],
            &kept,
            &indices(&pooled),
        );
        assert_eq!(pre.fingerprint, expected);
    }
}
