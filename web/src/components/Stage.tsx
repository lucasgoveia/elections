import { useState, type ReactNode } from 'react';
import {
  allMachines,
  attackOpen,
  availableScenarios,
  blankSession,
  useSim,
  type MachineUi,
} from '../sim';
import type {
  AttacksDto,
  CeremonyDto,
  ElectionDto,
  PreBuDto,
  ReportDto,
  ResultDto,
  SthDto,
  StripData,
  ZeresimaDto,
} from '../types';

/** The left column: who acts in the current phase, and the buttons they press. */
export function Stage() {
  const { snap } = useSim();
  const phase = snap.phase;
  return (
    <section className="stage" aria-labelledby="stage-title">
      <h2 id="stage-title" className="col-title">
        Stage
      </h2>

      {phase === 'setup' && <CeremonyPanel />}
      {phase === 'ceremony-done' && <PollsPanel />}
      {phase === 'polls-open' && (
        <>
          <VotingPanel />
          <ClosePanel />
        </>
      )}
      {phase === 'polls-closed' && <TallyPanel />}
      {phase === 'tallied' && <VerifyPanel />}

      <Sabotage />
      <NewElection />
    </section>
  );
}

function Panel({ step, title, who, children }: { step: string; title: string; who: string; children: ReactNode }) {
  return (
    <div className="panel">
      <div className="panel-step">{step}</div>
      <h3 className="panel-title">{title}</h3>
      <p className="muted small">
        <strong>Who acts:</strong> {who}
      </p>
      <div className="panel-body">{children}</div>
    </div>
  );
}

// -- ceremony -------------------------------------------------------------------

function CeremonyPanel() {
  const { snap, busy, run, update } = useSim();
  const election = snap.election;
  return (
    <Panel
      step="Ceremony"
      title="Key ceremony"
      who={`the trustees (${election.trustees.length}), each in its own bloc. They make the joint key with no single holder.`}
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run('Running key ceremony…', (sim) => sim.run_ceremony());
          if (r) update((u) => ({ ...u, ceremony: r as CeremonyDto }));
        }}
      >
        {busy === 'Running key ceremony…' ? 'Working…' : 'Run key ceremony'}
      </button>
      <RunWholeElection />
    </Panel>
  );
}

function RunWholeElection() {
  const { busy, run, update } = useSim();
  return (
    <div className="shortcut">
      <button
        type="button"
        className="btn"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run('Running the whole election…', (sim) => sim.run_all());
          if (!r) return;
          const view = r as ResultDto;
          const stripData: StripData = {
            kind: 'result',
            result: view,
            note: 'Printed by Run whole election. Its intermediate strips are not shown.',
          };
          update((u) => {
            const sessions: Record<string, MachineUi> = {};
            for (const [id, m] of Object.entries(u.sessions)) {
              sessions[id] = m.open ? { ...m, open: false, closed: true, authorized: false, pending: false } : m;
            }
            return {
              ...u,
              result: view,
              sessions,
              strips: [{ id: u.nextStripId, data: stripData }, ...u.strips].slice(0, 40),
              nextStripId: u.nextStripId + 1,
            };
          });
        }}
      >
        {busy === 'Running the whole election…' ? 'Working…' : 'Run whole election'}
      </button>
      <p className="muted small">
        Shortcut: runs the ceremony, opens polls, casts random ballots on every machine, closes, tallies and
        signs. Each step is still on the board.
      </p>
    </div>
  );
}

// -- polls ----------------------------------------------------------------------

function PollsPanel() {
  const { busy, run } = useSim();
  return (
    <Panel
      step="Polls"
      title="Open polls"
      who="the EA (election authority). It posts the signed registry and the polls_open record."
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={() =>
          run('Opening polls…', (sim) => {
            sim.open_polls();
            return true;
          })
        }
      >
        {busy === 'Opening polls…' ? 'Working…' : 'Open polls'}
      </button>
    </Panel>
  );
}

// -- voting ---------------------------------------------------------------------

function VotingPanel() {
  const { snap } = useSim();
  const election = snap.election;
  const [sectionId, setSectionId] = useState(election.sections[0]?.id ?? '');
  const section = election.sections.find((s) => s.id === sectionId) ?? election.sections[0];
  return (
    <Panel
      step="Voting"
      title="Sessions and voters"
      who="the mesário (poll worker) opens a session and authorizes each voter. The voter uses the urna in the workbench."
    >
      {election.sections.length > 0 && (
        <label className="field">
          <span>Section</span>
          <select value={section?.id ?? ''} onChange={(e) => setSectionId(e.target.value)}>
            {election.sections.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} · {s.region}
              </option>
            ))}
          </select>
        </label>
      )}
      {section && (
        <ul className="machines" aria-label={`Machines of section ${section.id}`}>
          {section.machines.map((m) => (
            <MachineCard key={m} id={m} />
          ))}
        </ul>
      )}
      {election.reserveMachines.length > 0 && (
        <>
          <h4 className="subhead">Reserve machines</h4>
          <ul className="machines">
            {election.reserveMachines.map((m) => (
              <MachineCard key={m} id={m} reserve election={election} />
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

function ClosePanel() {
  const { busy, run, update } = useSim();
  return (
    <div className="panel">
      <div className="panel-step">Close</div>
      <h3 className="panel-title">Close polls</h3>
      <p className="muted small">
        <strong>Who acts:</strong> the EA. Any session still open is closed first, then tally_cutoff is posted. A section whose machine never opened has no package, and the verifier lists it as missing (step 7).
      </p>
      <button
        type="button"
        className="btn"
        disabled={busy !== null}
        onClick={async () => {
          const ok = await run('Closing polls…', (sim) => {
            sim.cutoff();
            return true;
          });
          if (ok)
            update((u) => ({
              ...u,
              sessions: Object.fromEntries(
                Object.entries(u.sessions).map(([id, m]) => [
                  id,
                  m.open ? { ...m, open: false, closed: true, authorized: false, pending: false } : m,
                ]),
              ),
            }));
        }}
      >
        {busy === 'Closing polls…' ? 'Working…' : 'Close polls'}
      </button>
    </div>
  );
}

/** One machine: its session state, and the poll worker's buttons. */
function MachineCard({ id, reserve, election }: { id: string; reserve?: boolean; election?: ElectionDto }) {
  const { ui, busy, run, patchSession, addStrip } = useSim();
  const s: MachineUi = ui.sessions[id] ?? blankSession();
  const [pick, setPick] = useState('');
  const sections = election?.sections.map((x) => x.id) ?? [];

  const status = !s.open
    ? s.closed
      ? 'closed'
      : 'not opened'
    : s.pending
      ? 'ballot in progress'
      : s.authorized
        ? 'voter authorized'
        : 'open, waiting for a voter';

  const idle = busy === null;
  const sectionForOpen = reserve ? pick : null;

  return (
    <li className="machine">
      <div className="machine-head">
        <span className="mono">{id}</span>
        <span className={`badge badge-${s.open ? 'open' : s.closed ? 'closed' : 'idle'}`}>{status}</span>
      </div>
      <div className="counters muted small">
        cast {s.cast} · spoiled {s.spoiled} · abandoned {s.abandoned}
      </div>
      <div className="machine-actions">
        {!s.open && (
          <>
            {reserve && (
              <label className="field inline">
                <span>Stands in for</span>
                <select value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Pick a section</option>
                  {sections.map((x) => (
                    <option key={x} value={x}>
                      {x}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button
              type="button"
              className="btn"
              disabled={!idle || (reserve && !pick)}
              onClick={async () => {
                const z = await run(`Opening ${id}…`, (sim) => sim.open_session(id, sectionForOpen));
                if (!z) return;
                addStrip({ kind: 'zeresima', zeresima: z as ZeresimaDto });
                patchSession(id, () => ({ ...blankSession(), open: true }));
              }}
            >
              {busy === `Opening ${id}…` ? 'Working…' : 'Open session'}
            </button>
          </>
        )}
        {s.open && (
          <>
            <button
              type="button"
              className="btn"
              disabled={!idle || s.authorized || s.pending}
              onClick={async () => {
                const seq = await run(`Authorizing on ${id}…`, (sim) => sim.authorize(id));
                if (seq !== undefined) patchSession(id, () => ({ authorized: true }));
              }}
            >
              {busy === `Authorizing on ${id}…` ? 'Working…' : 'Authorize voter'}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || s.authorized || s.pending}
              onClick={async () => {
                const ok = await run(`Casting on ${id}…`, (sim) => {
                  sim.cast_random(id, 5);
                  return true;
                });
                if (ok) patchSession(id, (m) => ({ cast: m.cast + 5, authorized: false }));
              }}
            >
              {busy === `Casting on ${id}…` ? 'Working…' : 'Cast 5 random ballots'}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || !s.pending}
              onClick={async () => {
                const ok = await run(`Abandoning on ${id}…`, (sim) => {
                  sim.abandon(id);
                  return true;
                });
                if (ok) patchSession(id, (m) => ({ pending: false, abandoned: m.abandoned + 1 }));
              }}
            >
              Abandon ballot
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || s.pending}
              onClick={async () => {
                const pre = await run(`Closing ${id}…`, (sim) => sim.close_session(id));
                if (!pre) return;
                addStrip({ kind: 'prebu', prebu: pre as PreBuDto });
                patchSession(id, () => ({ open: false, closed: true, authorized: false, pending: false }));
              }}
            >
              {busy === `Closing ${id}…` ? 'Working…' : 'Close session'}
            </button>
          </>
        )}
      </div>
    </li>
  );
}

// -- tally, verify --------------------------------------------------------------

function TallyPanel() {
  const { busy, run, update, addStrip } = useSim();
  return (
    <Panel
      step="Tally"
      title="Run tally"
      who="the trustees decrypt the homomorphic totals and the mixnet runs; the EA signs the result."
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run('Tallying…', (sim) => sim.tally());
          if (!r) return;
          const view = r as ResultDto;
          update((u) => ({ ...u, result: view }));
          addStrip({ kind: 'result', result: view });
          // The board signs a tree head over the published tally, so the
          // verifier has a signed root to check the dump against (§17.3).
          const heads = await run('Signing…', (sim) => sim.sign_sth());
          if (!heads) return;
          const list = heads as SthDto[];
          update((u) => ({ ...u, sths: [...u.sths, ...list] }));
          for (const h of list) addStrip({ kind: 'sth', sth: h });
        }}
      >
        {busy === 'Tallying…' ? 'Working…' : 'Run tally'}
      </button>
    </Panel>
  );
}

function VerifyPanel() {
  const { busy, run, update, addStrip } = useSim();
  return (
    <>
      <Panel
        step="Tally"
        title="Sign tree head"
        who="the board. It signs the size and root of the log, so anyone can check later that nothing was added or removed."
      >
        <button
          type="button"
          className="btn"
          disabled={busy !== null}
          onClick={async () => {
            const heads = await run('Signing…', (sim) => sim.sign_sth());
            if (!heads) return;
            const list = heads as SthDto[];
            update((u) => ({ ...u, sths: [...u.sths, ...list] }));
            for (const h of list) addStrip({ kind: 'sth', sth: h });
          }}
        >
          {busy === 'Signing…' ? 'Working…' : 'Sign tree head'}
        </button>
      </Panel>
      <Panel
        step="Verify"
        title="Run verifier"
        who="anyone, from the public board alone. The 16 steps of §23 run in the workbench, with no keys."
      >
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy !== null}
          onClick={async () => {
            const rep = await run('Verifying…', (sim) => sim.verify());
            if (rep) update((u) => ({ ...u, report: rep as ReportDto }));
          }}
        >
          {busy === 'Verifying…' ? 'Working…' : 'Run verifier'}
        </button>
      </Panel>
    </>
  );
}

// -- sabotage -------------------------------------------------------------------

const ATTACKS: { key: keyof AttacksDto; label: string; does: string; caught: string }[] = [
  {
    key: 'machineFlipsVotes',
    label: 'Machine flips votes',
    does: "The machine encrypts a different choice for the first contest than the voter made. Its spoil receipt claims the voter's choice.",
    caught: 'a spoil audit (§14.2): "Check this receipt independently" re-encrypts the claim.',
  },
  {
    key: 'boardDropsPackageOf',
    label: "Board drops a machine's package",
    does: "The board never stores that machine's closed-session package. The section attestation is still posted.",
    caught: 'Packages and Completeness (steps 6 and 7).',
  },
  {
    key: 'trusteeLies',
    label: 'Trustee lies in decryption',
    does: 'One trustee signs corrupted decryption shares.',
    caught: 'Decryption (step 11): the bad shares are rejected and the tally still completes.',
  },
  {
    key: 'eaAltersResult',
    label: 'EA alters the result',
    does: 'The EA adds 100 votes to the first option of the first contest before signing the result.',
    caught: 'Counts (step 13) and Result (step 15): the published result differs from the recount.',
  },
  {
    key: 'boardEquivocates',
    label: 'Board equivocates',
    does: 'After the first tree head, the board signs a second head of the same size over an altered log.',
    caught: 'Board (step 1): two signed heads of one size disagree.',
  },
  {
    key: 'badDkgShare',
    label: 'Bad DKG share',
    does: 'One trustee sends another a share that does not match its commitments.',
    caught: 'Key ceremony (step 3): the receiver complains and the sender reveals the correct share.',
  },
];

function Sabotage() {
  const { snap, busy, run } = useSim();
  const a = snap.attacks;
  const phase = snap.phase;

  async function setAttack(patch: Partial<AttacksDto>) {
    await run('Setting attacks…', (sim) => {
      sim.set_attacks({ ...a, ...patch });
      return true;
    });
  }

  return (
    <details className="sabotage">
      <summary>Sabotage</summary>
      <p className="muted small">
        Deliberate misbehaviour, switched on before the step it affects. Each one says what should catch it.
      </p>
      {ATTACKS.map((t) => {
        const open = attackOpen(t.key, phase);
        const on = t.key === 'boardDropsPackageOf' ? a.boardDropsPackageOf !== null : Boolean(a[t.key]);
        return (
          <div key={t.key} className="attack">
            <div className="attack-head">
              <span className="attack-label">{t.label}</span>
              {t.key === 'boardDropsPackageOf' ? (
                <select
                  aria-label="Machine whose package is dropped"
                  value={a.boardDropsPackageOf ?? ''}
                  disabled={!open || busy !== null}
                  onChange={(e) => setAttack({ boardDropsPackageOf: e.target.value || null })}
                >
                  <option value="">Off</option>
                  {allMachines(snap.election).map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.id}
                    </option>
                  ))}
                </select>
              ) : (
                <button
                  type="button"
                  role="switch"
                  aria-checked={on}
                  className={`switch ${on ? 'switch-on' : ''}`}
                  disabled={!open || busy !== null}
                  onClick={() => setAttack({ [t.key]: !on } as Partial<AttacksDto>)}
                >
                  {on ? 'On' : 'Off'}
                </button>
              )}
            </div>
            <p className="small">{t.does}</p>
            <p className="small muted">
              <strong>Caught by:</strong> {t.caught}
            </p>
            {!open && <p className="small muted">Locked: this step has already passed.</p>}
          </div>
        );
      })}
    </details>
  );
}

// -- new election ---------------------------------------------------------------

function NewElection() {
  const { busy, newElection } = useSim();
  const scenarios = availableScenarios();
  const [scenario, setScenario] = useState(scenarios[0]?.id ?? 'star-wars');
  const [confirming, setConfirming] = useState(false);
  return (
    <div className="new-election">
      <label className="field">
        <span>Scenario</span>
        <select value={scenario} onChange={(e) => setScenario(e.target.value)} disabled={busy !== null}>
          {scenarios.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        className={confirming ? 'btn btn-danger' : 'btn'}
        disabled={busy !== null}
        onClick={() => {
          if (!confirming) {
            setConfirming(true);
            return;
          }
          setConfirming(false);
          newElection(scenario);
        }}
        onBlur={() => setConfirming(false)}
      >
        {confirming ? 'New election → Click again to discard the current one' : 'New election'}
      </button>
    </div>
  );
}
