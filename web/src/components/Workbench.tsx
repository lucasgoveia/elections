import { useState } from 'react';
import { allMachines, useSim } from '../sim';
import type { LookupDto, ResultContestDto, ResultDto, TrusteeDto } from '../types';
import { groupHex } from '../format';
import { Urna } from './Urna';
import { AuditSheet } from './AuditSheet';

/** The middle column: the view for the current phase. */
export function Workbench() {
  const { snap } = useSim();
  const phase = snap.phase;
  return (
    <section className="workbench" aria-labelledby="bench-title">
      <header className="bench-head">
        <h2 id="bench-title" className="col-title">
          Workbench
        </h2>
        <p className="election-title">{snap.election.title}</p>
      </header>
      {(phase === 'setup' || phase === 'ceremony-done') && <CeremonyView />}
      {phase === 'polls-open' && <VotingView />}
      {phase === 'polls-closed' && (
        <p className="lead">
          Polls are closed. The trustees decrypt the totals and the EA signs the result when the tally runs.
        </p>
      )}
      {phase === 'tallied' && (
        <>
          <ResultsView />
          <VerifyView />
        </>
      )}
    </section>
  );
}

// -- ceremony -------------------------------------------------------------------

function TrusteeCard({ t, total }: { t: TrusteeDto; total: number }) {
  return (
    <li className="trustee">
      <div className="trustee-head">
        <span className="bloc">{t.bloc}</span>
        <span className="muted small">
          trustee {t.index} of {total}
        </span>
      </div>
      <div className="trustee-name">{t.name}</div>
    </li>
  );
}

function CeremonyView() {
  const { snap, ui } = useSim();
  const trustees = snap.election.trustees;
  const c = ui.ceremony;
  return (
    <>
      <h3 className="subhead">Trustees</h3>
      <ul className="trustees">
        {trustees.map((t) => (
          <TrusteeCard key={t.index} t={t} total={trustees.length} />
        ))}
      </ul>
      <p className="muted small">
        Any subset of trustees smaller than the threshold learns nothing. The election key is never held by one
        party.
      </p>
      {c ? (
        <div className="ceremony">
          <p>
            Threshold <strong>{c.k} of {c.n}</strong>. Complaints: {c.complaints.length}
            {c.complaints.length === 0 ? '' : ' (each resolved by a reveal)'}.
          </p>
          {c.complaints.map((x) => (
            <p key={x} className="small">
              {x}
            </p>
          ))}
          <div className="label">Joint key</div>
          <div className="hash">{groupHex(c.jointKeyHex)}</div>
          <div className="label">Context hash</div>
          <div className="hash">{groupHex(c.contextHashHex)}</div>
        </div>
      ) : (
        <p className="lead">Run the key ceremony in the stage column to create the joint key.</p>
      )}
    </>
  );
}

// -- voting ---------------------------------------------------------------------

function VotingView() {
  const { snap } = useSim();
  const machines = allMachines(snap.election);
  const [machineId, setMachineId] = useState(machines[0]?.id ?? '');
  const current = machines.find((m) => m.id === machineId) ?? machines[0];
  return (
    <>
      <div className="machine-picker">
        <label className="field">
          <span>Machine</span>
          <select value={current?.id ?? ''} onChange={(e) => setMachineId(e.target.value)}>
            {machines.map((m) => (
              <option key={m.id} value={m.id}>
                {m.id}
                {m.section ? ` · ${m.section}` : ' · reserve'}
              </option>
            ))}
          </select>
        </label>
      </div>
      {current && <Urna key={current.id} machineId={current.id} />}
    </>
  );
}

// -- results --------------------------------------------------------------------

function ResultCard({ c, featured }: { c: ResultContestDto; featured?: boolean }) {
  const max = Math.max(1, ...c.options.map((o) => o.votes));
  const leader = [...c.options].sort((a, b) => b.votes - a.votes)[0];
  const tied = leader ? c.options.filter((o) => o.votes === leader.votes) : [];
  return (
    <article className={featured ? 'result result-featured' : 'result'} aria-label={c.name}>
      <header>
        <h3 className={featured ? 'result-title display' : 'result-title'}>{c.name}</h3>
        {featured && leader && (
          <p className="result-lead">
            <span className="display big">{leader.votes}</span>{' '}
            <span>{tied.length > 1 ? `Tie: ${tied.map((o) => o.name).join(', ')}` : leader.name}</span>
          </p>
        )}
      </header>
      <ul className="bars">
        {c.options.map((o) => (
          <li key={o.name} className="bar-row">
            <span className="bar-name">{o.name}</span>
            <span className="bar-track" aria-hidden="true">
              <span className="bar-fill" style={{ width: `${(o.votes / max) * 100}%` }} />
            </span>
            <span className="bar-votes mono">{o.votes}</span>
          </li>
        ))}
      </ul>
      <p className="muted small">
        counted {c.counted} · invalid {c.invalid} · excluded {c.excluded}
      </p>
      {c.seats && c.seats.length > 0 && (
        <ul className="seats">
          {c.seats.map((s) => (
            <li key={s.candidate}>
              {s.candidate} <span className="muted">· {s.party}</span>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function ResultsView() {
  const { ui } = useSim();
  const result: ResultDto | null = ui.result;
  if (!result) {
    return <p className="lead">The tally has not been printed yet. Run it in the stage column.</p>;
  }
  const [first, ...rest] = result.contests;
  return (
    <section aria-labelledby="results-title">
      <h3 id="results-title" className="subhead">
        Result
      </h3>
      {first && <ResultCard c={first} featured />}
      {rest.length > 0 && (
        <div className="result-grid">
          {rest.map((c) => (
            <ResultCard key={c.index} c={c} />
          ))}
        </div>
      )}
      <div className="section-chips" aria-label="Section tallies against the pre-BU">
        {result.sections.map((s) => (
          <span key={s.id} className={`chip ${s.matches ? 'chip-ok' : 'chip-fail'}`}>
            {s.id} {s.matches ? 'match' : 'mismatch'}
          </span>
        ))}
      </div>
    </section>
  );
}

// -- verify ---------------------------------------------------------------------

function VerifyView() {
  const { ui } = useSim();
  return (
    <section className="verify" aria-labelledby="verify-title">
      <h3 id="verify-title" className="subhead">
        Verify
      </h3>
      {ui.report ? (
        <AuditSheet report={ui.report} />
      ) : (
        <p className="lead">Run the verifier in the stage column to check the whole board, step by step.</p>
      )}
      <LookupBox />
    </section>
  );
}

function LookupBox() {
  const { ui, busy, run, update } = useSim();
  const [code, setCode] = useState('');
  const look: LookupDto | null = ui.lookup;
  return (
    <div className="lookup">
      <h4 className="subhead">Look up my code</h4>
      <p className="muted small">
        Type the short code from your slip. The lookup reads the public board, not the machine.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run('Looking up…', (sim) => sim.lookup(code.trim()));
          if (r) update((u) => ({ ...u, lookup: r as LookupDto }));
        }}
      >
        <label className="field">
          <span>Short code</span>
          <input
            className="mono"
            value={code}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy !== null || code.trim() === ''}>
          {busy === 'Looking up…' ? 'Working…' : 'Look up my code'}
        </button>
      </form>
      {look && <LookupResult look={look} />}
    </div>
  );
}

function LookupResult({ look }: { look: LookupDto }) {
  if (!look.found) {
    return (
      <p className="lookup-result" role="status">
        No ballot with this code is on the board. Check the short code on your slip. If polls are still open,
        the package appears on the board when the session closes.
      </p>
    );
  }
  return (
    <div className="lookup-result" role="status">
      <p>
        Found at board entry <strong>#{look.entryIndex}</strong> on {look.machineId}. Status:{' '}
        <strong>{look.status}</strong>.
      </p>
      <p className={look.inclusionProofVerifies ? 'check-ok' : 'check-fail'}>
        {look.inclusionProofVerifies
          ? '✓ Inclusion proof verifies against the latest tree head.'
          : '✗ Inclusion proof does not verify against the latest tree head. Sign a tree head.'}
      </p>
      {look.contestsCounted.length > 0 && (
        <ul className="counted">
          {look.contestsCounted.map((c) => (
            <li key={c.contest}>
              Contest {c.contest}:{' '}
              {c.counted === null ? 'tally not run yet' : c.counted ? '✓ counted' : '✗ not counted'}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
