import type { FindingDto, ReportDto } from '../types';
import { groupHex } from '../format';

/** Titles of the 16 steps of §23, in order. */
const STEP_NAMES = [
  'Board',
  'Manifest',
  'Key ceremony',
  'Context',
  'Registry & freeze',
  'Packages',
  'Completeness',
  'Spoiled ballots',
  'Homomorphic tally',
  'Mixnet',
  'Decryption',
  'Final BUs',
  'Counts',
  'Apportionment',
  'Result',
  'Independence',
];

function FindingLine({ f, kind }: { f: FindingDto; kind: 'fail' | 'warn' }) {
  const where = [f.entry !== null ? `entry ${f.entry}` : null, f.section ? `section ${f.section}` : null]
    .filter(Boolean)
    .join(', ');
  return (
    <p className={kind === 'fail' ? 'step-msg step-fail' : 'step-msg step-warn'}>
      {where && <span className="mono">{where}: </span>}
      {f.message}
    </p>
  );
}

/** A paper audit sheet: the 16 steps, each ticked or stamped, then the independence report. */
export function AuditSheet({ report }: { report: ReportDto }) {
  const known = new Set(STEP_NAMES.map((_, i) => i + 1));
  const stray = report.failures.filter((f) => !known.has(f.step));
  const strayWarn = report.warnings.filter((f) => !known.has(f.step));
  const ind = report.independence;

  return (
    <article className="sheet" aria-label="Verifier audit sheet">
      <header className="sheet-head">
        <div className="sheet-title">VERIFICAÇÃO · §23</div>
        <div className="sheet-sub">16 steps, run from the public board alone</div>
        <div className={report.passed ? 'sheet-verdict pass' : 'sheet-verdict fail'}>
          {report.passed ? 'All checks passed' : 'Checks failed'}
        </div>
      </header>

      <ol className="steps">
        {STEP_NAMES.map((name, i) => {
          const n = i + 1;
          const fails = report.failures.filter((f) => f.step === n);
          const warns = report.warnings.filter((f) => f.step === n);
          return (
            <li key={n} className="step">
              <div className="step-row">
                <span className="step-num mono">{n}</span>
                <span className="step-name">{name}</span>
                {fails.length > 0 ? (
                  <span className="stamp" aria-label="failed">
                    FAILED
                  </span>
                ) : (
                  <span className="tick" aria-label="passed">
                    ✓
                  </span>
                )}
              </div>
              {fails.map((f, j) => (
                <FindingLine key={`f${j}`} f={f} kind="fail" />
              ))}
              {warns.map((f, j) => (
                <FindingLine key={`w${j}`} f={f} kind="warn" />
              ))}
            </li>
          );
        })}
      </ol>

      {(stray.length > 0 || strayWarn.length > 0) && (
        <section className="sheet-block">
          <h4>Other findings</h4>
          {stray.map((f, j) => (
            <FindingLine key={`s${j}`} f={f} kind="fail" />
          ))}
          {strayWarn.map((f, j) => (
            <FindingLine key={`sw${j}`} f={f} kind="warn" />
          ))}
        </section>
      )}

      {report.excluded.length > 0 && (
        <section className="sheet-block">
          <h4>Excluded ballots ({report.excluded.length})</h4>
          {report.excluded.map((f, j) => (
            <FindingLine key={`x${j}`} f={f} kind="warn" />
          ))}
        </section>
      )}

      {report.result && (
        <section className="sheet-block">
          <h4>Verified result</h4>
          {report.result.contests.map((c) => (
            <div key={c.index} className="sheet-result">
              <div className="label">{c.name}</div>
              {c.votes.map((v) => (
                <div key={v.option} className="sheet-row">
                  <span>{v.option}</span>
                  <span className="mono">{v.votes}</span>
                </div>
              ))}
              <div className="muted small">
                counted {c.counted} · invalid {c.invalid} · excluded {c.excluded}
              </div>
            </div>
          ))}
        </section>
      )}

      <section className="sheet-block">
        <h4>Independence</h4>
        {report.contextHash && (
          <p className="small">
            Context <span className="mono">{groupHex(report.contextHash)}</span>
          </p>
        )}
        <PartyList title="Trustees" items={ind.trustees} />
        <PartyList title="Release signers" items={ind.releaseSigners} />
        <PartyList title="Mirrors" items={ind.mirrors} />
        <div className="label">Rules 11 to 13</div>
        <ul className="rules">
          {ind.rules.map((r) => (
            <li key={r.rule} className={r.ok ? 'check-ok' : 'check-fail'}>
              Rule {r.rule} {r.ok ? '✓ ok' : '✗ fails'}
            </li>
          ))}
        </ul>
        {ind.partyKeys.length > 0 && (
          <>
            <div className="label">Party keys</div>
            <ul className="small">
              {ind.partyKeys.map((k) => (
                <li key={k.party}>
                  {k.party}: {k.fingerprint ? <span className="mono">{k.fingerprint}</span> : 'no key'}
                </li>
              ))}
            </ul>
          </>
        )}
        <div className="label">Sections without observer signatures</div>
        <p className="small">
          {ind.sectionsWithoutObserver.length === 0
            ? 'None. Every section has an observer signature.'
            : ind.sectionsWithoutObserver.join(', ')}
        </p>
        {ind.partiesWithoutObserver.length > 0 && (
          <>
            <div className="label">Parties without observer signatures</div>
            <p className="small">{ind.partiesWithoutObserver.join(', ')}</p>
          </>
        )}
      </section>
    </article>
  );
}

function PartyList({
  title,
  items,
}: {
  title: string;
  items: { organisation: string; bloc: string; fingerprint: string }[];
}) {
  if (items.length === 0) return null;
  return (
    <>
      <div className="label">{title}</div>
      <ul className="parties">
        {items.map((p) => (
          <li key={p.organisation + p.fingerprint}>
            <span>{p.organisation}</span> <span className="bloc">{p.bloc}</span>
            <div className="hash">{p.fingerprint}</div>
          </li>
        ))}
      </ul>
    </>
  );
}
