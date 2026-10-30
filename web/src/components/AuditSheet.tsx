import type { FindingDto, ReportDto } from '../types';
import { groupHex } from '../format';

/** Titles of the 16 steps of §23, in order, in pt-BR. */
const STEP_NAMES = [
  'Mural',
  'Manifesto',
  'Cerimônia de chaves',
  'Contexto',
  'Registro e congelamento',
  'Pacotes',
  'Completude',
  'Cédulas auditadas',
  'Apuração homomórfica',
  'Mixnet',
  'Decriptação',
  'BUs finais',
  'Contagem',
  'Distribuição de cadeiras',
  'Resultado',
  'Independência',
];

/** A finding: where it is, then the message as the Rust verifier wrote it (English), labelled as technical detail. */
function FindingLine({ f, kind }: { f: FindingDto; kind: 'fail' | 'warn' }) {
  const where = [f.entry !== null ? `entrada ${f.entry}` : null, f.section ? `seção ${f.section}` : null]
    .filter(Boolean)
    .join(', ');
  return (
    <p className={kind === 'fail' ? 'step-msg step-fail' : 'step-msg step-warn'}>
      {where && <span className="mono">{where}: </span>}
      <span className="tech-label">detalhe técnico</span> {f.message}
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
    <article className="sheet" aria-label="Folha de verificação">
      <header className="sheet-head">
        <div className="sheet-title">VERIFICAÇÃO · §23</div>
        <div className="sheet-sub">16 passos, rodados só com o mural público</div>
        <div className={report.passed ? 'sheet-verdict pass' : 'sheet-verdict fail'}>
          {report.passed ? 'Todas as verificações passaram' : 'Verificações falharam'}
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
                  <span className="stamp" aria-label="falhou">
                    FALHOU
                  </span>
                ) : (
                  <span className="tick" aria-label="passou">
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
          <h4>Outros achados</h4>
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
          <h4>Cédulas excluídas ({report.excluded.length})</h4>
          {report.excluded.map((f, j) => (
            <FindingLine key={`x${j}`} f={f} kind="warn" />
          ))}
        </section>
      )}

      {report.result && (
        <section className="sheet-block">
          <h4>Resultado verificado</h4>
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
                contadas {c.counted} · inválidas {c.invalid} · excluídas {c.excluded}
              </div>
            </div>
          ))}
        </section>
      )}

      <section className="sheet-block">
        <h4>Independência</h4>
        {report.contextHash && (
          <p className="small">
            Contexto <span className="mono">{groupHex(report.contextHash)}</span>
          </p>
        )}
        <PartyList title="Guardiões da chave" items={ind.trustees} />
        <PartyList title="Assinantes da liberação" items={ind.releaseSigners} />
        <PartyList title="Espelhos" items={ind.mirrors} />
        <div className="label">Regras 11 a 13</div>
        <ul className="rules">
          {ind.rules.map((r) => (
            <li key={r.rule} className={r.ok ? 'check-ok' : 'check-fail'}>
              Regra {r.rule} {r.ok ? '✓ ok' : '✗ falha'}
            </li>
          ))}
        </ul>
        {ind.partyKeys.length > 0 && (
          <>
            <div className="label">Chaves dos partidos</div>
            <ul className="small">
              {ind.partyKeys.map((k) => (
                <li key={k.party}>
                  {k.party}: {k.fingerprint ? <span className="mono">{k.fingerprint}</span> : 'sem chave'}
                </li>
              ))}
            </ul>
          </>
        )}
        <div className="label">Seções sem assinatura de fiscal</div>
        <p className="small">
          {ind.sectionsWithoutObserver.length === 0
            ? 'Nenhuma. Toda seção tem assinatura de fiscal.'
            : ind.sectionsWithoutObserver.join(', ')}
        </p>
        {ind.partiesWithoutObserver.length > 0 && (
          <>
            <div className="label">Partidos sem assinatura de fiscal</div>
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
