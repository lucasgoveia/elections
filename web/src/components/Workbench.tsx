import { useState, type ReactNode } from 'react';
import { allMachines, useSim } from '../sim';
import type { LookupDto, Phase, TrusteeDto } from '../types';
import { groupHex } from '../format';
import { num, pct, presidencyOf, raceOf, senatesOf, type Candidate, type Presidency, type Race, type Senate } from '../apuracao';
import { CandidatePhoto } from '../photos';
import { Urna } from './Urna';
import { AuditSheet } from './AuditSheet';
import { Candidatos } from './Candidatos';
import { BuBody } from './Bu';

type TabId = 'cerimonia' | 'urna' | 'candidatos' | 'boletins' | 'resultado' | 'verificacao';

const TAB_NAMES: Record<TabId, string> = {
  cerimonia: 'Cerimônia',
  urna: 'Urna',
  candidatos: 'Candidatos',
  boletins: 'Boletins',
  resultado: 'Resultado',
  verificacao: 'Verificação',
};

/** The tab order of the bar. */
const TAB_ORDER: TabId[] = ['cerimonia', 'urna', 'candidatos', 'boletins', 'resultado', 'verificacao'];

/** The tabs that make sense in each phase. Candidatos is always there. */
function tabsFor(phase: Phase): TabId[] {
  const allowed: TabId[] = (() => {
    switch (phase) {
      case 'setup':
      case 'ceremony-done':
        return ['cerimonia', 'candidatos'];
      case 'polls-open':
        return ['urna', 'candidatos'];
      case 'polls-closed':
        return ['candidatos', 'resultado'];
      case 'tallied':
        return ['candidatos', 'boletins', 'resultado', 'verificacao'];
    }
  })();
  return TAB_ORDER.filter((t) => allowed.includes(t));
}

/** The tab shown when the phase changes, unless the voter picked another one that is still open. */
const DEFAULT_TAB: Record<Phase, TabId> = {
  setup: 'cerimonia',
  'ceremony-done': 'cerimonia',
  'polls-open': 'urna',
  'polls-closed': 'resultado',
  tallied: 'resultado',
};

/** The middle column: a tab bar, then the view for the current phase. */
export function Workbench() {
  const { snap } = useSim();
  const phase = snap.phase;
  const tabs = tabsFor(phase);
  const [picked, setPicked] = useState<TabId | null>(null);
  const active: TabId = picked && tabs.includes(picked) ? picked : DEFAULT_TAB[phase];

  const panels: Record<TabId, () => ReactNode> = {
    cerimonia: () => <CeremonyView />,
    urna: () => <VotingView />,
    candidatos: () => <Candidatos />,
    boletins: () => <BoletinsView />,
    resultado: () => <ResultadoView />,
    verificacao: () => <VerifyView />,
  };

  return (
    <section className="workbench" aria-labelledby="bench-title">
      <header className="bench-head">
        <h2 id="bench-title" className="col-title">
          Bancada
        </h2>
        <p className="election-title">{snap.election.title}</p>
      </header>

      <div className="tabs" role="tablist" aria-label="Seções da bancada">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            id={`tab-${t}`}
            aria-selected={t === active}
            aria-controls={`panel-${t}`}
            tabIndex={t === active ? 0 : -1}
            className={`tab ${t === active ? 'tab-on' : ''}`}
            onClick={() => setPicked(t)}
          >
            {TAB_NAMES[t]}
          </button>
        ))}
      </div>

      {/* Panels stay mounted while hidden, so an urna mid-ballot keeps its state. */}
      {tabs.map((t) => (
        <div
          key={t}
          role="tabpanel"
          id={`panel-${t}`}
          aria-labelledby={`tab-${t}`}
          className="tab-panel"
          hidden={t !== active}
        >
          {panels[t]()}
        </div>
      ))}
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
          guardião {t.index} de {total}
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
      <h3 className="subhead">Guardiões da chave</h3>
      <ul className="trustees">
        {trustees.map((t) => (
          <TrusteeCard key={t.index} t={t} total={trustees.length} />
        ))}
      </ul>
      <p className="muted small">
        Qualquer grupo de guardiões menor que o limiar não aprende nada. A chave da eleição nunca fica nas mãos de
        uma só parte.
      </p>
      {c ? (
        <div className="ceremony">
          <p>
            Limiar <strong>{c.k} de {c.n}</strong>. Queixas: {c.complaints.length}
            {c.complaints.length === 0 ? '' : ' (cada uma resolvida por uma revelação)'}.
          </p>
          {c.complaints.map((x) => (
            <p key={x} className="small">
              {x}
            </p>
          ))}
          <div className="label">Chave conjunta</div>
          <div className="hash">{groupHex(c.jointKeyHex)}</div>
          <div className="label">Hash do contexto</div>
          <div className="hash">{groupHex(c.contextHashHex)}</div>
        </div>
      ) : (
        <p className="lead">Realize a cerimônia de chaves no palco para gerar a chave conjunta.</p>
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
          <span>Urna</span>
          <select value={current?.id ?? ''} onChange={(e) => setMachineId(e.target.value)}>
            {machines.map((m) => (
              <option key={m.id} value={m.id}>
                {m.id}
                {m.section ? ` · ${m.section}` : ' · reserva'}
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

function Stats({ race }: { race: Race }) {
  const t = race.totals;
  return (
    <dl className="stats">
      <div>
        <dt>Válidos</dt>
        <dd className="mono">{num(t.valid)}</dd>
      </div>
      <div>
        <dt>Brancos</dt>
        <dd className="mono">{num(t.blank)}</dd>
      </div>
      <div>
        <dt>Nulos</dt>
        <dd className="mono">{num(t.nul)}</dd>
      </div>
      <div>
        <dt>Comparecimento</dt>
        <dd className="mono">
          {pct(t.cast, t.eligible)} <span className="muted">({num(t.cast)})</span>
        </dd>
      </div>
      <div>
        <dt>Abstenções</dt>
        <dd className="mono">{num(t.abstentions)}</dd>
      </div>
    </dl>
  );
}

/** One line per candidate: a photo, the name and number, and the share of valid votes. */
function RankRow({ c, valid, won }: { c: Candidate; valid: number; won?: boolean }) {
  const share = valid > 0 ? (100 * c.votes) / valid : 0;
  return (
    <li className={`rank-row ${won ? 'rank-won' : ''}`}>
      <CandidatePhoto name={c.option.name} party={c.option.party} number={c.option.number} size={52} />
      <div className="rank-main">
        <div className="rank-name">
          <span className="mono">{c.option.number}</span> {c.option.name}
        </div>
        <div className="muted small">{c.option.party ?? 'Sem partido'}</div>
        <div className="bar-track" aria-hidden="true">
          <span className="bar-fill" style={{ width: `${share}%` }} />
        </div>
      </div>
      <div className="rank-votes">
        <span className="display rank-pct">{pct(c.votes, valid)}</span>
        <span className="mono small">{num(c.votes)} votos</span>
      </div>
    </li>
  );
}

function PresidencyCard({ pres }: { pres: Presidency }) {
  const { race, outcome } = pres;
  const valid = race.totals.valid;
  return (
    <article className="pres" aria-label="Presidente">
      <header className="pres-head">
        <div className="kicker">Presidente</div>
        {outcome.kind === 'eleito' && (
          <span className="chip chip-ok">Eleito no 1º turno · mais da metade dos válidos</span>
        )}
        {outcome.kind === 'segundo-turno' && (
          <span className="chip chip-round">
            2º turno: {outcome.first.option.name} × {outcome.second.option.name}
          </span>
        )}
        {outcome.kind === 'sem-votos' && <span className="chip">Sem votos válidos</span>}
      </header>
      {outcome.kind === 'segundo-turno' && outcome.tieFirst && (
        <p className="chip-tie">Empate no 1º lugar. Esta simulação não aplica critério de desempate.</p>
      )}
      {outcome.kind === 'segundo-turno' && outcome.tieSecond && (
        <p className="chip-tie">Empate no 2º lugar. Esta simulação não aplica critério de desempate.</p>
      )}
      <ol className="rank">
        {race.candidates.map((c) => (
          <RankRow key={c.key} c={c} valid={valid} won={outcome.kind === 'eleito' && outcome.winner.key === c.key} />
        ))}
      </ol>
      <Stats race={race} />
    </article>
  );
}

function SenateCard({ s }: { s: Senate }) {
  return (
    <article className="sen" aria-label={`Senado, ${s.place}`}>
      <header className="sen-head">
        <div className="kicker">Senado</div>
        <h3 className="sen-place">{s.place}</h3>
        <span className="chip">{s.seats} vagas</span>
      </header>
      <div className="sen-elected">
        {s.elected.map((c) => (
          <figure key={c.key} className="sen-fig">
            <CandidatePhoto name={c.option.name} party={c.option.party} number={c.option.number} size={72} />
            <figcaption>
              <span className="mono">{c.option.number}</span> {c.option.name}
            </figcaption>
          </figure>
        ))}
        {s.elected.length === 0 && <span className="muted small">Ninguém eleito.</span>}
      </div>
      {s.tied.length > 0 && (
        <p className="chip-tie">
          Empate: {s.tied.map((c) => c.option.name).join(', ')}. Critério: mais idoso (art. 110).
        </p>
      )}
      <Stats race={s.race} />
      <details className="sen-all">
        <summary>Todos os candidatos</summary>
        <ol className="rank">
          {s.race.candidates.map((c) => (
            <RankRow key={c.key} c={c} valid={s.race.totals.valid} won={s.elected.some((e) => e.key === c.key)} />
          ))}
        </ol>
      </details>
    </article>
  );
}

/** Any other office (a scenario may have offices without a place): a plain race card. */
function OtherCard({ race, title }: { race: Race; title: string }) {
  return (
    <article className="sen" aria-label={title}>
      <header className="sen-head">
        <div className="kicker">{title}</div>
      </header>
      <ol className="rank">
        {race.candidates.map((c) => (
          <RankRow key={c.key} c={c} valid={race.totals.valid} />
        ))}
      </ol>
      <Stats race={race} />
    </article>
  );
}

function ResultadoView() {
  const { snap, ui } = useSim();
  const election = snap.election;
  const result = ui.result;
  if (!result) {
    return (
      <p className="lead">
        {snap.phase === 'polls-closed'
          ? 'A votação está encerrada. Os guardiões da chave decifram os totais, e a EA assina o resultado quando a apuração roda, no palco.'
          : 'A apuração ainda não foi feita. Rode-a no palco.'}
      </p>
    );
  }
  const pres = presidencyOf(election, result);
  const senates = senatesOf(election, result);
  const others = election.contests.filter((c) => c.office !== 'Presidente' && !c.place);

  return (
    <section aria-labelledby="results-title">
      <h3 id="results-title" className="subhead">
        Resultado
      </h3>
      <p className="muted small">
        Votos válidos são só os dos candidatos. Brancos e nulos não entram na porcentagem (Lei 9.504/97).
      </p>
      {pres && <PresidencyCard pres={pres} />}
      {senates.length > 0 && (
        <>
          <h4 className="subhead">Senado · eleitos por planeta</h4>
          <div className="sen-grid">
            {senates.map((s) => (
              <SenateCard key={s.place} s={s} />
            ))}
          </div>
        </>
      )}
      {others.map((c) => (
        <OtherCard key={c.index} race={raceOf(election, result, [c])} title={c.name} />
      ))}
      <div className="section-chips" aria-label="Seções conferidas com o pré-BU">
        {result.sections.map((s) => (
          <span key={s.sectionId} className={`chip ${s.matches ? 'chip-ok' : 'chip-fail'}`}>
            {s.sectionId} {s.matches ? 'confere' : 'não confere'}
          </span>
        ))}
      </div>
    </section>
  );
}

// -- boletins -------------------------------------------------------------------

function BoletinsView() {
  const { snap, ui } = useSim();
  const result = ui.result;
  const [pick, setPick] = useState('');
  if (!result || result.sections.length === 0) {
    return <p className="lead">Os boletins saem depois da apuração, um por seção.</p>;
  }
  const sec = result.sections.find((s) => s.sectionId === pick) ?? result.sections[0];
  return (
    <section aria-labelledby="bu-title">
      <h3 id="bu-title" className="subhead">
        Boletins de urna
      </h3>
      <label className="field">
        <span>Seção</span>
        <select value={sec.sectionId} onChange={(e) => setPick(e.target.value)}>
          {result.sections.map((s) => (
            <option key={s.sectionId} value={s.sectionId}>
              {s.sectionId}
            </option>
          ))}
        </select>
      </label>
      <div className="strip-paper bu-large">
        <BuBody section={sec} election={snap.election} />
      </div>
      <p className="muted small">
        Cada número é comprovado pelas provas de decifragem dos guardiões da chave, e a conferência fica na aba
        Verificação.
      </p>
    </section>
  );
}

// -- verify ---------------------------------------------------------------------

function VerifyView() {
  const { ui } = useSim();
  return (
    <section className="verify" aria-labelledby="verify-title">
      <h3 id="verify-title" className="subhead">
        Verificação
      </h3>
      {ui.report ? (
        <AuditSheet report={ui.report} />
      ) : (
        <p className="lead">Rode o verificador no palco para conferir o mural inteiro, passo a passo.</p>
      )}
      <LookupBox />
    </section>
  );
}

function LookupBox() {
  const { ui, busy, run, update } = useSim();
  const [code, setCode] = useState('');
  const look: LookupDto | null = ui.lookup;
  const looking = 'Consultando…';
  return (
    <div className="lookup">
      <h4 className="subhead">Consultar meu código</h4>
      <p className="muted small">
        Digite o código curto do seu comprovante. A consulta lê o mural público, não a urna.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run(looking, (sim) => sim.lookup(code.trim()));
          if (r) update((u) => ({ ...u, lookup: r as LookupDto }));
        }}
      >
        <label className="field">
          <span>Código curto</span>
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
          {busy === looking ? 'Trabalhando…' : 'Consultar meu código'}
        </button>
      </form>
      {look && <LookupResult look={look} />}
    </div>
  );
}

function LookupResult({ look }: { look: LookupDto }) {
  const { snap } = useSim();
  if (!look.found) {
    return (
      <p className="lookup-result" role="status">
        Não há cédula com este código no mural. Confira o código curto do seu comprovante. Se a votação ainda está
        aberta, o pacote aparece no mural quando a sessão encerrar.
      </p>
    );
  }
  return (
    <div className="lookup-result" role="status">
      <p>
        Encontrado na entrada <strong>#{look.entryIndex}</strong> do mural, na urna {look.machineId}. Situação:{' '}
        <strong>{look.status}</strong>.
      </p>
      <p className={look.inclusionProofVerifies ? 'check-ok' : 'check-fail'}>
        {look.inclusionProofVerifies
          ? '✓ A prova de inclusão confere com a cabeça assinada mais recente.'
          : '✗ A prova de inclusão não confere com a cabeça assinada mais recente. Assine uma cabeça.'}
      </p>
      {look.contestsCounted.length > 0 && (
        <ul className="counted">
          {look.contestsCounted.map((c) => {
            const name = snap.election.contests.find((x) => x.index === c.contest)?.name ?? `cargo ${c.contest}`;
            return (
              <li key={c.contest}>
                {name}:{' '}
                {c.counted === null ? 'apuração ainda não feita' : c.counted ? '✓ contada' : '✗ não contada'}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
