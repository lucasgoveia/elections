import { useState, type ReactNode } from 'react';
import {
  allMachines,
  attackOpen,
  availableScenarios,
  blankSession,
  printStrips,
  useSim,
  type MachineUi,
} from '../sim';
import type {
  AttacksDto,
  CeremonyDto,
  ElectionDto,
  PreBuDto,
  ReportDto,
  SthDto,
  ZeresimaDto,
} from '../types';
import { toResult } from '../normalize';
import { tallyStrips } from './strips';

/** The left column: who acts in the current phase, and the buttons they press. */
export function Stage() {
  const { snap } = useSim();
  const phase = snap.phase;
  return (
    <section className="stage" aria-labelledby="stage-title">
      <h2 id="stage-title" className="col-title">
        Palco
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
        <strong>Quem age:</strong> {who}
      </p>
      <div className="panel-body">{children}</div>
    </div>
  );
}

// -- ceremony -------------------------------------------------------------------

const CEREMONY = 'Realizando a cerimônia…';

function CeremonyPanel() {
  const { snap, busy, run, update } = useSim();
  const election = snap.election;
  return (
    <Panel
      step="1 · Cerimônia de chaves"
      title="Cerimônia de chaves"
      who={`os guardiões da chave (${election.trustees.length}), cada um em seu bloco. Eles geram a chave da eleição sem que nenhum deles a detenha.`}
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run(CEREMONY, (sim) => sim.run_ceremony());
          if (r) update((u) => ({ ...u, ceremony: r as CeremonyDto }));
        }}
      >
        {busy === CEREMONY ? 'Trabalhando…' : 'Realizar cerimônia de chaves'}
      </button>
      <RunWholeElection />
    </Panel>
  );
}

const WHOLE = 'Rodando a eleição inteira…';

function RunWholeElection() {
  const { busy, run, update } = useSim();
  return (
    <div className="shortcut">
      <button
        type="button"
        className="btn"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run(WHOLE, (sim) => sim.run_all());
          if (!r) return;
          const view = toResult(r);
          update((u) => {
            const sessions: Record<string, MachineUi> = {};
            for (const [id, m] of Object.entries(u.sessions)) {
              sessions[id] = m.open ? { ...m, open: false, closed: true, authorized: false, pending: false } : m;
            }
            const printed = printStrips(
              { ...u, sessions, result: view },
              tallyStrips(view, 'Impresso por Rodar eleição completa. As etapas intermediárias não aparecem aqui.'),
            );
            return printed;
          });
        }}
      >
        {busy === WHOLE ? 'Trabalhando…' : 'Rodar eleição completa'}
      </button>
      <p className="muted small">
        Atalho: faz a cerimônia, abre a votação, registra votos aleatórios em todas as urnas, encerra, apura e
        assina. Cada etapa continua no mural público.
      </p>
    </div>
  );
}

// -- polls ----------------------------------------------------------------------

const OPEN_POLLS = 'Abrindo a votação…';

function PollsPanel() {
  const { busy, run } = useSim();
  return (
    <Panel
      step="2 · Abertura"
      title="Abrir votação"
      who="a Justiça Eleitoral (EA). Ela publica o cadastro assinado e o registro de abertura."
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={() =>
          run(OPEN_POLLS, (sim) => {
            sim.open_polls();
            return true;
          })
        }
      >
        {busy === OPEN_POLLS ? 'Trabalhando…' : 'Abrir votação'}
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
      step="3 · Votação"
      title="Seções e eleitores"
      who="o mesário abre a seção e identifica cada eleitor. O eleitor vota na urna da aba Urna."
    >
      {election.sections.length > 0 && (
        <label className="field">
          <span>Seção</span>
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
        <ul className="machines" aria-label={`Urnas da seção ${section.id}`}>
          {section.machines.map((m) => (
            <MachineCard key={m} id={m} />
          ))}
        </ul>
      )}
      {election.reserveMachines.length > 0 && (
        <>
          <h4 className="subhead">Urnas de reserva</h4>
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

const CLOSE_POLLS = 'Encerrando a votação…';

function ClosePanel() {
  const { busy, run, update } = useSim();
  return (
    <div className="panel">
      <div className="panel-step">4 · Encerramento</div>
      <h3 className="panel-title">Encerrar votação</h3>
      <p className="muted small">
        <strong>Quem age:</strong> a Justiça Eleitoral (EA). Antes, as seções abertas são encerradas, e o corte da
        votação é publicado. Uma seção cuja urna nunca abriu não tem pacote, e o verificador a lista como ausente
        (passo 7).
      </p>
      <button
        type="button"
        className="btn"
        disabled={busy !== null}
        onClick={async () => {
          const ok = await run(CLOSE_POLLS, (sim) => {
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
        {busy === CLOSE_POLLS ? 'Trabalhando…' : 'Encerrar votação'}
      </button>
    </div>
  );
}

const SECTION_PICK = 'Escolha uma seção';

/** One machine: its session state, and the mesário's buttons. */
function MachineCard({ id, reserve, election }: { id: string; reserve?: boolean; election?: ElectionDto }) {
  const { ui, busy, run, patchSession, addStrip } = useSim();
  const s: MachineUi = ui.sessions[id] ?? blankSession();
  const [pick, setPick] = useState('');
  const sections = election?.sections.map((x) => x.id) ?? [];

  const status = !s.open
    ? s.closed
      ? 'encerrada'
      : 'não aberta'
    : s.pending
      ? 'cédula em andamento'
      : s.authorized
        ? 'eleitor liberado'
        : 'aberta, aguardando eleitor';

  const idle = busy === null;
  const sectionForOpen = reserve ? pick : null;
  const openLabel = `Abrindo ${id}…`;
  const authLabel = `Liberando ${id}…`;
  const castLabel = `Simulando votos em ${id}…`;
  const closeLabel = `Encerrando ${id}…`;

  return (
    <li className="machine">
      <div className="machine-head">
        <span className="mono">{id}</span>
        <span className={`badge badge-${s.open ? 'open' : s.closed ? 'closed' : 'idle'}`}>{status}</span>
      </div>
      <div className="counters muted small">
        depositados {s.cast} · auditados {s.spoiled} · abandonados {s.abandoned}
      </div>
      <div className="machine-actions">
        {!s.open && (
          <>
            {reserve && (
              <label className="field inline">
                <span>Substitui a seção</span>
                <select value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">{SECTION_PICK}</option>
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
                const z = await run(openLabel, (sim) => sim.open_session(id, sectionForOpen));
                if (!z) return;
                addStrip({ kind: 'zeresima', zeresima: z as ZeresimaDto });
                patchSession(id, () => ({ ...blankSession(), open: true }));
              }}
            >
              {busy === openLabel ? 'Trabalhando…' : 'Abrir seção (zerésima)'}
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
                const seq = await run(authLabel, (sim) => sim.authorize(id));
                if (seq !== undefined) patchSession(id, () => ({ authorized: true }));
              }}
            >
              {busy === authLabel ? 'Trabalhando…' : 'Identificar eleitor e liberar a urna'}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || s.authorized || s.pending}
              onClick={async () => {
                const ok = await run(castLabel, (sim) => {
                  sim.cast_random(id, 5);
                  return true;
                });
                if (ok) patchSession(id, (m) => ({ cast: m.cast + 5, authorized: false }));
              }}
            >
              {busy === castLabel ? 'Trabalhando…' : 'Simular 5 votos aleatórios'}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || !s.pending}
              onClick={async () => {
                const ok = await run(`Abandonando em ${id}…`, (sim) => {
                  sim.abandon(id);
                  return true;
                });
                if (ok) patchSession(id, (m) => ({ pending: false, abandoned: m.abandoned + 1 }));
              }}
            >
              Abandonar cédula
            </button>
            <button
              type="button"
              className="btn"
              disabled={!idle || s.pending}
              onClick={async () => {
                const pre = await run(closeLabel, (sim) => sim.close_session(id));
                if (!pre) return;
                addStrip({ kind: 'prebu', prebu: pre as PreBuDto });
                patchSession(id, () => ({ open: false, closed: true, authorized: false, pending: false }));
              }}
            >
              {busy === closeLabel ? 'Trabalhando…' : 'Encerrar seção'}
            </button>
          </>
        )}
      </div>
    </li>
  );
}

// -- tally, verify --------------------------------------------------------------

const TALLY = 'Apurando…';
const SIGN = 'Assinando…';

function TallyPanel() {
  const { busy, run, update } = useSim();
  return (
    <Panel
      step="5 · Apuração"
      title="Apurar votos"
      who="os guardiões da chave decifram os totais e as misturas são feitas; a EA assina o resultado."
    >
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy !== null}
        onClick={async () => {
          const r = await run(TALLY, (sim) => sim.tally());
          if (!r) return;
          const view = toResult(r);
          update((u) => printStrips({ ...u, result: view }, tallyStrips(view)));
          // The board signs a tree head over the published tally, so the
          // verifier has a signed root to check the dump against (§17.3).
          const heads = await run(SIGN, (sim) => sim.sign_sth());
          if (!heads) return;
          const list = heads as SthDto[];
          update((u) => printStrips({ ...u, sths: [...u.sths, ...list] }, list.map((h) => ({ kind: 'sth', sth: h }))));
        }}
      >
        {busy === TALLY ? 'Trabalhando…' : 'Apurar votos'}
      </button>
    </Panel>
  );
}

const SIGN_HEAD = 'Assinando a cabeça…';
const VERIFY = 'Rodando o verificador…';

function VerifyPanel() {
  const { busy, run, update } = useSim();
  return (
    <>
      <Panel
        step="5 · Apuração"
        title="Assinar raiz do mural"
        who="o mural público. Ele assina o tamanho e a raiz do registro, para que qualquer um confira depois que nada foi acrescentado ou retirado."
      >
        <button
          type="button"
          className="btn"
          disabled={busy !== null}
          onClick={async () => {
            const heads = await run(SIGN_HEAD, (sim) => sim.sign_sth());
            if (!heads) return;
            const list = heads as SthDto[];
            update((u) => printStrips({ ...u, sths: [...u.sths, ...list] }, list.map((h) => ({ kind: 'sth', sth: h }))));
          }}
        >
          {busy === SIGN_HEAD ? 'Trabalhando…' : 'Assinar raiz do mural'}
        </button>
      </Panel>
      <Panel
        step="6 · Verificação"
        title="Rodar verificador"
        who="qualquer pessoa, só com o mural público. Os 16 passos do §23 rodam na aba Verificação, sem chaves."
      >
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy !== null}
          onClick={async () => {
            const rep = await run(VERIFY, (sim) => sim.verify());
            if (rep) update((u) => ({ ...u, report: rep as ReportDto }));
          }}
        >
          {busy === VERIFY ? 'Trabalhando…' : 'Rodar verificador'}
        </button>
      </Panel>
    </>
  );
}

// -- sabotage -------------------------------------------------------------------

const ATTACKS: { key: keyof AttacksDto; label: string; does: string; caught: string }[] = [
  {
    key: 'machineFlipsVotes',
    label: 'Urna troca votos',
    does: 'A urna cifra uma escolha diferente da feita pelo eleitor no primeiro cargo. O recibo de auditoria afirma a escolha do eleitor.',
    caught: 'uma auditoria de cédula (§14.2): "Conferir este recibo de forma independente" recifra a afirmação.',
  },
  {
    key: 'boardDropsPackageOf',
    label: 'Mural perde o pacote de uma urna',
    does: 'O mural nunca guarda o pacote de sessão encerrada daquela urna. A atestação da seção continua publicada.',
    caught: 'Pacotes e Completude (passos 6 e 7).',
  },
  {
    key: 'trusteeLies',
    label: 'Guardião mente na decifragem',
    does: 'Um guardião assina frações de decifragem corrompidas.',
    caught: 'Decriptação (passo 11): as frações ruins são rejeitadas e a apuração ainda termina.',
  },
  {
    key: 'eaAltersResult',
    label: 'EA altera o resultado',
    does: 'A EA soma 100 votos à primeira opção do primeiro cargo antes de assinar o resultado.',
    caught: 'Contagem (passo 13) e Resultado (passo 15): o resultado publicado difere da recontagem.',
  },
  {
    key: 'boardEquivocates',
    label: 'Mural emite duas cabeças',
    does: 'Depois da primeira cabeça, o mural assina uma segunda, do mesmo tamanho, sobre um registro alterado.',
    caught: 'Mural (passo 1): duas cabeças assinadas de um mesmo tamanho divergem.',
  },
  {
    key: 'badDkgShare',
    label: 'Fração ruim na cerimônia',
    does: 'Um guardião envia a outro uma fração que não bate com os compromissos.',
    caught: 'Cerimônia de chaves (passo 3): quem recebe reclama, e quem enviou revela a fração correta.',
  },
];

function Sabotage() {
  const { snap, busy, run } = useSim();
  const a = snap.attacks;
  const phase = snap.phase;

  async function setAttack(patch: Partial<AttacksDto>) {
    await run('Aplicando sabotagem…', (sim) => {
      sim.set_attacks({ ...a, ...patch });
      return true;
    });
  }

  return (
    <details className="sabotage">
      <summary>Sabotagem</summary>
      <p className="muted small">
        Mau comportamento deliberado, ligado antes da etapa que ele afeta. Cada um diz o que deveria detectá-lo.
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
                  aria-label="Urna cujo pacote é descartado"
                  value={a.boardDropsPackageOf ?? ''}
                  disabled={!open || busy !== null}
                  onChange={(e) => setAttack({ boardDropsPackageOf: e.target.value || null })}
                >
                  <option value="">Desligado</option>
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
                  {on ? 'Ligado' : 'Desligado'}
                </button>
              )}
            </div>
            <p className="small">
              <strong>O que faz:</strong> {t.does}
            </p>
            <p className="small muted">
              <strong>Quem detecta:</strong> {t.caught}
            </p>
            {!open && <p className="small muted">Bloqueado: esta etapa já passou.</p>}
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
        <span>Cenário</span>
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
        {confirming ? 'Nova eleição → clique de novo para descartar a atual' : 'Nova eleição'}
      </button>
    </div>
  );
}
