import { useSim } from './sim';
import { Stage } from './components/Stage';
import { Workbench } from './components/Workbench';
import { Printer } from './components/Printer';
import { Board } from './components/Board';
import { Roteiro } from './components/Roteiro';
import { shortHash } from './format';

const PHASES = ['Cerimônia de chaves', 'Abertura', 'Votação', 'Encerramento', 'Apuração', 'Verificação'];

/** Index into PHASES of the step the election is on. Encerramento is done once polls are closed. */
const CURRENT: Record<string, number> = {
  setup: 0,
  'ceremony-done': 1,
  'polls-open': 2,
  'polls-closed': 4,
  tallied: 5,
};

function Rail() {
  const { snap, busy } = useSim();
  const cur = CURRENT[snap.phase];
  return (
    <header className="rail">
      <div className="brand">Oficina</div>
      <ol className="rail-phases" aria-label="Etapa da eleição">
        {PHASES.map((label, i) => (
          <li
            key={label}
            className={i < cur ? 'done' : i === cur ? 'current' : 'todo'}
            aria-current={i === cur ? 'step' : undefined}
          >
            <span className="rail-num mono">{i + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      <div className="rail-end">
        {busy && (
          <span className="rail-busy" role="status">
            {busy}
          </span>
        )}
        <span className="rail-root mono" title={`Raiz do mural ${snap.root}`}>
          raiz {shortHash(snap.root)}
        </span>
      </div>
    </header>
  );
}

/** The site's running head, shared in look with Início and Técnico. */
function SiteBar() {
  return (
    <header className="sitebar">
      <a className="sitebar-marca" href="./">
        Urna <span>à</span> Prova
      </a>
      <nav aria-label="Páginas">
        <ul className="sitebar-paginas">
          <li>
            <a href="./">Início</a>
          </li>
          <li>
            <a href="./tecnico.html">Técnico</a>
          </li>
          <li>
            <a href="./oficina.html" aria-current="page">
              Oficina
            </a>
          </li>
        </ul>
      </nav>
      <p className="sitebar-aviso">
        Simulação de pesquisa. Não é um ataque à urna eletrônica atual nem uma acusação de que ela seja insegura; propõe
        mudanças para que cada eleitor possa conferir o próprio voto. <a href="./#advertencia">Leia a advertência</a>.
      </p>
    </header>
  );
}

function Toast() {
  const { toast, dismissToast } = useSim();
  if (!toast) return null;
  return (
    <div className="toast" role="alert" key={toast.id}>
      <span>{toast.text}</span>
      <button type="button" className="btn btn-small" onClick={dismissToast}>
        Dispensar
      </button>
    </div>
  );
}

export function App() {
  return (
    <div className="app">
      <SiteBar />
      <Rail />
      <Roteiro />
      <div className="columns">
        <Stage />
        <Workbench />
        <Printer />
      </div>
      <Board />
      <Toast />
    </div>
  );
}
