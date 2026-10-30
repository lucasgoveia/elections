import { useSim } from './sim';
import type { Phase } from './types';
import { Stage } from './components/Stage';
import { Workbench } from './components/Workbench';
import { Printer } from './components/Printer';
import { Board } from './components/Board';
import { shortHash } from './format';

const PHASES = ['Ceremony', 'Polls', 'Voting', 'Close', 'Tally', 'Verify'];

/** Index into PHASES of the step the election is on. Close is done once polls are closed. */
const CURRENT: Record<Phase, number> = {
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
      <div className="brand">
        <span className="mono">eg/v1</span> Urna Lab
      </div>
      <ol className="rail-phases" aria-label="Election phase">
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
        <span className="rail-root mono" title={`Board root ${snap.root}`}>
          root {shortHash(snap.root)}
        </span>
      </div>
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
        Dismiss
      </button>
    </div>
  );
}

export function App() {
  return (
    <div className="app">
      <Rail />
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
