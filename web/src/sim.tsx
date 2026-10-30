import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import * as wasm from './wasm/eg_wasm.js';
import { Sim } from './wasm/eg_wasm.js';
import type {
  AttacksDto,
  BoardEntryDto,
  CeremonyDto,
  ElectionDto,
  LookupDto,
  MachineContestsDto,
  Phase,
  ReportDto,
  ResultDto,
  SthDto,
  StripData,
} from './types';
import { toElection } from './normalize';

// -- scenarios ----------------------------------------------------------------

export interface ScenarioInfo {
  id: string;
  name: string;
}

/** Names shown for the scenarios, in pt-BR. Unknown ids keep the name the wasm gives. */
const SCENARIO_NAMES: Record<string, string> = {
  'star-wars': 'Star Wars',
  pilot: 'Piloto (exemplo brasileiro)',
};

/** Scenarios the app offers. The wasm may list its own with `scenarios()`. */
export const FALLBACK_SCENARIOS: ScenarioInfo[] = [
  { id: 'star-wars', name: SCENARIO_NAMES['star-wars'] },
  { id: 'pilot', name: SCENARIO_NAMES.pilot },
];

/** The scenarios the wasm build offers, or the fallback list if it has no `scenarios()`. */
export function availableScenarios(): ScenarioInfo[] {
  const fn = (wasm as unknown as { scenarios?: () => ScenarioInfo[] }).scenarios;
  if (typeof fn === 'function') {
    try {
      const list = fn();
      if (Array.isArray(list) && list.length > 0) {
        return list.map((s) => ({ ...s, name: SCENARIO_NAMES[s.id] ?? s.name }));
      }
    } catch {
      // Fall through to the fallback list.
    }
  }
  return FALLBACK_SCENARIOS;
}

/** The scenario constructor exists only in wasm builds that have scenarios. */
type SimStatics = {
  with_scenario?: (seed: number, scenario: string) => Sim;
};

/** Builds a simulation for a scenario, falling back to the pilot if the wasm
 *  build predates scenarios. */
export function createSim(seed: number, scenario: string): Sim {
  const statics = Sim as unknown as SimStatics;
  if (typeof statics.with_scenario === 'function') {
    return statics.with_scenario(seed, scenario);
  }
  return new Sim(seed);
}

function randomSeed(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0];
}

// -- state --------------------------------------------------------------------

/** What the urna and the stage know about one machine's session. */
export interface MachineUi {
  open: boolean;
  closed: boolean;
  authorized: boolean;
  /** A ballot is encrypted on the urna and not yet cast, spoiled or abandoned. */
  pending: boolean;
  cast: number;
  spoiled: number;
  abandoned: number;
}

export function blankSession(): MachineUi {
  return { open: false, closed: false, authorized: false, pending: false, cast: 0, spoiled: 0, abandoned: 0 };
}

export interface StripItem {
  id: number;
  data: StripData;
}

export interface Ui {
  scenario: string;
  sessions: Record<string, MachineUi>;
  ceremony: CeremonyDto | null;
  result: ResultDto | null;
  report: ReportDto | null;
  sths: SthDto[];
  lookup: LookupDto | null;
  strips: StripItem[];
  nextStripId: number;
}

function initialUi(scenario: string): Ui {
  return {
    scenario,
    sessions: {},
    ceremony: null,
    result: null,
    report: null,
    sths: [],
    lookup: null,
    strips: [],
    nextStripId: 1,
  };
}

export interface Snapshot {
  phase: Phase;
  root: string;
  board: BoardEntryDto[];
  attacks: AttacksDto;
  election: ElectionDto;
}

export interface Toast {
  id: number;
  text: string;
}

function readSnapshot(sim: Sim): Snapshot {
  return {
    phase: sim.phase() as Phase,
    root: sim.board_root(),
    board: sim.board() as BoardEntryDto[],
    attacks: sim.get_attacks() as AttacksDto,
    election: toElection(sim.election() as ElectionDto),
  };
}

/** Turns a wasm error into a sentence that says what to do next, in pt-BR. */
export function explain(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/needs phase/.test(msg)) {
    return 'Esta etapa ainda não está aberta. Conclua a etapa anterior no trilho e tente de novo.';
  }
  if (/already has an open session/.test(msg)) {
    return 'Esta urna já tem uma seção aberta. Encerre a seção antes de abrir outra.';
  }
  if (/no ballot is pending/.test(msg)) {
    return 'Não há cédula em andamento nesta urna. Identifique um eleitor e libere a urna antes.';
  }
  if (/a ballot is pending/.test(msg)) {
    return 'Termine a cédula na urna primeiro: depositar, auditar ou abandonar.';
  }
  if (/not a short code/.test(msg)) {
    return 'Isto não é um código curto. Ele tem o formato XXXX-XXXX-XXXX-XXXX-XXXX (letras e dígitos, cinco grupos de quatro).';
  }
  if (/no open session/.test(msg)) {
    return 'Esta urna não tem seção aberta. Abra a seção nela primeiro.';
  }
  return `O simulador recusou a etapa: ${msg}`;
}

// -- context ------------------------------------------------------------------

export interface SimContext {
  snap: Snapshot;
  ui: Ui;
  busy: string | null;
  toast: Toast | null;
  dismissToast: () => void;
  /** Runs one wasm call with a busy label, then refreshes the derived state. */
  run: <T>(label: string, fn: (sim: Sim) => T) => Promise<T | undefined>;
  update: (f: (u: Ui) => Ui) => void;
  patchSession: (machineId: string, f: (m: MachineUi) => Partial<MachineUi>) => void;
  addStrip: (data: StripData) => void;
  /** Starts a new election with a fresh seed in the given scenario. */
  newElection: (scenario: string) => void;
  /** Read-only access to the current simulation, for entry JSON and the like. */
  getSim: () => Sim;
}

const Ctx = createContext<SimContext | null>(null);

export function useSim(): SimContext {
  const c = useContext(Ctx);
  if (!c) throw new Error('useSim must be used inside <SimProvider>');
  return c;
}

/** Keeps at most this many strips in the printer. */
const MAX_STRIPS = 80;

/** Prints a batch of strips, in order. The newest is on top, as on the printer. */
export function printStrips(u: Ui, list: StripData[]): Ui {
  let id = u.nextStripId;
  const items: StripItem[] = list.map((data) => ({ id: id++, data }));
  return { ...u, strips: [...items.reverse(), ...u.strips].slice(0, MAX_STRIPS), nextStripId: id };
}

export function SimProvider({ children }: { children: ReactNode }) {
  const [boot] = useState(() => {
    const sim = createSim(randomSeed(), FALLBACK_SCENARIOS[0].id);
    return { sim, snap: readSnapshot(sim), scenario: FALLBACK_SCENARIOS[0].id };
  });
  const simRef = useRef<Sim>(boot.sim);
  const busyRef = useRef(false);
  const toastSeq = useRef(0);
  const [snap, setSnap] = useState<Snapshot>(boot.snap);
  const [ui, setUi] = useState<Ui>(() => initialUi(boot.scenario));
  const [busy, setBusy] = useState<string | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);

  const dismissToast = useCallback(() => setToast(null), []);

  const run = useCallback(
    async <T,>(label: string, fn: (sim: Sim) => T): Promise<T | undefined> => {
      if (busyRef.current) return undefined;
      busyRef.current = true;
      setBusy(label);
      // Yield so the "Trabalhando…" state paints before the wasm call blocks.
      await new Promise((r) => setTimeout(r, 16));
      try {
        return fn(simRef.current);
      } catch (e) {
        toastSeq.current += 1;
        setToast({ id: toastSeq.current, text: explain(e) });
        return undefined;
      } finally {
        setSnap(readSnapshot(simRef.current));
        busyRef.current = false;
        setBusy(null);
      }
    },
    [],
  );

  const update = useCallback((f: (u: Ui) => Ui) => setUi(f), []);

  const patchSession = useCallback(
    (machineId: string, f: (m: MachineUi) => Partial<MachineUi>) =>
      setUi((u) => {
        const current = u.sessions[machineId] ?? blankSession();
        return { ...u, sessions: { ...u.sessions, [machineId]: { ...current, ...f(current) } } };
      }),
    [],
  );

  const addStrip = useCallback((data: StripData) => setUi((u) => printStrips(u, [data])), []);

  const newElection = useCallback((scenario: string) => {
    const old = simRef.current;
    const sim = createSim(randomSeed(), scenario);
    simRef.current = sim;
    old.free();
    setSnap(readSnapshot(sim));
    setUi(initialUi(scenario));
    setToast(null);
  }, []);

  const getSim = useCallback(() => simRef.current, []);

  const value = useMemo<SimContext>(
    () => ({
      snap,
      ui,
      busy,
      toast,
      dismissToast,
      run,
      update,
      patchSession,
      addStrip,
      newElection,
      getSim,
    }),
    [snap, ui, busy, toast, dismissToast, run, update, patchSession, addStrip, newElection, getSim],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

// -- helpers shared by components ---------------------------------------------

/** The contests a machine offers. Falls back to every contest when the wasm
 *  build does not report machineContests. */
export function contestsOf(election: ElectionDto, machineId: string): number[] {
  const lists: MachineContestsDto[] = [
    ...election.sections.flatMap((s) => s.machineContests ?? []),
    ...(election.machineContests ?? []),
  ];
  const found = lists.find((m) => m.id === machineId);
  return found ? found.contests : election.contests.map((c) => c.index);
}

/** Every machine id, with its section (empty for the reserve). */
export function allMachines(election: ElectionDto): { id: string; section: string }[] {
  const out = election.sections.flatMap((s) => s.machines.map((m) => ({ id: m, section: s.id })));
  return [...out, ...election.reserveMachines.map((m) => ({ id: m, section: '' }))];
}

/** Whether an attack switch can still take effect in this phase. */
export function attackOpen(key: keyof AttacksDto, phase: Phase): boolean {
  switch (key) {
    case 'badDkgShare':
      return phase === 'setup';
    case 'machineFlipsVotes':
    case 'boardDropsPackageOf':
      return phase === 'setup' || phase === 'ceremony-done' || phase === 'polls-open';
    case 'trusteeLies':
    case 'eaAltersResult':
      return phase !== 'tallied';
    case 'boardEquivocates':
      return true;
  }
}
