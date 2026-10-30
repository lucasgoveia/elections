// Counting rules of the Brazilian election, computed from the tally DTO and the
// election DTO. Brancos and nulos are not valid votes (Lei 9.504/97, art. 77):
// percentages are over votos válidos, which are the votes for candidates (and
// party legends, where a scenario has them).

import type { ContestDto, ElectionDto, OptionDto, ResultDto } from './types';

export interface Candidate {
  key: string;
  option: OptionDto;
  votes: number;
}

export interface Totals {
  valid: number;
  blank: number;
  nul: number;
  eligible: number;
  cast: number;
  abstentions: number;
}

export interface Race {
  contests: ContestDto[];
  /** Candidates, most votes first (ties by name, so the order is stable). */
  candidates: Candidate[];
  totals: Totals;
}

export type Outcome =
  | { kind: 'sem-votos' }
  | { kind: 'eleito'; winner: Candidate }
  | { kind: 'segundo-turno'; first: Candidate; second: Candidate; tieFirst: boolean; tieSecond: boolean };

export interface Presidency {
  contest: ContestDto;
  race: Race;
  outcome: Outcome;
}

export interface Senate {
  place: string;
  race: Race;
  seats: number;
  elected: Candidate[];
  /** Candidates tied at the cutoff for the last seat(s). Non-empty means a tie-break is needed. */
  tied: Candidate[];
}

const CANDIDATE_KINDS = new Set(['candidate', 'party']);

/** Sections that offer a contest. Without machine offers in the election, every section does. */
export function sectionsOffering(election: ElectionDto, contestIndex: number): Set<string> {
  const out = new Set<string>();
  for (const s of election.sections) {
    const offers = s.machineContests
      ? s.machineContests.some((m) => m.contests.includes(contestIndex))
      : true;
    if (offers) out.add(s.id);
  }
  return out;
}

/** Votes per option of one contest, summed over the given sections (all when none is given). */
function optionVotes(result: ResultDto, contest: ContestDto, sections: Set<string>): number[] {
  const totals = contest.options.map(() => 0);
  const hasSectionData = result.sections.some((s) => s.contests.length > 0);
  if (hasSectionData) {
    for (const s of result.sections) {
      if (!sections.has(s.sectionId)) continue;
      const sc = s.contests.find((c) => c.index === contest.index);
      if (!sc) continue;
      sc.votes.forEach((v, i) => {
        if (i < totals.length) totals[i] += v;
      });
    }
    return totals;
  }
  // Older builds report only the contest totals, by option name.
  const agg = result.contests.find((c) => c.index === contest.index);
  contest.options.forEach((o, i) => {
    totals[i] = agg?.options.find((v) => v.name === o.name)?.votes ?? 0;
  });
  return totals;
}

/** The race over one or more contests, with the candidates merged by number. */
export function raceOf(election: ElectionDto, result: ResultDto, contests: ContestDto[]): Race {
  const sectionIds = new Set<string>();
  for (const c of contests) for (const s of sectionsOffering(election, c.index)) sectionIds.add(s);

  const cands = new Map<string, Candidate>();
  let valid = 0;
  let blank = 0;
  let nul = 0;
  for (const c of contests) {
    const votes = optionVotes(result, c, sectionsOffering(election, c.index));
    c.options.forEach((o, i) => {
      const v = votes[i] ?? 0;
      if (o.kind === 'blank') blank += v;
      else if (o.kind === 'null') nul += v;
      else if (CANDIDATE_KINDS.has(o.kind)) {
        valid += v;
        if (o.kind === 'candidate') {
          const key = o.number ?? o.name;
          const cur = cands.get(key);
          if (cur) cur.votes += v;
          else cands.set(key, { key, option: o, votes: v });
        }
      }
    });
  }

  let eligible = 0;
  let cast = 0;
  for (const s of result.sections) {
    if (!sectionIds.has(s.sectionId)) continue;
    eligible += s.eligible;
    cast += s.cast;
  }

  const candidates = [...cands.values()].sort(
    (a, b) => b.votes - a.votes || a.option.name.localeCompare(b.option.name, 'pt-BR'),
  );
  return {
    contests,
    candidates,
    totals: { valid, blank, nul, eligible, cast, abstentions: eligible - cast },
  };
}

/** The presidential race and its outcome: elected in the first round only with more than half of the valid votes. */
export function presidencyOf(election: ElectionDto, result: ResultDto): Presidency | null {
  const contest = election.contests.find((c) => c.office === 'Presidente');
  if (!contest) return null;
  const race = raceOf(election, result, [contest]);
  const [top, second] = race.candidates;
  let outcome: Outcome;
  if (!top || race.totals.valid === 0) {
    outcome = { kind: 'sem-votos' };
  } else if (top.votes * 2 > race.totals.valid || !second) {
    outcome = { kind: 'eleito', winner: top };
  } else {
    outcome = {
      kind: 'segundo-turno',
      first: top,
      second,
      tieFirst: top.votes === second.votes,
      tieSecond: race.candidates[2] !== undefined && race.candidates[2].votes === second.votes,
    };
  }
  return { contest, race, outcome };
}

/** Who is elected among the candidates for `seats` seats, and who is tied at the cutoff. */
export function electedOf(race: Race, seats: number): { elected: Candidate[]; tied: Candidate[] } {
  const sorted = race.candidates;
  if (sorted.length <= seats) return { elected: sorted, tied: [] };
  const cut = sorted[seats - 1].votes;
  const above = sorted.filter((c) => c.votes > cut);
  const atCut = sorted.filter((c) => c.votes === cut);
  const remaining = seats - above.length;
  if (atCut.length > remaining) return { elected: above, tied: atCut };
  return { elected: sorted.filter((c) => c.votes >= cut), tied: [] };
}

/** One Senate race per planet: its two linked contests (1ª and 2ª vaga) summed together. */
export function senatesOf(election: ElectionDto, result: ResultDto): Senate[] {
  const byPlace = new Map<string, ContestDto[]>();
  for (const c of election.contests) {
    if (c.office === 'Presidente') continue;
    const place = c.place ?? c.name;
    byPlace.set(place, [...(byPlace.get(place) ?? []), c]);
  }
  return [...byPlace.entries()].map(([place, contests]) => {
    const race = raceOf(election, result, contests);
    const seats = contests.length;
    return { place, race, seats, ...electedOf(race, seats) };
  });
}

/** Share of a total, as text in pt-BR. */
export function pct(part: number, whole: number): string {
  if (whole <= 0) return '—';
  return `${((100 * part) / whole).toLocaleString('pt-BR', { maximumFractionDigits: 1, minimumFractionDigits: 1 })}%`;
}

export function num(n: number): string {
  return n.toLocaleString('pt-BR');
}

/** Presidency first, then the other offices in index order; the planets' two seats stay together. */
export function ballotScreenOrder(contests: ContestDto[]): ContestDto[] {
  const rank = (c: ContestDto) => (c.office === 'Presidente' ? 1 : 0);
  return [...contests].sort((a, b) => rank(a) - rank(b) || a.index - b.index);
}

/** Option votes of one contest in one section, for the Boletim de Urna. */
export function sectionContestVotes(
  result: ResultDto,
  sectionId: string,
  contest: ContestDto,
): { votes: number[]; counted: number } | null {
  const s = result.sections.find((x) => x.sectionId === sectionId);
  const sc = s?.contests.find((c) => c.index === contest.index);
  if (!sc) return null;
  const votes = contest.options.map((_, i) => sc.votes[i] ?? 0);
  return { votes, counted: sc.counted };
}

/** The label of a contest in printed and on-screen copy: "Senador · 1ª vaga", "Presidente". */
export function officeLabel(c: ContestDto): string {
  return c.seat ? `${c.office} · ${c.seat}` : c.office;
}
