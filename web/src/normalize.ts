import type { ContestDto, ElectionDto, ResultDto, SectionResultDto } from './types';

// Builds from before the Star Wars rework leave fields out. These helpers fill
// them in, so the rest of the app can rely on the current shapes. Once the new
// wasm is in place they change nothing.

function str(v: unknown, fallback: string): string {
  return typeof v === 'string' ? v : fallback;
}

function num(v: unknown): number {
  return typeof v === 'number' ? v : 0;
}

export function toElection(raw: ElectionDto): ElectionDto {
  return {
    ...raw,
    contests: raw.contests.map((c): ContestDto => {
      const old = c as ContestDto & { office?: string; seat?: string | null; place?: string | null };
      return {
        ...c,
        office: str(old.office, c.name),
        seat: old.seat ?? null,
        place: old.place ?? null,
        options: c.options.map((o) => ({ ...o, partyNumber: o.partyNumber ?? null })),
      };
    }),
  };
}

/** Accepts either the current result shape or the older one (`sections: [{ id, matches }]`). */
export function toResult(raw: unknown): ResultDto {
  const r = raw as { contests?: ResultDto['contests']; sections?: Record<string, unknown>[] };
  const sections: SectionResultDto[] = (r.sections ?? []).map((s) => ({
    sectionId: str(s.sectionId, str(s.id, '')),
    matches: s.matches === true,
    eligible: num(s.eligible),
    cast: num(s.cast),
    abstentions: num(s.abstentions),
    preBuFingerprint: str(s.preBuFingerprint, ''),
    contests: Array.isArray(s.contests)
      ? (s.contests as SectionResultDto['contests'])
      : [],
  }));
  return { contests: r.contests ?? [], sections };
}
