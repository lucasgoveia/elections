import type { ResultDto, StripData } from '../types';

/** The strips a tally prints, in print order: one Boletim de Urna per section, then the result summary. */
export function tallyStrips(result: ResultDto, note?: string): StripData[] {
  return [
    ...result.sections.map((section): StripData => ({ kind: 'bu', section })),
    { kind: 'result', result, note },
  ];
}
