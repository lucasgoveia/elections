// JSON shapes returned by eg-wasm (crates/eg-wasm/src/dto.rs). Every field is
// camelCase on the wire. Byte strings are lower-case hex.

export type Phase = 'setup' | 'ceremony-done' | 'polls-open' | 'polls-closed' | 'tallied';

export type ContestKind = 'single' | 'multi' | 'proportional';
export type OptionKindName = 'candidate' | 'party' | 'blank' | 'null';

export interface ElectionDto {
  id: string;
  title: string;
  /** "star-wars" or "pilot". Absent in older builds of the wasm. */
  scenario?: string;
  contests: ContestDto[];
  parties: PartyDto[];
  trustees: TrusteeDto[];
  sections: SectionDto[];
  reserveMachines: string[];
  /** Contests offered by each reserve machine, if the build reports it. */
  machineContests?: MachineContestsDto[];
}

/** Which contests one machine offers. Absent in older builds of the wasm. */
export interface MachineContestsDto {
  id: string;
  contests: number[];
}

export interface ContestDto {
  index: number;
  name: string;
  kind: ContestKind;
  method: 'homomorphic' | 'mixnet';
  limit: number;
  options: OptionDto[];
  seats: number | null;
  linkGroup: number | null;
}

export interface OptionDto {
  index: number;
  name: string;
  kind: OptionKindName;
  number: string | null;
  party: string | null;
}

export interface PartyDto {
  index: number;
  name: string;
  number: string;
}

export interface TrusteeDto {
  index: number;
  name: string;
  bloc: string;
}

export interface SectionDto {
  id: string;
  region: string;
  eligible: number;
  machines: string[];
  pollWorkers: number;
  /** Contests offered by each machine of this section. Absent in older builds. */
  machineContests?: MachineContestsDto[];
}

export interface ChoiceDto {
  contest: number;
  selected: number[];
}

export interface ZeresimaDto {
  machineId: string;
  sectionId: string;
  sessionId: string;
  measurementHex: string;
  head0Hex: string;
  contests: { index: number; name: string; options: string[] }[];
}

export interface EncryptDto {
  code: string;
  shortCode: string;
}

export interface SlipDto {
  shortCode: string;
  code: string;
  machineId: string;
  slipHex: string;
  slipJson: string;
}

export interface SpoilDto {
  shortCode: string;
  receiptHex: string;
  receiptJson: string;
  claimed: ChoiceDto[];
}

export interface PreBuDto {
  machineId: string;
  sectionId: string;
  cast: number;
  spoiled: number;
  abandoned: number;
  fingerprint: string;
  chainHeadHex: string;
}

export interface CeremonyDto {
  trustees: TrusteeDto[];
  k: number;
  n: number;
  complaints: string[];
  contextHashHex: string;
  jointKeyHex: string;
}

export interface VotesDto {
  name: string;
  votes: number;
}

export interface SeatDto {
  candidate: string;
  party: string;
}

export interface ResultContestDto {
  index: number;
  name: string;
  options: VotesDto[];
  counted: number;
  invalid: number;
  excluded: number;
  seats: SeatDto[] | null;
}

export interface ResultDto {
  contests: ResultContestDto[];
  sections: { id: string; matches: boolean }[];
}

export interface SthDto {
  size: number;
  rootHex: string;
  timestamp: number;
  hex: string;
}

export interface CountedDto {
  contest: number;
  counted: boolean | null;
}

export interface LookupDto {
  found: boolean;
  entryIndex: number | null;
  status: string | null;
  machineId: string | null;
  inclusionProofVerifies: boolean;
  contestsCounted: CountedDto[];
}

export interface SpoilCheckDto {
  ok: boolean;
  message: string;
  claimed: ChoiceDto[];
}

export interface BoardEntryDto {
  index: number;
  kind: string;
  detail: string;
  leafHash: string;
}

export interface AttacksDto {
  machineFlipsVotes: boolean;
  boardDropsPackageOf: string | null;
  trusteeLies: boolean;
  eaAltersResult: boolean;
  boardEquivocates: boolean;
  badDkgShare: boolean;
}

export interface FindingDto {
  step: number;
  entry: number | null;
  section: string;
  message: string;
  stepName: string;
}

export interface VerifiedPartyDto {
  organisation: string;
  bloc: string;
  fingerprint: string;
}

export interface IndependenceDto {
  trustees: VerifiedPartyDto[];
  releaseSigners: VerifiedPartyDto[];
  mirrors: VerifiedPartyDto[];
  rules: { rule: number; ok: boolean }[];
  partyKeys: { party: string; fingerprint: string | null }[];
  sectionsWithoutObserver: string[];
  partiesWithoutObserver: string[];
}

export interface VerifiedContestDto {
  index: number;
  name: string;
  votes: { option: string; votes: number }[];
  counted: number;
  invalid: number;
  excluded: number;
}

export interface ReportDto {
  passed: boolean;
  failures: FindingDto[];
  warnings: FindingDto[];
  excluded: FindingDto[];
  independence: IndependenceDto;
  contextHash: string | null;
  result: { contests: VerifiedContestDto[] } | null;
}

/** One printed strip. The printer renders each kind with its own layout. */
export type StripData =
  | { kind: 'zeresima'; zeresima: ZeresimaDto }
  | { kind: 'slip'; slip: SlipDto }
  | { kind: 'spoil'; spoil: SpoilDto }
  | { kind: 'prebu'; prebu: PreBuDto }
  | { kind: 'result'; result: ResultDto; note?: string }
  | { kind: 'sth'; sth: SthDto };
