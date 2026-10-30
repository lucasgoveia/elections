/* tslint:disable */
/* eslint-disable */
/**
 * Verifies a board given as CBOR hex strings: `entries_hex` and `sths_hex`
 * are JS arrays of strings, as in `export_board`.
 */
export function verify_board(entries_hex: any, sths_hex: any): any;
/**
 * The short code (`XXXX-XXXX-XXXX-XXXX-XXXX`) of a 32-byte tracking code.
 */
export function short_code_of(code_hex: string): string;
/**
 * The selectable scenarios, as `[{ id, name }]`.
 */
export function scenarios(): any;
/**
 * One election, played step by step. Demo and test tool: every key is in
 * memory, and one process plays every role.
 */
export class Sim {
  free(): void;
  board_root(): string;
  entry_json(index: number): string;
  open_polls(): void;
  cast_random(machine_id: string, n: number): void;
  check_spoil(receipt_hex: string): any;
  get_attacks(): any;
  /**
   * `attacks` is `{ machineFlipsVotes, boardDropsPackageOf, trusteeLies,
   * eaAltersResult, boardEquivocates, badDkgShare }`. Missing fields are off.
   */
  set_attacks(attacks: any): void;
  /**
   * The raw board and the STHs, as CBOR hex: `{ entries, sths }`.
   */
  export_board(): any;
  open_session(machine_id: string, section?: string | null): any;
  run_ceremony(): any;
  close_session(machine_id: string): any;
  /**
   * A simulation of the named scenario: "star-wars" or "pilot". An unknown
   * name is an error that lists the valid names.
   */
  static with_scenario(seed: number, scenario: string): Sim;
  random_choices(machine_id: string): any;
  constructor(seed: number);
  cast(machine_id: string): any;
  board(): any;
  /**
   * "setup" | "ceremony-done" | "polls-open" | "polls-closed" | "tallied"
   */
  phase(): string;
  spoil(machine_id: string): any;
  tally(): any;
  cutoff(): void;
  lookup(short_code: string): any;
  /**
   * Runs the full §23 verifier over this simulation's board and STHs.
   */
  verify(): any;
  abandon(machine_id: string): void;
  /**
   * `choices` is a JS array of `{ contest: number, selected: number[] }`.
   */
  encrypt(machine_id: string, choices: any): any;
  run_all(): any;
  election(): any;
  /**
   * The identifier of this simulation's scenario: "pilot" or "star-wars".
   */
  scenario(): string;
  sign_sth(): any;
  authorize(machine_id: string): number;
  entry_hex(index: number): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_sim_free: (a: number, b: number) => void;
  readonly scenarios: () => any;
  readonly short_code_of: (a: number, b: number) => [number, number, number, number];
  readonly sim_abandon: (a: number, b: number, c: number) => [number, number];
  readonly sim_authorize: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_board: (a: number) => [number, number, number];
  readonly sim_board_root: (a: number) => [number, number];
  readonly sim_cast: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_cast_random: (a: number, b: number, c: number, d: number) => [number, number];
  readonly sim_check_spoil: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_close_session: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_cutoff: (a: number) => [number, number];
  readonly sim_election: (a: number) => [number, number, number];
  readonly sim_encrypt: (a: number, b: number, c: number, d: any) => [number, number, number];
  readonly sim_entry_hex: (a: number, b: number) => [number, number, number, number];
  readonly sim_entry_json: (a: number, b: number) => [number, number, number, number];
  readonly sim_export_board: (a: number) => [number, number, number];
  readonly sim_get_attacks: (a: number) => [number, number, number];
  readonly sim_lookup: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_new: (a: number) => number;
  readonly sim_open_polls: (a: number) => [number, number];
  readonly sim_open_session: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly sim_phase: (a: number) => [number, number];
  readonly sim_random_choices: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_run_all: (a: number) => [number, number, number];
  readonly sim_run_ceremony: (a: number) => [number, number, number];
  readonly sim_scenario: (a: number) => [number, number];
  readonly sim_set_attacks: (a: number, b: any) => [number, number];
  readonly sim_sign_sth: (a: number) => [number, number, number];
  readonly sim_spoil: (a: number, b: number, c: number) => [number, number, number];
  readonly sim_tally: (a: number) => [number, number, number];
  readonly sim_verify: (a: number) => [number, number, number];
  readonly sim_with_scenario: (a: number, b: number, c: number) => [number, number, number];
  readonly verify_board: (a: any, b: any) => [number, number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
