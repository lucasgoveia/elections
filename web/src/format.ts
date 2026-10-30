/** Groups a hex string in fours, separated by spaces, as printed on a BU. */
export function groupHex(hex: string): string {
  return hex.match(/.{1,4}/g)?.join(' ') ?? hex;
}

/** The first and last characters of a hash, for compact display. */
export function shortHash(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 4)}…${hex.slice(-4)}` : hex;
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}
