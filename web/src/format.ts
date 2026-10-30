/** Groups a hex string in fours, separated by spaces, as printed on a BU. */
export function groupHex(hex: string): string {
  // Some values arrive already grouped ("ABCD-EF01-…"); regroup the bare digits.
  const bare = hex.replace(/[^0-9a-fA-F]/g, '');
  return bare.match(/.{1,4}/g)?.join(' ') ?? hex;
}

/** The first and last characters of a hash, for compact display. */
export function shortHash(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 4)}…${hex.slice(-4)}` : hex;
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}
