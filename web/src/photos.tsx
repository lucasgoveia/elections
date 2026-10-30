import { useState } from 'react';
import { CANDIDATE_PHOTO_URLS } from './candidate-photos';

/**
 * Real pictures, by candidate number within the contest (e.g. "10"). A URL here
 * wins over everything else. Empty by default.
 *
 * To add a real photo: put the file in web/public/candidatos/ (for example
 * web/public/candidatos/10.jpg), then map the number to it:
 *   PHOTO_OVERRIDES["10"] = "/candidatos/10.jpg";
 *
 * Without an override, the picture comes from CANDIDATE_PHOTO_URLS (by name),
 * and without that, or when the image fails to load, a generated portrait is
 * drawn from the name.
 */
export const PHOTO_OVERRIDES: Record<string, string> = {};

const PARTY_COLORS: Record<string, string> = {
  'Aliança Rebelde': '#C2541B',
  'Ordem Jedi': '#2E6E8E',
  'Wookiees Livres': '#6B4E2E',
  'Império Galáctico': '#4A4F57',
  'Ordem Sith': '#8E1B1B',
};
const NO_PARTY = '#7A847E';

const SKIN = ['#F1C9A5', '#E0AC80', '#C68B5C', '#8D5A37', '#5B3A22'];
const HAIR = ['#1E1B18', '#4A3322', '#8A5A2B', '#C9A16A', '#9A9A9A'];
const CLOTHES = ['#2D3E50', '#6B2E2E', '#3F5B3A', '#5E4A7A', '#A0792E', '#2B2B2B'];
const STYLES = ['short', 'long', 'bun', 'bald'] as const;

/** FNV-1a, 32 bits. The same name always gives the same portrait. */
function hash(s: string): number {
  let h = 0x811c9dc5;
  for (const ch of s) {
    h ^= ch.codePointAt(0) ?? 0;
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Mixes a #RRGGBB colour with white. `t` is the share of white. */
function tint(hex: string, t: number): string {
  const n = parseInt(hex.slice(1), 16);
  const ch = (shift: number) => {
    const c = (n >> shift) & 0xff;
    return Math.round(c + (255 - c) * t);
  };
  return `#${[16, 8, 0].map((s) => ch(s).toString(16).padStart(2, '0')).join('')}`;
}

export function partyColor(party: string | null): string {
  return (party && PARTY_COLORS[party]) || NO_PARTY;
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter((w) => /^[A-Za-zÀ-ÿ]/.test(w))
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('');
}

/** A head-and-shoulders silhouette. Skin, hair, clothes and hair style come from the name's hash. */
function Portrait({ name, party }: { name: string; party: string | null }) {
  const h = hash(name);
  const skin = SKIN[h % SKIN.length];
  const hair = HAIR[(h >>> 3) % HAIR.length];
  const cloth = CLOTHES[(h >>> 6) % CLOTHES.length];
  const style = STYLES[(h >>> 9) % STYLES.length];
  const bg = tint(partyColor(party), 0.6);
  return (
    <svg viewBox="0 0 100 100" role="img" aria-label={`Retrato gerado de ${name}`} focusable="false">
      <rect width="100" height="100" fill={bg} />
      {style === 'long' && <path d="M29 44 C28 20 72 20 71 44 L73 74 L27 74 Z" fill={hair} />}
      <path d="M12 100 C12 76 28 66 50 66 C72 66 88 76 88 100 Z" fill={cloth} />
      <rect x="43" y="56" width="14" height="14" fill={skin} />
      <ellipse cx="50" cy="43" rx="18" ry="21" fill={skin} />
      {style === 'short' && <path d="M31 40 C29 20 71 16 69 40 C64 28 40 28 31 40 Z" fill={hair} />}
      {style === 'bun' && (
        <>
          <circle cx="50" cy="19" r="8" fill={hair} />
          <path d="M31 42 C29 24 71 24 69 42 C64 31 40 31 31 42 Z" fill={hair} />
        </>
      )}
      <circle cx="43" cy="44" r="1.8" fill="#161A18" />
      <circle cx="57" cy="44" r="1.8" fill="#161A18" />
      <rect x="0" y="86" width="100" height="14" fill="#000000" fillOpacity="0.45" />
      <text x="50" y="96" textAnchor="middle" fontSize="8" fontFamily="monospace" fill="#FFFFFF">
        {initials(name)}
      </text>
    </svg>
  );
}

/**
 * A candidate's photo in a square frame. Real pictures win; the generated
 * portrait is the fallback, and it is also what shows when a picture fails.
 */
export function CandidatePhoto({
  name,
  party,
  number,
  size = 96,
}: {
  name: string;
  party: string | null;
  number: string | null;
  size?: number;
}) {
  const [broken, setBroken] = useState<string | null>(null);
  const url = (number && PHOTO_OVERRIDES[number]) || CANDIDATE_PHOTO_URLS[name] || null;
  return (
    <span className="photo" style={{ width: size, height: size }}>
      {url && url !== broken ? (
        <img
          src={url}
          alt={`Foto de ${name}`}
          loading="lazy"
          referrerPolicy="no-referrer"
          onError={() => setBroken(url)}
        />
      ) : (
        <Portrait name={name} party={party} />
      )}
    </span>
  );
}
