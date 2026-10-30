import type { ReactNode } from 'react';

/** The header block of a printed strip: a centred title, its lines, and a rule. */
export function Head({ title, lines }: { title: string; lines: string[] }) {
  return (
    <div className="strip-head">
      <div className="strip-title">{title}</div>
      {lines.map((l) => (
        <div key={l}>{l}</div>
      ))}
      <hr className="strip-rule" />
    </div>
  );
}

/** One line of a printed strip: a label on the left, a value on the right. */
export function Row({ left, right }: { left: ReactNode; right: ReactNode }) {
  return (
    <div className="strip-row">
      <span>{left}</span>
      <span>{right}</span>
    </div>
  );
}
