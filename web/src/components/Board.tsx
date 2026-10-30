import { useMemo, useState } from 'react';
import { useSim } from '../sim';

/** The public bulletin board (Mural público): a slate drawer listing every entry, with its JSON or CBOR hex. */
export function Board() {
  const { snap, getSim } = useSim();
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<number | null>(null);
  const [hex, setHex] = useState(false);

  const shown = useMemo(() => {
    if (sel === null) return '';
    try {
      const sim = getSim();
      return hex ? sim.entry_hex(sel) : sim.entry_json(sel);
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
    // The root changes whenever the board grows, so it stands in for the board state.
  }, [sel, hex, snap.root, getSim]);

  return (
    <section className={`board ${open ? 'board-open' : ''}`} aria-label="Mural público">
      <button
        type="button"
        className="board-toggle"
        aria-expanded={open}
        aria-controls="board-body"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="display">Mural público</span>
        <span className="mono">
          {snap.board.length} {snap.board.length === 1 ? 'entrada' : 'entradas'} · raiz {snap.root.slice(0, 8)}…
          {snap.root.slice(-4)}
        </span>
        <span aria-hidden="true">{open ? 'Ocultar' : 'Mostrar'}</span>
      </button>

      <div id="board-body" className="board-body" hidden={!open}>
        <div className="board-list" role="list">
          {snap.board.map((e) => (
            <button
              key={e.index}
              type="button"
              role="listitem"
              className={`board-row ${sel === e.index ? 'board-row-sel' : ''}`}
              onClick={() => setSel(e.index)}
              aria-pressed={sel === e.index}
            >
              <span className="mono">#{e.index}</span>
              <span className="mono">{e.kind}</span>
              <span className="board-detail">{e.detail}</span>
              <span className="mono">{e.leafHash.slice(0, 8)}</span>
            </button>
          ))}
        </div>
        <div className="board-detail-pane">
          {sel === null ? (
            <p className="muted small">Clique em uma entrada para ver o registro.</p>
          ) : (
            <>
              <div className="board-detail-head">
                <span className="mono">Entrada #{sel}</span>
                <button type="button" className="btn btn-small" onClick={() => setHex((h) => !h)}>
                  {hex ? 'Mostrar JSON' : 'Mostrar CBOR hex'}
                </button>
              </div>
              <pre className="board-pre mono">{shown}</pre>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
