import { useSim } from '../sim';
import { Strip } from './Strip';

/** The right column: a slot at the top, and strips feeding down from it. */
export function Printer() {
  const { ui, snap } = useSim();
  return (
    <section className="printer" aria-labelledby="printer-title">
      <h2 id="printer-title" className="col-title">
        Printer
      </h2>
      <div className="slot" aria-hidden="true" />
      <div className="strips" role="log" aria-live="polite" aria-label="Printed strips, newest first">
        {ui.strips.length === 0 ? (
          <p className="muted idle">
            The printer is idle. Strips come out here as the polling day runs: zerésima, comprovante,
            boletim de urna, the signed result.
          </p>
        ) : (
          ui.strips.map((s) => <Strip key={s.id} data={s.data} election={snap.election} />)
        )}
      </div>
    </section>
  );
}
