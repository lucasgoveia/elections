import { useSim } from '../sim';
import { Strip } from './Strip';

/** The right column: a slot at the top, and strips feeding down from it. */
export function Printer() {
  const { ui, snap } = useSim();
  return (
    <section className="printer" aria-labelledby="printer-title">
      <h2 id="printer-title" className="col-title">
        Impressora
      </h2>
      <div className="slot" aria-hidden="true" />
      <div className="strips" role="log" aria-live="polite" aria-label="Fitas impressas, da mais nova para a mais antiga">
        {ui.strips.length === 0 ? (
          <p className="muted idle">
            A impressora está parada. As fitas saem aqui conforme a votação acontece: zerésima, comprovante,
            pré-boletim, boletim de urna e o resultado assinado.
          </p>
        ) : (
          ui.strips.map((s) => <Strip key={s.id} data={s.data} election={snap.election} />)
        )}
      </div>
    </section>
  );
}
