import { useSim } from '../sim';
import type { ContestDto, ElectionDto, OptionDto } from '../types';
import { CandidatePhoto, partyColor } from '../photos';

/** Office names as the guide shows them. The wasm's own name is kept for offices not listed here. */
const OFFICE_TITLE: Record<string, string> = {
  Presidente: 'Presidente',
  Senador: 'Senado',
};

function byNumber(a: OptionDto, b: OptionDto): number {
  return Number(a.number ?? 0) - Number(b.number ?? 0);
}

/** The candidates of one contest, in number order, without blank and null. */
function candidatesOf(c: ContestDto): OptionDto[] {
  return c.options.filter((o) => o.kind === 'candidate').sort(byNumber);
}

function Card({ o }: { o: OptionDto }) {
  const partyLine = o.party ? (o.partyNumber ? `${o.party} · ${o.partyNumber}` : o.party) : 'Sem partido';
  return (
    <li className="cand">
      <CandidatePhoto name={o.name} party={o.party} number={o.number} size={96} />
      <div className="cand-num mono">{o.number ?? '—'}</div>
      <div className="cand-name">{o.name}</div>
      <div className="cand-party small muted">{partyLine}</div>
    </li>
  );
}

/** A block of cards under a heading. Several seats share one list of candidates. */
function Block({ title, seats, contest }: { title: string; seats: number; contest: ContestDto }) {
  return (
    <section className="cand-block" aria-label={title}>
      <header className="cand-head">
        <h3 className="display cand-title">{title}</h3>
        {seats > 1 && <span className="chip">{seats} vagas</span>}
      </header>
      <ul className="cands">
        {candidatesOf(contest).map((o) => (
          <Card key={o.index} o={o} />
        ))}
      </ul>
    </section>
  );
}

export function Candidatos() {
  const { snap } = useSim();
  const election: ElectionDto = snap.election;

  const presidency = election.contests.filter((c) => c.office === 'Presidente');
  const others = election.contests.filter((c) => c.office !== 'Presidente');
  const senate = new Map<string, ContestDto[]>();
  const single: ContestDto[] = [];
  for (const c of others) {
    if (c.place) senate.set(c.place, [...(senate.get(c.place) ?? []), c]);
    else single.push(c);
  }

  return (
    <div className="guide">
      <p className="lead">Quem concorre, com o número que você digita na urna.</p>

      {presidency.map((c) => (
        <Block key={c.index} title={OFFICE_TITLE.Presidente} seats={1} contest={c} />
      ))}

      {[...senate.entries()].map(([place, contests]) => (
        <Block
          key={place}
          title={`${OFFICE_TITLE[contests[0].office] ?? contests[0].office} · ${place}`}
          seats={contests.length}
          contest={contests[0]}
        />
      ))}

      {single.map((c) => (
        <Block key={c.index} title={OFFICE_TITLE[c.office] ?? c.name} seats={c.seats ?? 1} contest={c} />
      ))}

      {election.parties.length > 0 && (
        <section className="parties-guide" aria-label="Partidos">
          <h3 className="subhead">Partidos</h3>
          <ul className="party-list">
            {election.parties
              .slice()
              .sort((a, b) => Number(a.number) - Number(b.number))
              .map((p) => (
                <li key={p.index} className="party-row">
                  <span className="party-swatch" style={{ background: partyColor(p.name) }} aria-hidden="true" />
                  <span className="mono party-number">{p.number}</span>
                  <span>{p.name}</span>
                </li>
              ))}
          </ul>
        </section>
      )}

      <p className="credit small muted">
        Imagens: Wookieepedia (starwars.fandom.com), uso não comercial. Sem rede, cada candidato aparece com um
        retrato gerado a partir do nome.
      </p>
    </div>
  );
}
