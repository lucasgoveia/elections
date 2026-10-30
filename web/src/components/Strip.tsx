import { useMemo, type ReactNode } from 'react';
import qrcode from 'qrcode-generator';
import type { ElectionDto, ResultDto, SpoilDto, StripData } from '../types';
import { groupHex } from '../format';

/** A QR code as an inline SVG. The library's output is markup it generated itself. */
function Qr({ data, label }: { data: string; label: string }) {
  const svg = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(data);
    qr.make();
    return qr.createSvgTag({ cellSize: 2, margin: 0, scalable: true });
  }, [data]);
  return (
    <div
      className="strip-qr"
      role="img"
      aria-label={label}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

function Head({ title, lines }: { title: string; lines: string[] }) {
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

function Row({ left, right }: { left: ReactNode; right: ReactNode }) {
  return (
    <div className="strip-row">
      <span>{left}</span>
      <span>{right}</span>
    </div>
  );
}

function Zeresima({ data }: { data: Extract<StripData, { kind: 'zeresima' }>['zeresima'] }) {
  return (
    <>
      <Head
        title="ZERÉSIMA"
        lines={[`machine ${data.machineId}`, `section ${data.sectionId} · session ${data.sessionId}`]}
      />
      <div className="strip-label">measurement</div>
      <div className="strip-hash">{groupHex(data.measurementHex)}</div>
      <div className="strip-label">head₀</div>
      <div className="strip-hash">{groupHex(data.head0Hex)}</div>
      <hr className="strip-rule" />
      {data.contests.map((c) => (
        <div key={c.index} className="strip-block">
          <div className="strip-label">{c.name}</div>
          {c.options.map((o) => (
            <Row key={o} left={o} right="0" />
          ))}
        </div>
      ))}
      <div className="strip-foot">All counters at zero. Printed before the first voter.</div>
    </>
  );
}

function Slip({ data }: { data: Extract<StripData, { kind: 'slip' }>['slip'] }) {
  return (
    <>
      <Head title="COMPROVANTE DE VOTO" lines={[`machine ${data.machineId}`]} />
      <div className="strip-short">{data.shortCode}</div>
      <Qr data={data.code} label={`QR code of the tracking code ${data.shortCode}`} />
      <div className="strip-label">tracking code</div>
      <div className="strip-hash">{groupHex(data.code)}</div>
      <hr className="strip-rule" />
      <div className="strip-foot">
        Keep this slip. Look up the short code on the bulletin board to see your ballot counted.
      </div>
    </>
  );
}

/** Spoken selections of a receipt, in words, from the election names. */
function claimedWords(
  election: ElectionDto,
  spoil: SpoilDto,
): { key: number; name: string; text: string }[] {
  return spoil.claimed.map((ch) => {
    const contest = election.contests.find((c) => c.index === ch.contest);
    const names = ch.selected.map((o) => contest?.options[o]?.name ?? `option ${o}`);
    return {
      key: ch.contest,
      name: contest?.name ?? 'contest',
      text: names.length ? names.join(', ') : 'blank (no candidates)',
    };
  });
}

function Spoil({ data, election }: { data: SpoilDto; election: ElectionDto }) {
  return (
    <>
      <Head title="RECIBO DE VOTO ANULADO" lines={['NOT A VOTE · for audit only']} />
      <div className="strip-short">{data.shortCode}</div>
      <div className="strip-label">the machine claims the ballot says</div>
      {claimedWords(election, data).map((w) => (
        <div key={w.key} className="strip-block">
          <div className="strip-label">{w.name}</div>
          <div>{w.text}</div>
        </div>
      ))}
      <div className="strip-stamp-line">NOT A VOTE</div>
      <Qr data={data.receiptHex} label={`QR code of the spoil receipt ${data.shortCode}`} />
      <hr className="strip-rule" />
      <div className="strip-foot">Check this receipt independently to see whether the claim matches the ballot.</div>
    </>
  );
}

function PreBu({ data }: { data: Extract<StripData, { kind: 'prebu' }>['prebu'] }) {
  return (
    <>
      <Head
        title="BOLETIM DE URNA (pre-BU)"
        lines={[`machine ${data.machineId}`, `section ${data.sectionId}`]}
      />
      <Row left="cast" right={data.cast} />
      <Row left="spoiled" right={data.spoiled} />
      <Row left="abandoned" right={data.abandoned} />
      <hr className="strip-rule" />
      <div className="strip-label">subtotal fingerprint</div>
      <div className="strip-hash">{data.fingerprint}</div>
      <div className="strip-label">chain head</div>
      <div className="strip-hash">{groupHex(data.chainHeadHex)}</div>
    </>
  );
}

function Result({ data, note, election }: { data: ResultDto; note?: string; election: ElectionDto }) {
  return (
    <>
      <Head title="BOLETIM DE URNA · RESULTADO" lines={[election.title]} />
      {data.contests.map((c) => (
        <div key={c.index} className="strip-block">
          <div className="strip-label">{c.name}</div>
          {c.options.map((o) => (
            <Row key={o.name} left={o.name} right={o.votes} />
          ))}
          <div className="strip-foot">
            counted {c.counted} · invalid {c.invalid} · excluded {c.excluded}
          </div>
          {c.seats && c.seats.length > 0 && (
            <div className="strip-foot">
              seats: {c.seats.map((s) => `${s.candidate} (${s.party})`).join(', ')}
            </div>
          )}
        </div>
      ))}
      <hr className="strip-rule" />
      {data.sections.map((s) => (
        <Row
          key={s.id}
          left={`section ${s.id}`}
          right={s.matches ? 'match' : 'mismatch'}
        />
      ))}
      {note && <div className="strip-foot">{note}</div>}
    </>
  );
}

function Sth({ data }: { data: Extract<StripData, { kind: 'sth' }>['sth'] }) {
  return (
    <>
      <Head title="CABEÇA DA ÁRVORE (STH)" lines={[`board size ${data.size} entries`]} />
      <div className="strip-label">root</div>
      <div className="strip-hash">{groupHex(data.rootHex)}</div>
      <Row left="timestamp" right={data.timestamp} />
      <div className="strip-foot">Signed by the board. Compare this root with the one in the rail.</div>
    </>
  );
}

/** One printed strip. The paper and its torn edges come from CSS in styles.css. */
export function Strip({ data, election }: { data: StripData; election: ElectionDto }) {
  let body: ReactNode;
  switch (data.kind) {
    case 'zeresima':
      body = <Zeresima data={data.zeresima} />;
      break;
    case 'slip':
      body = <Slip data={data.slip} />;
      break;
    case 'spoil':
      body = <Spoil data={data.spoil} election={election} />;
      break;
    case 'prebu':
      body = <PreBu data={data.prebu} />;
      break;
    case 'result':
      body = <Result data={data.result} note={data.note} election={election} />;
      break;
    case 'sth':
      body = <Sth data={data.sth} />;
      break;
  }
  return (
    <div className={`strip strip-${data.kind}`}>
      <div className="strip-paper">{body}</div>
    </div>
  );
}
