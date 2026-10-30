import { useMemo, type ReactNode } from 'react';
import type { ElectionDto, ResultDto, SpoilDto, StripData } from '../types';
import { groupHex } from '../format';
import { num, presidencyOf, senatesOf } from '../apuracao';
import { Head, Row } from './paper';
import { Qr } from './Qr';
import { BuBody } from './Bu';

function Zeresima({ data }: { data: Extract<StripData, { kind: 'zeresima' }>['zeresima'] }) {
  return (
    <>
      <Head
        title="ZERÉSIMA"
        lines={[`urna ${data.machineId}`, `seção ${data.sectionId} · sessão ${data.sessionId}`]}
      />
      <div className="strip-label">medição</div>
      <div className="strip-hash">{groupHex(data.measurementHex)}</div>
      <div className="strip-label">cabeça₀</div>
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
      <div className="strip-foot">Todos os contadores em zero. Impressa antes do primeiro eleitor.</div>
    </>
  );
}

function Slip({ data }: { data: Extract<StripData, { kind: 'slip' }>['slip'] }) {
  return (
    <>
      <Head title="COMPROVANTE DE VOTAÇÃO" lines={[`urna ${data.machineId}`]} />
      <div className="strip-short">{data.shortCode}</div>
      <Qr data={data.code} label={`QR code do código de rastreamento ${data.shortCode}`} />
      <div className="strip-label">código de rastreamento</div>
      <div className="strip-hash">{groupHex(data.code)}</div>
      <hr className="strip-rule" />
      <div className="strip-foot">
        Guarde o comprovante. Confira o código curto no mural público para ver seu voto contado.
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
    const names = ch.selected.map((o) => contest?.options[o]?.name ?? `opção ${o}`);
    return {
      key: ch.contest,
      name: contest?.name ?? 'cargo',
      text: names.length ? names.join(', ') : 'branco (sem candidatos)',
    };
  });
}

function Spoil({ data, election }: { data: SpoilDto; election: ElectionDto }) {
  return (
    <>
      <Head title="RECIBO DE AUDITORIA" lines={['NÃO É UM VOTO · só para auditoria']} />
      <div className="strip-short">{data.shortCode}</div>
      <div className="strip-label">a urna afirma que a cédula diz</div>
      {claimedWords(election, data).map((w) => (
        <div key={w.key} className="strip-block">
          <div className="strip-label">{w.name}</div>
          <div>{w.text}</div>
        </div>
      ))}
      <div className="strip-stamp-line">NÃO É UM VOTO</div>
      <Qr data={data.receiptHex} label={`QR code do recibo de auditoria ${data.shortCode}`} />
      <hr className="strip-rule" />
      <div className="strip-foot">
        Confira este recibo de forma independente para ver se a afirmação bate com a cédula.
      </div>
    </>
  );
}

function PreBu({ data }: { data: Extract<StripData, { kind: 'prebu' }>['prebu'] }) {
  return (
    <>
      <Head
        title="PRÉ-BOLETIM DE URNA (cifrado)"
        lines={[`seção ${data.sectionId}`, `urna ${data.machineId}`]}
      />
      <Row left="depositados" right={data.cast} />
      <Row left="auditados" right={data.spoiled} />
      <Row left="abandonados" right={data.abandoned} />
      <hr className="strip-rule" />
      <div className="strip-label">código de verificação</div>
      <div className="strip-hash">{groupHex(data.fingerprint)}</div>
      <div className="strip-label">cabeça da cadeia</div>
      <div className="strip-hash">{groupHex(data.chainHeadHex)}</div>
      <div className="strip-foot">
        Sem votos por candidato: a apuração é feita pelos guardiões da chave.
      </div>
    </>
  );
}

/** The summary strip after the tally: the presidency, and who each planet elected. */
function Result({ data, note, election }: { data: ResultDto; note?: string; election: ElectionDto }) {
  const pres = presidencyOf(election, data);
  const senates = senatesOf(election, data);
  return (
    <>
      <Head title="APURAÇÃO · RESULTADO" lines={[election.title]} />
      {pres && (
        <div className="strip-block">
          <div className="strip-label">Presidente</div>
          {pres.outcome.kind === 'eleito' && (
            <>
              <Row left={pres.outcome.winner.option.name} right={pres.outcome.winner.votes} />
              <div className="strip-foot">Eleito no 1º turno (mais da metade dos votos válidos).</div>
            </>
          )}
          {pres.outcome.kind === 'segundo-turno' && (
            <div className="strip-foot">
              2º turno: {pres.outcome.first.option.name} × {pres.outcome.second.option.name}
            </div>
          )}
          {pres.outcome.kind === 'sem-votos' && <div className="strip-foot">Sem votos válidos.</div>}
        </div>
      )}
      {senates.map((s) => (
        <div key={s.place} className="strip-block">
          <div className="strip-label">Senado · {s.place}</div>
          <div className="strip-foot">
            Eleitos: {s.elected.map((c) => c.option.name).join(', ') || 'ninguém'}
            {s.tied.length > 0 && ' · empate — critério: mais idoso (art. 110)'}
          </div>
        </div>
      ))}
      <div className="strip-foot">
        Votos válidos: {pres ? num(pres.race.totals.valid) : '—'}. Brancos e nulos não entram na porcentagem.
      </div>
      {note && <div className="strip-foot">{note}</div>}
    </>
  );
}

function Sth({ data }: { data: Extract<StripData, { kind: 'sth' }>['sth'] }) {
  return (
    <>
      <Head title="CABEÇA DA ÁRVORE (STH)" lines={[`tamanho do mural: ${data.size} entradas`]} />
      <div className="strip-label">raiz</div>
      <div className="strip-hash">{groupHex(data.rootHex)}</div>
      <Row left="carimbo" right={data.timestamp} />
      <div className="strip-foot">Assinada pelo mural. Compare esta raiz com a do trilho.</div>
    </>
  );
}

/** One printed strip. The paper and its torn edges come from CSS in styles.css. */
export function Strip({ data, election }: { data: StripData; election: ElectionDto }) {
  const body = useMemo((): ReactNode => {
    switch (data.kind) {
      case 'zeresima':
        return <Zeresima data={data.zeresima} />;
      case 'slip':
        return <Slip data={data.slip} />;
      case 'spoil':
        return <Spoil data={data.spoil} election={election} />;
      case 'prebu':
        return <PreBu data={data.prebu} />;
      case 'bu':
        return <BuBody section={data.section} election={election} />;
      case 'result':
        return <Result data={data.result} note={data.note} election={election} />;
      case 'sth':
        return <Sth data={data.sth} />;
    }
  }, [data, election]);
  return (
    <div className={`strip strip-${data.kind}`}>
      <div className="strip-paper">{body}</div>
    </div>
  );
}
