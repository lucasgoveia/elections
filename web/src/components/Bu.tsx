import type { ElectionDto, SectionResultDto } from '../types';
import { groupHex } from '../format';
import { num, officeLabel, pct } from '../apuracao';
import { Head, Row } from './paper';
import { Qr } from './Qr';

/**
 * The Boletim de Urna of one section, as paper lines. The printer uses it
 * inside a strip; the Boletins tab uses it at full size. Both show the same
 * content.
 */
export function BuBody({ section, election }: { section: SectionResultDto; election: ElectionDto }) {
  const info = election.sections.find((s) => s.id === section.sectionId);
  const machine = info?.machines.join(', ') ?? '—';
  const contests = [...section.contests]
    .map((sc) => ({ sc, contest: election.contests.find((c) => c.index === sc.index) }))
    .filter((x): x is { sc: typeof x.sc; contest: NonNullable<typeof x.contest> } => x.contest !== undefined)
    .sort((a, b) => {
      const rank = (c: { office: string }) => (c.office === 'Presidente' ? 0 : 1);
      return rank(a.contest) - rank(b.contest) || a.contest.index - b.contest.index;
    });

  return (
    <>
      <Head
        title="BOLETIM DE URNA"
        lines={[election.title, `Seção ${section.sectionId} · Urna ${machine}`]}
      />
      <Row left="Eleitores aptos" right={num(section.eligible)} />
      <Row
        left="Comparecimento"
        right={`${num(section.cast)} (${pct(section.cast, section.eligible)})`}
      />
      <Row left="Abstenções" right={num(section.abstentions)} />
      <hr className="strip-rule" />
      {contests.map(({ sc, contest }) => {
        let blank = 0;
        let nul = 0;
        let total = 0;
        contest.options.forEach((o, i) => {
          const v = sc.votes[i] ?? 0;
          total += v;
          if (o.kind === 'blank') blank += v;
          if (o.kind === 'null') nul += v;
        });
        return (
          <div key={contest.index} className="strip-block">
            <div className="strip-label">{officeLabel(contest)}</div>
            {contest.options.map((o, i) =>
              o.kind === 'candidate' || o.kind === 'party' ? (
                <Row key={i} left={`${o.number ?? ''} ${o.name}`.trim()} right={sc.votes[i] ?? 0} />
              ) : null,
            )}
            <Row left="Brancos" right={blank} />
            <Row left="Nulos" right={nul} />
            <Row left="Total" right={total} />
          </div>
        );
      })}
      <hr className="strip-rule" />
      <div className="strip-label">Código de verificação</div>
      <div className="strip-hash">{groupHex(section.preBuFingerprint)}</div>
      <Row left="Confere com o pré-BU" right={section.matches ? 'SIM' : 'NÃO'} />
      {section.preBuFingerprint && (
        <Qr data={section.preBuFingerprint} label={`QR code do código de verificação da seção ${section.sectionId}`} />
      )}
      <div className="strip-foot">
        Cada número é comprovado pelas provas de decifragem dos guardiões da chave e conferido na aba Verificação.
      </div>
    </>
  );
}
