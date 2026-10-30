import { useEffect, useMemo, useState } from 'react';
import type {
  ChoiceDto,
  ContestDto,
  EncryptDto,
  OptionDto,
  SlipDto,
  SpoilCheckDto,
  SpoilDto,
} from '../types';
import { blankSession, contestsOf, useSim } from '../sim';
import { ballotScreenOrder } from '../apuracao';
import { CandidatePhoto } from '../photos';

type Screen = 'ballot' | 'review' | 'cast' | 'spoiled';

type Match =
  | { kind: 'none' }
  | { kind: 'candidate'; opt: OptionDto }
  | { kind: 'party'; opt: OptionDto }
  | { kind: 'unknown' };

/** Identity of a candidate across contests of one link group. */
function candidateKey(o: OptionDto): string {
  return `${o.number}|${o.name}`;
}

/** How long the FIM screen stays before the urna waits for the next voter. */
const FIM_MS = 2000;

/**
 * The voting machine, laid out like the TSE urna. It walks the voter through
 * the machine's contests in screen order (Senador 1ª vaga, Senador 2ª vaga,
 * then Presidente) and encrypts the ballot. CONFIRMA deposits it (cast) and
 * AUDITAR spoils it for audit, on the code screen only.
 *
 * Choice mapping (see eg-core ballot.rs): a candidate is [its option index], a
 * party is [party option], BRANCO is [blank option] (multi: []), a wrong number
 * or a linked repeat is [null option] (multi: the same, which counts L times).
 */
export function Urna({ machineId }: { machineId: string }) {
  const { snap, ui, busy, run, patchSession, addStrip } = useSim();
  const session = ui.sessions[machineId] ?? blankSession();

  const contests: ContestDto[] = useMemo(() => {
    const ids = new Set(contestsOf(snap.election, machineId));
    return ballotScreenOrder(snap.election.contests.filter((c) => ids.has(c.index)));
  }, [snap.election, machineId]);

  const [answers, setAnswers] = useState<ChoiceDto[]>([]);
  const [digits, setDigits] = useState('');
  const [chosen, setChosen] = useState<number[]>([]);
  const [blank, setBlank] = useState(false);
  const [forcedUnknown, setForcedUnknown] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>('ballot');
  const [review, setReview] = useState<EncryptDto | null>(null);
  const [spoil, setSpoil] = useState<SpoilDto | null>(null);
  const [check, setCheck] = useState<SpoilCheckDto | null>(null);
  const [farewell, setFarewell] = useState(false);

  function resetBallot() {
    setAnswers([]);
    setDigits('');
    setChosen([]);
    setBlank(false);
    setForcedUnknown(false);
    setNotice(null);
    setScreen('ballot');
    setReview(null);
    setSpoil(null);
    setCheck(null);
    setFarewell(false);
  }

  // A new authorization, a closed session, or an abandoned ballot starts over.
  useEffect(() => {
    if (session.authorized) resetBallot();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.authorized]);
  useEffect(() => {
    if (!session.open) resetBallot();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.open]);
  useEffect(() => {
    if (screen === 'review' && !session.pending) resetBallot();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen, session.pending]);

  // After FIM, the urna waits for the next voter.
  useEffect(() => {
    if (screen !== 'cast') return;
    const t = window.setTimeout(() => setFarewell(true), FIM_MS);
    return () => window.clearTimeout(t);
  }, [screen]);

  const contest = contests[answers.length] as ContestDto | undefined;
  const candOpts = contest?.options.filter((o) => o.kind === 'candidate') ?? [];
  const partyOpts = contest?.options.filter((o) => o.kind === 'party') ?? [];
  const candLen = candOpts[0]?.number?.length ?? 0;
  const partyLen = partyOpts[0]?.number?.length ?? 0;
  const blankOpt = contest?.options.find((o) => o.kind === 'blank');
  const nullOpt = contest?.options.find((o) => o.kind === 'null');
  const limit = contest?.kind === 'multi' ? contest.limit : 1;
  const office = contest ? (contest.office || contest.name).toUpperCase() : '';

  /** Candidates already chosen in an earlier contest of this link group, with the seat they were chosen for. */
  const taken = useMemo(() => {
    const out = new Map<string, string>();
    if (!contest || contest.linkGroup === null) return out;
    for (const a of answers) {
      const c = snap.election.contests.find((x) => x.index === a.contest);
      if (!c || c.linkGroup !== contest.linkGroup) continue;
      for (const s of a.selected) {
        const o = c.options[s];
        if (o?.kind === 'candidate') out.set(candidateKey(o), (c.seat ?? c.name).toLowerCase());
      }
    }
    return out;
  }, [answers, contest, snap.election.contests]);

  const match: Match = useMemo(() => {
    if (!contest || digits === '') return { kind: 'none' };
    if (partyLen && digits.length === partyLen) {
      const p = partyOpts.find((o) => o.number === digits);
      if (p) return { kind: 'party', opt: p };
    }
    if (candLen && digits.length === candLen) {
      const c = candOpts.find((o) => o.number === digits);
      return c ? { kind: 'candidate', opt: c } : { kind: 'unknown' };
    }
    return { kind: 'none' };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contest, digits, candLen, partyLen]);

  const unknown = match.kind === 'unknown' || (forcedUnknown && match.kind === 'none');
  const linkedSeat = match.kind === 'candidate' ? taken.get(candidateKey(match.opt)) : undefined;
  const alreadyChosen =
    match.kind === 'candidate' && contest?.kind === 'multi' && chosen.includes(match.opt.index);

  const gateMessage = !session.open
    ? 'Esta urna não está recebendo votos. O mesário abre a seção no palco.'
    : !session.authorized
      ? 'Aguardando o mesário. Ele identifica o eleitor e libera a urna no palco.'
      : null;
  const ready = screen === 'ballot' && gateMessage === null && contest !== undefined;

  function digit(d: string) {
    if (!ready || candLen === 0) return;
    setNotice(null);
    setForcedUnknown(false);
    setBlank(false);
    setDigits((prev) => (prev.length < candLen ? prev + d : prev));
  }

  /** CORRIGE: clears what is typed, then the last multi choice, then restarts the vote (REINICIAR). */
  function corrige() {
    if (!ready) return;
    if (digits) {
      setDigits('');
      setForcedUnknown(false);
      setNotice(null);
      return;
    }
    if (blank) {
      setBlank(false);
      setNotice(null);
      return;
    }
    if (contest?.kind === 'multi' && chosen.length) {
      setChosen((c) => c.slice(0, -1));
      setNotice(null);
      return;
    }
    if (answers.length > 0) {
      setAnswers([]);
      setChosen([]);
      setForcedUnknown(false);
      setNotice(null);
    }
  }

  function record(selected: number[]) {
    if (!contest) return;
    const next: ChoiceDto[] = [
      ...answers,
      { contest: contest.index, selected: [...selected].sort((a, b) => a - b) },
    ];
    setAnswers(next);
    setDigits('');
    setChosen([]);
    setBlank(false);
    setForcedUnknown(false);
    setNotice(null);
    if (next.length === contests.length) void encryptBallot(next);
  }

  function branco() {
    if (!ready || !contest) return;
    if (contest.kind === 'multi' && chosen.length) {
      setNotice('Tire os candidatos escolhidos antes. CORRIGE remove o último.');
      return;
    }
    setDigits('');
    setForcedUnknown(false);
    setNotice(null);
    setBlank(true);
  }

  function confirma() {
    if (screen === 'review') return void castBallot();
    if (!ready || !contest) return;
    const nullVote = nullOpt ? [nullOpt.index] : [];

    if (blank) return record(contest.kind === 'multi' || !blankOpt ? [] : [blankOpt.index]);
    if (unknown) return record(nullVote);
    if (linkedSeat) return record(nullVote);

    if (contest.kind === 'multi') {
      if (match.kind === 'candidate') {
        if (alreadyChosen) {
          setNotice('Já escolhido neste cargo.');
          return;
        }
        const next = [...chosen, match.opt.index].sort((a, b) => a - b);
        setChosen(next);
        setDigits('');
        setNotice(null);
        if (next.length >= limit) record(next);
        return;
      }
      if (digits === '') return record(chosen);
      setForcedUnknown(true);
      return;
    }

    if (match.kind === 'candidate' || match.kind === 'party') return record([match.opt.index]);
    if (digits === '') {
      setNotice('Digite o número ou aperte BRANCO.');
      return;
    }
    setForcedUnknown(true);
  }

  /** AUDITAR, on the code screen only: spoils the ballot for audit. */
  function auditar() {
    if (screen === 'review') void spoilBallot();
  }

  async function encryptBallot(choices: ChoiceDto[]) {
    // The library takes the choices in contest index order.
    const sorted = [...choices].sort((a, b) => a.contest - b.contest);
    const enc = await run('Cifrando a cédula…', (sim) => sim.encrypt(machineId, sorted));
    if (!enc) {
      setNotice('A urna recusou a cédula. Comece de novo pela primeira tela.');
      resetBallot();
      return;
    }
    patchSession(machineId, () => ({ pending: true }));
    setReview(enc as EncryptDto);
    setScreen('review');
  }

  async function castBallot() {
    const s = await run('Depositando o voto…', (sim) => sim.cast(machineId));
    if (!s) return;
    addStrip({ kind: 'slip', slip: s as SlipDto });
    patchSession(machineId, (m) => ({ pending: false, authorized: false, cast: m.cast + 1 }));
    setReview(null);
    setFarewell(false);
    setScreen('cast');
  }

  async function spoilBallot() {
    const sp = await run('Gerando o recibo de auditoria…', (sim) => sim.spoil(machineId));
    if (!sp) return;
    const spoilData = sp as SpoilDto;
    addStrip({ kind: 'spoil', spoil: spoilData });
    patchSession(machineId, (m) => ({ pending: false, spoiled: m.spoiled + 1 }));
    setSpoil(spoilData);
    setCheck(null);
    setReview(null);
    setScreen('spoiled');
  }

  async function checkReceipt() {
    if (!spoil) return;
    const c = await run('Conferindo o recibo…', (sim) => sim.check_spoil(spoil.receiptHex));
    if (c) setCheck(c as SpoilCheckDto);
  }

  // Keyboard: digits, Backspace = CORRIGE, Enter = CONFIRMA, b = BRANCO, a = AUDITAR.
  // Buttons already act on Enter and Space through their click, so those keys
  // are left alone when a button has focus.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target;
      if (t instanceof HTMLInputElement || t instanceof HTMLSelectElement || t instanceof HTMLTextAreaElement) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      // Keypad buttons act on Enter/Space through their own click. Any other
      // focused button (a tab, a stage action) must not swallow CONFIRMA.
      if (t instanceof HTMLButtonElement && (e.key === 'Enter' || e.key === ' ')) {
        if (t.closest('.urna')) return;
        if (e.key === ' ') return;
        e.preventDefault();
      }
      if (/^[0-9]$/.test(e.key)) digit(e.key);
      else if (e.key === 'Backspace') corrige();
      else if (e.key === 'Enter') confirma();
      else if (e.key === 'b' || e.key === 'B') branco();
      else if (e.key === 'a' || e.key === 'A') auditar();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // Only the code screen has CONFIRMA (deposit) and AUDITAR (audit).
  const digitsEnabled = ready;
  const brancoEnabled = ready;
  const corrigeEnabled = ready;
  const confirmaEnabled = screen === 'review' || ready;
  const auditarEnabled = screen === 'review';

  const selectedNames = (chosenIdx: number[]) =>
    chosenIdx.map((i) => candOpts.find((o) => o.index === i)?.name ?? '').filter(Boolean).join(', ');

  const matchedOpt = match.kind === 'candidate' || match.kind === 'party' ? match.opt : null;

  function ballotScreen(c: ContestDto) {
    return (
      <div className="lcd-screen">
        <div className="lcd-top">
          <div className="lcd-main">
            <div className="lcd-kicker">SEU VOTO PARA</div>
            <div className="lcd-office">{office}</div>
            {c.seat && <div className="lcd-seat">{c.seat.toUpperCase()}</div>}
            {c.method === 'mixnet' && <span className="lcd-tag">contado por mixnet</span>}
            {c.kind === 'multi' && (
              <div className="lcd-line">
                Até {limit} candidatos · escolhidos {chosen.length}/{limit}
              </div>
            )}

            {blank ? (
              <div className="lcd-big">VOTO EM BRANCO</div>
            ) : unknown ? (
              <>
                <div className="lcd-big lcd-warn">NÚMERO ERRADO</div>
                <div className="lcd-big lcd-warn">VOTO NULO</div>
              </>
            ) : linkedSeat !== undefined ? (
              <>
                <div className="lcd-warn">CANDIDATO JÁ ESCOLHIDO NA {linkedSeat.toUpperCase()}</div>
                <div className="lcd-big lcd-warn">VOTO NULO</div>
              </>
            ) : (
              <>
                {candLen > 0 && (
                  <>
                    <div className="lcd-line">Número:</div>
                    <div className="boxes" aria-label={`Número, ${candLen} dígitos`}>
                      {Array.from({ length: candLen }, (_, i) => (
                        <span key={i} className="box">
                          {digits[i] ?? ''}
                        </span>
                      ))}
                    </div>
                  </>
                )}
                {match.kind === 'candidate' && (
                  <div className="lcd-info">
                    <div>
                      Nome: <span className="lcd-name">{match.opt.name}</span>
                    </div>
                    {match.opt.party && (
                      <div>
                        Partido: <span className="lcd-name">{match.opt.party}</span>
                      </div>
                    )}
                  </div>
                )}
                {match.kind === 'party' && (
                  <div className="lcd-info">
                    <div>
                      Legenda: <span className="lcd-name">{match.opt.name}</span>
                    </div>
                  </div>
                )}
              </>
            )}

            {c.kind === 'multi' && chosen.length > 0 && <div className="lcd-line">Escolhidos: {selectedNames(chosen)}</div>}
            {c.kind === 'multi' && <div className="lcd-hint">CONFIRMA com o número vazio encerra este cargo.</div>}
            {partyOpts.length > 0 && <div className="lcd-hint">Dois dígitos = voto de legenda.</div>}
            {notice && <div className="lcd-warn">{notice}</div>}
          </div>

          <div className="lcd-photo">
            {matchedOpt ? (
              <CandidatePhoto
                name={matchedOpt.name}
                party={matchedOpt.party}
                number={matchedOpt.number}
                size={92}
              />
            ) : (
              <div className="lcd-photo-empty" aria-hidden="true" />
            )}
          </div>
        </div>

        <div className="lcd-rule" />
        <div className="lcd-foot">
          Aperte a tecla: CONFIRMA para CONFIRMAR este voto · CORRIGE para REINICIAR este voto
        </div>
      </div>
    );
  }

  function lcdContent() {
    if (screen === 'review' && review) {
      return (
        <div className="lcd-screen lcd-final">
          <div className="lcd-kicker">SEU CÓDIGO DE RASTREAMENTO</div>
          <div className="lcd-code">{review.shortCode}</div>
          <div className="lcd-foot">CONFIRMA para DEPOSITAR o voto</div>
          <div className="lcd-foot">AUDITAR para auditar esta cédula (ela não é contada; você vota de novo)</div>
        </div>
      );
    }
    if (screen === 'cast') {
      return farewell ? (
        <div className="lcd-screen lcd-center">
          <p className="lcd-line-big">aguardando o próximo eleitor</p>
        </div>
      ) : (
        <div className="lcd-screen lcd-center">
          <p className="lcd-fim">FIM</p>
        </div>
      );
    }
    if (screen === 'spoiled' && spoil) {
      return (
        <div className="lcd-screen lcd-final">
          <div className="lcd-kicker">AUDITORIA</div>
          <div className="lcd-code">{spoil.shortCode}</div>
          <div className="lcd-foot">Recibo impresso. Não é um voto.</div>
        </div>
      );
    }
    if (gateMessage) {
      return (
        <div className="lcd-screen lcd-center">
          <p className="lcd-gate">{gateMessage}</p>
        </div>
      );
    }
    if (contest) return ballotScreen(contest);
    return null;
  }

  return (
    <div className="urna-wrap">
      <div className="urna" aria-label={`Urna ${machineId}`}>
        <div className="urna-body">
          <div className="lcd" aria-live="polite">
            {lcdContent()}
          </div>

          <div className="keypad" role="group" aria-label="Teclado da urna">
            <div className="keypad-digits">
              {['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'].map((d) => (
                <button
                  key={d}
                  type="button"
                  className="key key-digit"
                  disabled={!digitsEnabled}
                  onClick={() => digit(d)}
                  aria-label={`Dígito ${d}`}
                >
                  {d}
                </button>
              ))}
            </div>
            <div className="keypad-functions">
              <button
                type="button"
                className="key key-branco"
                disabled={!brancoEnabled}
                onClick={branco}
                aria-label="BRANCO, voto em branco (atalho: b)"
              >
                BRANCO
              </button>
              <button
                type="button"
                className="key key-corrige"
                disabled={!corrigeEnabled}
                onClick={corrige}
                aria-label="CORRIGE (atalho: Backspace)"
              >
                CORRIGE
              </button>
              <button
                type="button"
                className="key key-confirma"
                disabled={!confirmaEnabled}
                onClick={confirma}
                aria-label={
                  screen === 'review' ? 'CONFIRMA, depositar o voto (atalho: Enter)' : 'CONFIRMA (atalho: Enter)'
                }
              >
                CONFIRMA
              </button>
            </div>
            <button
              type="button"
              className="key key-auditar"
              disabled={!auditarEnabled}
              onClick={auditar}
              aria-label="AUDITAR, auditar esta cédula (atalho: a)"
            >
              AUDITAR
            </button>
          </div>
        </div>
      </div>

      {screen === 'review' && (
        <p className="note">
          Esta etapa não existe na urna atual. A cédula é cifrada na própria urna; o código curto é seu
          rastreamento.
        </p>
      )}

      {screen === 'spoiled' && spoil && (
        <div className="urna-actions">
          <button
            type="button"
            className="btn"
            disabled={!session.closed || busy !== null}
            onClick={checkReceipt}
          >
            Conferir este recibo de forma independente
          </button>
          {!session.closed && (
            <p className="muted small">
              Disponível depois que esta seção encerrar. O pacote da cédula cifrada vai ao mural no
              encerramento, e a conferência o procura lá.
            </p>
          )}
          {check && (
            <p className={check.ok ? 'check-ok' : 'check-fail'} role="status">
              {check.ok ? 'Conferência passou. ' : 'Conferência falhou. '}
              {check.message}
            </p>
          )}
          <button
            type="button"
            className="btn"
            disabled={!session.open || !session.authorized}
            onClick={resetBallot}
          >
            Votar de novo
          </button>
        </div>
      )}
    </div>
  );
}
