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

/**
 * The voting machine. It walks the voter through the machine's contests in
 * index order, builds one ChoiceDto per contest, and then encrypts the whole
 * ballot. CONFIRMA casts it; CORRIGE spoils it for audit.
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
    return snap.election.contests
      .filter((c) => ids.has(c.index))
      .sort((a, b) => a.index - b.index);
  }, [snap.election, machineId]);

  const [answers, setAnswers] = useState<ChoiceDto[]>([]);
  const [digits, setDigits] = useState('');
  const [chosen, setChosen] = useState<number[]>([]);
  const [forcedUnknown, setForcedUnknown] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>('ballot');
  const [review, setReview] = useState<EncryptDto | null>(null);
  const [slip, setSlip] = useState<SlipDto | null>(null);
  const [spoil, setSpoil] = useState<SpoilDto | null>(null);
  const [check, setCheck] = useState<SpoilCheckDto | null>(null);

  function resetBallot() {
    setAnswers([]);
    setDigits('');
    setChosen([]);
    setForcedUnknown(false);
    setNotice(null);
    setScreen('ballot');
    setReview(null);
    setSlip(null);
    setSpoil(null);
    setCheck(null);
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

  const contest = contests[answers.length] as ContestDto | undefined;
  const candOpts = contest?.options.filter((o) => o.kind === 'candidate') ?? [];
  const partyOpts = contest?.options.filter((o) => o.kind === 'party') ?? [];
  const candLen = candOpts[0]?.number?.length ?? 0;
  const partyLen = partyOpts[0]?.number?.length ?? 0;
  const blankOpt = contest?.options.find((o) => o.kind === 'blank');
  const nullOpt = contest?.options.find((o) => o.kind === 'null');
  const limit = contest?.kind === 'multi' ? contest.limit : 1;

  /** Candidates already chosen in an earlier contest of this link group. */
  const taken = useMemo(() => {
    const out = new Map<string, string>();
    if (!contest || contest.linkGroup === null) return out;
    for (const a of answers) {
      const c = snap.election.contests.find((x) => x.index === a.contest);
      if (!c || c.linkGroup !== contest.linkGroup) continue;
      for (const s of a.selected) {
        const o = c.options[s];
        if (o?.kind === 'candidate') out.set(candidateKey(o), c.name);
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
  const linkedName = match.kind === 'candidate' ? taken.get(candidateKey(match.opt)) : undefined;
  const alreadyChosen =
    match.kind === 'candidate' && contest?.kind === 'multi' && chosen.includes(match.opt.index);

  const gateMessage = !session.open
    ? 'This machine is not taking votes. The mesário opens a session in STAGE.'
    : !session.authorized
      ? 'Waiting for the mesário. Authorize a voter in STAGE.'
      : null;
  const ready = screen === 'ballot' && gateMessage === null && contest !== undefined;

  function digit(d: string) {
    if (!ready || candLen === 0) return;
    setNotice(null);
    setForcedUnknown(false);
    setDigits((prev) => (prev.length < candLen ? prev + d : prev));
  }

  function corrige() {
    if (screen === 'review') return void spoilBallot();
    if (!ready) return;
    if (digits) {
      setDigits('');
      setForcedUnknown(false);
      setNotice(null);
      return;
    }
    if (contest?.kind === 'multi' && chosen.length) {
      setChosen((c) => c.slice(0, -1));
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
    setForcedUnknown(false);
    setNotice(null);
    if (next.length === contests.length) void encryptBallot(next);
  }

  function branco() {
    if (!ready || !contest) return;
    if (contest.kind === 'multi') {
      if (chosen.length) {
        setNotice('Clear the chosen candidates first. CORRIGE removes the last one.');
        return;
      }
      record([]);
      return;
    }
    if (blankOpt) record([blankOpt.index]);
  }

  function confirma() {
    if (screen === 'review') return void castBallot();
    if (!ready || !contest) return;
    const nullVote = nullOpt ? [nullOpt.index] : [];

    if (unknown) return record(nullVote);
    if (linkedName) return record(nullVote);

    if (contest.kind === 'multi') {
      if (match.kind === 'candidate') {
        if (alreadyChosen) {
          setNotice('Already chosen in this contest.');
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
      setNotice('Type the number, or press BRANCO.');
      return;
    }
    setForcedUnknown(true);
  }

  async function encryptBallot(choices: ChoiceDto[]) {
    const enc = await run('Encrypting ballot…', (sim) => sim.encrypt(machineId, choices));
    if (!enc) {
      setNotice('The machine refused the ballot. Start again from the first contest.');
      resetBallot();
      return;
    }
    patchSession(machineId, () => ({ pending: true }));
    setReview(enc as EncryptDto);
    setScreen('review');
  }

  async function castBallot() {
    const s = await run('Casting…', (sim) => sim.cast(machineId));
    if (!s) return;
    const slipData = s as SlipDto;
    addStrip({ kind: 'slip', slip: slipData });
    patchSession(machineId, (m) => ({ pending: false, authorized: false, cast: m.cast + 1 }));
    setSlip(slipData);
    setReview(null);
    setScreen('cast');
  }

  async function spoilBallot() {
    const sp = await run('Spoiling ballot…', (sim) => sim.spoil(machineId));
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
    const c = await run('Checking receipt…', (sim) => sim.check_spoil(spoil.receiptHex));
    if (c) setCheck(c as SpoilCheckDto);
  }

  // Keyboard: digits, Backspace = CORRIGE, Enter = CONFIRMA, b = BRANCO.
  // Buttons already act on Enter and Space through their click, so those keys
  // are left alone when a button has focus.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target;
      if (t instanceof HTMLInputElement || t instanceof HTMLSelectElement || t instanceof HTMLTextAreaElement) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (t instanceof HTMLButtonElement && (e.key === 'Enter' || e.key === ' ')) return;
      if (/^[0-9]$/.test(e.key)) digit(e.key);
      else if (e.key === 'Backspace') corrige();
      else if (e.key === 'Enter') confirma();
      else if (e.key === 'b' || e.key === 'B') branco();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // In review, only CONFIRMA (cast) and CORRIGE (spoil) work.
  const digitsEnabled = ready;
  const confirmaEnabled = screen === 'review' || ready;
  const corrigeEnabled = screen === 'review' || ready;

  const selectedNames = (chosenIdx: number[]) =>
    chosenIdx.map((i) => candOpts.find((o) => o.index === i)?.name ?? '').filter(Boolean).join(', ');

  return (
    <div className="urna-wrap">
      <div className="urna" aria-label={`Urna for machine ${machineId}`}>
        <div className="urna-body">
          <div className="lcd" aria-live="polite">
            {screen === 'ballot' && gateMessage && <p className="lcd-gate">{gateMessage}</p>}

            {screen === 'ballot' && !gateMessage && contest && (
              <>
                <div className="lcd-head">
                  <span>{contest.name.toUpperCase()}</span>
                  <span className="lcd-progress">
                    {answers.length + 1}/{contests.length}
                  </span>
                </div>
                {contest.method === 'mixnet' && <div className="lcd-tag">counted by mixnet</div>}
                {contest.kind === 'multi' && (
                  <div className="lcd-line">
                    Up to {limit} candidates · chosen {chosen.length}/{limit}
                  </div>
                )}
                {candLen > 0 && (
                  <>
                    <div className="lcd-line">Número:</div>
                    <div className="boxes" aria-label={`Number, ${candLen} digits`}>
                      {Array.from({ length: candLen }, (_, i) => (
                        <span key={i} className="box">
                          {digits[i] ?? ''}
                        </span>
                      ))}
                    </div>
                  </>
                )}

                <div className="lcd-info">
                  {match.kind === 'candidate' && (
                    <>
                      <div className="lcd-name">{match.opt.name}</div>
                      {match.opt.party && <div>{match.opt.party}</div>}
                    </>
                  )}
                  {match.kind === 'party' && <div className="lcd-name">LEGENDA · {match.opt.name}</div>}
                  {unknown && <div className="lcd-warn">NÚMERO ERRADO</div>}
                  {unknown && <div>CONFIRMA records a null vote.</div>}
                  {linkedName && (
                    <div className="lcd-warn">
                      Already chosen in {linkedName}. This vote will be null.
                    </div>
                  )}
                  {alreadyChosen && <div className="lcd-warn">Already chosen in this contest.</div>}
                  {contest.kind === 'multi' && chosen.length > 0 && (
                    <div>Chosen: {selectedNames(chosen)}</div>
                  )}
                  {contest.kind === 'multi' && (
                    <div className="lcd-hint">CONFIRMA on an empty number ends this contest.</div>
                  )}
                  {partyOpts.length > 0 && (
                    <div className="lcd-hint">Two digits = party vote (legenda).</div>
                  )}
                  {notice && <div className="lcd-warn">{notice}</div>}
                </div>
              </>
            )}

            {screen === 'review' && review && (
              <div className="lcd-final">
                <div className="lcd-head">
                  <span>SEU CÓDIGO</span>
                </div>
                <div className="lcd-code">{review.shortCode}</div>
                <div className="lcd-line">CONFIRMA = cast</div>
                <div className="lcd-line">CORRIGE = audit this ballot (spoil)</div>
              </div>
            )}

            {screen === 'cast' && slip && (
              <div className="lcd-final">
                <div className="lcd-head">
                  <span>VOTO REGISTRADO</span>
                </div>
                <div className="lcd-code">{slip.shortCode}</div>
                <div className="lcd-line">Keep the slip.</div>
              </div>
            )}

            {screen === 'spoiled' && spoil && (
              <div className="lcd-final">
                <div className="lcd-head">
                  <span>VOTO ANULADO · AUDIT</span>
                </div>
                <div className="lcd-code">{spoil.shortCode}</div>
                <div className="lcd-line">The receipt is printed. It is not a vote.</div>
              </div>
            )}
          </div>

          <div className="keypad" role="group" aria-label="Keypad">
            <div className="keypad-digits">
              {['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'].map((d) => (
                <button
                  key={d}
                  type="button"
                  className="key key-digit"
                  disabled={!digitsEnabled}
                  onClick={() => digit(d)}
                  aria-label={`Digit ${d}`}
                >
                  {d}
                </button>
              ))}
            </div>
            <div className="keypad-functions">
              <button
                type="button"
                className="key key-branco"
                disabled={!digitsEnabled}
                onClick={branco}
                aria-label="BRANCO, blank vote (shortcut b)"
              >
                BRANCO
              </button>
              <button
                type="button"
                className="key key-corrige"
                disabled={!corrigeEnabled}
                onClick={corrige}
                aria-label={screen === 'review' ? 'CORRIGE, audit this ballot (spoil)' : 'CORRIGE (shortcut Backspace)'}
              >
                CORRIGE
              </button>
              <button
                type="button"
                className="key key-confirma"
                disabled={!confirmaEnabled}
                onClick={confirma}
                aria-label={screen === 'review' ? 'CONFIRMA, cast this ballot' : 'CONFIRMA (shortcut Enter)'}
              >
                CONFIRMA
              </button>
            </div>
          </div>
        </div>
      </div>

      {screen === 'review' && (
        <p className="note">
          This step is new: today's urna doesn't have it. The ballot is encrypted on the machine; the
          short code is your tracking code.
        </p>
      )}

      {screen === 'cast' && (
        <div className="urna-actions">
          <button type="button" className="btn btn-primary" onClick={resetBallot}>
            Next voter
          </button>
        </div>
      )}

      {screen === 'spoiled' && spoil && (
        <div className="urna-actions">
          <button
            type="button"
            className="btn"
            disabled={!session.closed || busy !== null}
            onClick={checkReceipt}
          >
            Check this receipt independently
          </button>
          {!session.closed && (
            <p className="muted small">
              Available after this session closes. The package holding the committed ballot goes to
              the board at close, and the check looks for it there.
            </p>
          )}
          {check && (
            <p className={check.ok ? 'check-ok' : 'check-fail'} role="status">
              {check.ok ? 'Check passed. ' : 'Check failed. '}
              {check.message}
            </p>
          )}
          <button
            type="button"
            className="btn"
            disabled={!session.open || !session.authorized}
            onClick={resetBallot}
          >
            Vote again
          </button>
        </div>
      )}
    </div>
  );
}
