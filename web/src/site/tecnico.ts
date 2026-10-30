// The Técnico page: each "bancada" runs one piece of the protocol for real, in
// the toy group of powers of g = 2 modulo p = 23 (11 elements, exponents mod 11).
// The arithmetic is the protocol's; only the group is tiny.
import './site.css';

const P = 23;
const Q = 11;
const G = 2;

const mod = (a: number, n: number) => ((a % n) + n) % n;

/** b^e in the subgroup of order Q (every base used here is a power of g). */
function pw(b: number, e: number): number {
  let x = mod(e, Q);
  let base = mod(b, P);
  let r = 1;
  while (x > 0) {
    if (x & 1) r = (r * base) % P;
    base = (base * base) % P;
    x >>= 1;
  }
  return r;
}

const mul = (...xs: number[]) => xs.reduce((a, b) => (a * b) % P, 1);
const inv = (a: number) => pw(a, Q - 1);

/** The exponent x with g^x = y, read off the table. */
function lg(y: number): number {
  for (let x = 0; x < Q; x += 1) if (pw(G, x) === y) return x;
  return -1;
}

/** A group element with its exponent, for checking against the table. */
const el = (y: number) => `${y} <span class="exp">(g<sup>${lg(y)}</sup>)</span>`;

/** The inverse of a scalar modulo Q. */
function invQ(x: number): number {
  for (let y = 1; y < Q; y += 1) if (mod(x * y, Q) === 1) return y;
  throw new Error('no inverse of 0');
}

const rand = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

const utf8 = (s: string) => new TextEncoder().encode(s);
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/** A tagged hash, as the spec's Digest(tag, …): here SHA-256 of the JSON array. */
async function digest(tag: string, ...parts: (string | number)[]): Promise<string> {
  return toHex(await sha256(utf8(JSON.stringify([`eg/v1/${tag}`, ...parts]))));
}

/** A challenge: a real SHA-256, reduced to the toy's 11 possible values. */
async function challenge(tag: string, ...parts: number[]): Promise<number> {
  const h = await sha256(utf8(JSON.stringify([`eg/v1/${tag}`, ...parts])));
  return ((h[0] << 8) | h[1]) % Q;
}

const short = (hex: string, n = 16) => hex.slice(0, n).toUpperCase().match(/.{4}/g)!.join('-');

// -- rendering ------------------------------------------------------------------

type Linha = [string, ('ok' | 'mau' | 'obs')?];

function show(box: HTMLElement, lines: Linha[]) {
  const ol = box.querySelector<HTMLOListElement>('.passos')!;
  ol.replaceChildren(
    ...lines.map(([html, kind]) => {
      const li = document.createElement('li');
      if (kind) li.className = kind;
      // Every value interpolated here is a number, a hex digest or text the page itself wrote.
      li.innerHTML = html + (kind === 'ok' ? ' <b class="marca-ok">✓</b>' : kind === 'mau' ? ' <b class="marca-mau">✗</b>' : '');
      return li;
    }),
  );
}

function num(box: HTMLElement, id: string): number {
  const input = box.querySelector<HTMLInputElement>(`#${id}`)!;
  const v = Math.round(Number(input.value));
  const lo = Number(input.min);
  const hi = Number(input.max);
  const clamped = Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : lo;
  return clamped;
}

const val = (box: HTMLElement, id: string) => box.querySelector<HTMLInputElement | HTMLSelectElement>(`#${id}`)!.value;
const checked = (box: HTMLElement, id: string) => box.querySelector<HTMLInputElement>(`#${id}`)!.checked;

/** Runs a bench now and again whenever one of its controls changes. */
function bench(id: string, run: (box: HTMLElement) => Linha[] | Promise<Linha[]>) {
  const box = document.getElementById(id);
  if (!box) return;
  let seq = 0;
  // Runs are async (hashing); only the latest one may draw.
  const go = async () => {
    const mine = ++seq;
    const lines = await run(box);
    if (mine === seq) show(box, lines);
  };
  box.querySelectorAll('input, select').forEach((c) => c.addEventListener('input', () => void go()));
  box.querySelectorAll('button[data-acao]').forEach((b) => b.addEventListener('click', () => void go()));
  void go();
}

// -- shared pieces: encryption and the 0-or-1 proof --------------------------------

const KEY_S = 3;
const KEY = pw(G, KEY_S);

const enc = (m: number, r: number, k = KEY): [number, number] => [pw(G, r), mul(pw(G, m), pw(k, r))];

interface Disj {
  c: number;
  c0: number;
  c1: number;
  v0: number;
  v1: number;
  a: number[]; // A0, D0, A1, D1 as published
  fake?: number; // the branch that was simulated, when one was
}

/** The commitments a checker recomputes for branch j from (c_j, v_j). */
function branch(alpha: number, beta: number, j: number, cj: number, vj: number): [number, number] {
  const a = mul(pw(G, vj), inv(pw(alpha, cj)));
  const d = mul(pw(KEY, vj), inv(pw(mul(beta, inv(pw(G, j))), cj)));
  return [a, d];
}

/** Proves that (alpha, beta) holds 0 or 1. With m = 2 there is no witness, so it fakes both branches and hopes. */
async function proveDisj(alpha: number, beta: number, m: number, r: number): Promise<Disj> {
  if (m === 0 || m === 1) {
    const f = 1 - m;
    const cf = rand(Q);
    const vf = rand(Q);
    const [af, df] = branch(alpha, beta, f, cf, vf);
    const u = rand(Q);
    const ab = pw(G, u);
    const db = pw(KEY, u);
    const a = m === 1 ? [af, df, ab, db] : [ab, db, af, df];
    const c = await challenge('disj01', alpha, beta, ...a);
    const cb = mod(c - cf, Q);
    const vb = mod(u + cb * r, Q);
    return m === 1
      ? { c, c0: cf, v0: vf, c1: cb, v1: vb, a, fake: 0 }
      : { c, c0: cb, v0: vb, c1: cf, v1: vf, a, fake: 1 };
  }
  const c0 = rand(Q);
  const v0 = rand(Q);
  const c1 = rand(Q);
  const v1 = rand(Q);
  const a = [...branch(alpha, beta, 0, c0, v0), ...branch(alpha, beta, 1, c1, v1)];
  const c = await challenge('disj01', alpha, beta, ...a);
  return { c, c0, c1, v0, v1, a };
}

async function verifyDisj(alpha: number, beta: number, p: Disj): Promise<{ ok: boolean; c: number; a: number[] }> {
  const a = [...branch(alpha, beta, 0, p.c0, p.v0), ...branch(alpha, beta, 1, p.c1, p.v1)];
  const c = await challenge('disj01', alpha, beta, ...a);
  return { ok: mod(p.c0 + p.c1, Q) === c, c, a };
}

// -- 2. hashes ---------------------------------------------------------------------

bench('run-hash', async (box) => {
  const t = val(box, 'h-txt');
  const code = await digest('code', t);
  const ballot = await digest('ballot', t);
  const changed = await digest('code', `${t}.`);
  return [
    [`D("eg/v1/code", "${escapeText(t)}") = ${short(code, 32)}…`],
    [`D("eg/v1/ballot", "${escapeText(t)}") = ${short(ballot, 32)}…`],
    ['mesma entrada, etiquetas diferentes: as impressões não têm relação nenhuma', 'obs'],
    [`D("eg/v1/code", "${escapeText(t)}.") = ${short(changed, 32)}…`],
    ['um ponto a mais no fim muda a impressão inteira', 'obs'],
  ];
});

function escapeText(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
}

// -- 3. ElGamal ------------------------------------------------------------------

bench('run-elgamal', (box) => {
  const s = num(box, 'e-s');
  const k = pw(G, s);
  const votes = [1, 2, 3].map((i) => ({ m: Number(val(box, `e-m${i}`)), r: num(box, `e-r${i}`) }));
  const lines: Linha[] = [[`chave pública K = g<sup>${s}</sup> = ${el(k)}`]];
  const boxes = votes.map(({ m, r }, i) => {
    const [a, b] = enc(m, r, k);
    lines.push([`caixa ${i + 1} (voto ${m}, r = ${r}): α = g<sup>${r}</sup> = ${el(a)}, β = g<sup>${m}</sup>·K<sup>${r}</sup> = ${el(b)}`]);
    return [a, b];
  });
  const A = mul(...boxes.map((x) => x[0]));
  const B = mul(...boxes.map((x) => x[1]));
  lines.push([`caixa da soma, multiplicando número a número: α = ${el(A)}, β = ${el(B)}`]);
  const as = pw(A, s);
  const gm = mul(B, inv(as));
  const total = lg(gm);
  const expected = votes.reduce((n, v) => n + v.m, 0);
  lines.push([`para abrir: α<sup>s</sup> = ${el(as)}; β ÷ α<sup>s</sup> = ${el(gm)}, então o total é ${total}`]);
  lines.push([`o total confere com a soma dos votos (${expected}), sem abrir nenhuma caixa`, total === expected ? 'ok' : 'mau']);
  return lines;
});

// -- 4. the shared key -------------------------------------------------------------

bench('run-shamir', (box) => {
  const s = num(box, 's-s');
  const a = num(box, 's-a');
  const m = num(box, 's-m');
  const r = num(box, 's-r');
  const who = val(box, 's-par').split(',').map(Number);
  const z = [0, 1, 2, 3].map((j) => mod(s + a * j, Q));
  const f0 = pw(G, s);
  const f1 = pw(G, a);
  const lines: Linha[] = [
    [`reta f(x) = ${s} + ${a}·x mod 11: pedaços z<sub>1</sub> = ${z[1]}, z<sub>2</sub> = ${z[2]}, z<sub>3</sub> = ${z[3]}`],
    [`compromissos públicos: F<sub>0</sub> = g<sup>${s}</sup> = ${el(f0)}, F<sub>1</sub> = g<sup>${a}</sup> = ${el(f1)}`],
  ];
  for (const j of [1, 2, 3]) {
    const lhs = pw(G, z[j]);
    const rhs = mul(f0, pw(f1, j));
    lines.push([`guardião ${j} confere o seu pedaço sem ver a reta: g<sup>${z[j]}</sup> = ${el(lhs)} e F<sub>0</sub>·F<sub>1</sub><sup>${j}</sup> = ${el(rhs)}`, lhs === rhs ? 'ok' : 'mau']);
  }
  const [alpha, beta] = enc(m, r, f0);
  const target = pw(alpha, s);
  lines.push([`caixa trancada com K = F<sub>0</sub>: (α, β) = (${el(alpha)}, ${el(beta)})`]);
  if (who.length === 1) {
    const m1 = pw(alpha, z[1]);
    lines.push([`só o guardião 1 aplica o seu pedaço: α<sup>${z[1]}</sup> = ${el(m1)}`]);
    lines.push([`para abrir seria preciso α<sup>s</sup> = ${el(target)}; com um ponto só, qualquer s é possível`, 'mau']);
    return lines;
  }
  const [i, j] = who;
  const mi = pw(alpha, z[i]);
  const mj = pw(alpha, z[j]);
  const li = mod(j * invQ(mod(j - i, Q)), Q);
  const lj = mod(i * invQ(mod(i - j, Q)), Q);
  const comb = mul(pw(mi, li), pw(mj, lj));
  lines.push([`guardião ${i} publica M<sub>${i}</sub> = α<sup>${z[i]}</sup> = ${el(mi)}; guardião ${j} publica M<sub>${j}</sub> = α<sup>${z[j]}</sup> = ${el(mj)}`]);
  lines.push([`pesos de Lagrange: λ<sub>${i}</sub> = ${j} ÷ (${j} − ${i}) = ${li}, λ<sub>${j}</sub> = ${i} ÷ (${i} − ${j}) = ${lj} (mod 11)`]);
  lines.push([`M<sub>${i}</sub><sup>${li}</sup> · M<sub>${j}</sub><sup>${lj}</sup> = ${el(comb)}, que é α<sup>s</sup> = ${el(target)}, sem ninguém conhecer s`, comb === target ? 'ok' : 'mau']);
  const gm = mul(beta, inv(comb));
  lines.push([`β ÷ ${comb} = ${el(gm)}, então a caixa guarda ${lg(gm)}`, lg(gm) === m ? 'ok' : 'mau']);
  return lines;
});

// -- 5. Schnorr ------------------------------------------------------------------

bench('run-schnorr', async (box) => {
  const x = num(box, 'sc-x');
  const u = num(box, 'sc-u');
  const c2 = num(box, 'sc-c2');
  const X = pw(G, x);
  const A = pw(G, u);
  const c = await challenge('schnorr', X, A);
  const v = mod(u + c * x, Q);
  const lhs = pw(G, v);
  const rhs = mul(A, pw(X, c));
  const lines: Linha[] = [
    [`afirmação pública: X = g<sup>${x}</sup> = ${el(X)}`],
    [`entra na caverna: A = g<sup>${u}</sup> = ${el(A)}`],
    [`desafio: c = SHA-256("schnorr", X, A) mod 11 = ${c}`],
    [`resposta: v = ${u} + ${c}·${x} mod 11 = ${v}`],
    [`quem confere: g<sup>${v}</sup> = ${el(lhs)} e A·X<sup>${c}</sup> = ${el(rhs)}`, lhs === rhs ? 'ok' : 'mau'],
  ];
  if (c2 === c) {
    lines.push([`escolha um segundo desafio diferente de ${c} para ver a extração`, 'obs']);
  } else {
    const v2 = mod(u + c2 * x, Q);
    const xr = mod((v - v2) * invQ(mod(c - c2, Q)), Q);
    lines.push([`se a mesma entrada A respondesse também ao desafio ${c2}: v' = ${v2}`]);
    lines.push([`então x = (${v} − ${v2}) ÷ (${c} − ${c2}) mod 11 = ${xr}: duas respostas entregam o segredo`, 'obs']);
  }
  const cs = mod(c + 3, Q);
  const vs = mod(v + 5, Q);
  const As = mul(pw(G, vs), inv(pw(X, cs)));
  const ok = pw(G, vs) === mul(As, pw(X, cs));
  lines.push([`falsificador, sem saber x: escolhe c = ${cs} e v = ${vs} e calcula A = g<sup>${vs}</sup> ÷ X<sup>${cs}</sup> = ${el(As)}`]);
  lines.push([`a conversa (A, c, v) confere, mas o desafio foi escolhido antes; por isso o desafio real vem do hash, depois de A`, ok ? 'ok' : 'mau']);
  return lines;
});

// -- 6. Chaum-Pedersen -----------------------------------------------------------

bench('run-cp', async (box) => {
  const z = num(box, 'cp-z');
  const r = num(box, 'cp-r');
  const u = num(box, 'cp-u');
  const lies = checked(box, 'cp-mente');
  const Z = pw(G, z);
  const alpha = pw(G, r);
  const M = lies ? mul(pw(alpha, z), G) : pw(alpha, z);
  const a1 = pw(G, u);
  const a2 = pw(alpha, u);
  const c = await challenge('cp', Z, alpha, M, a1, a2);
  const v = mod(u + c * z, Q);
  const ok1 = pw(G, v) === mul(a1, pw(Z, c));
  const ok2 = pw(alpha, v) === mul(a2, pw(M, c));
  const lines: Linha[] = [
    [`pedaço registrado na cerimônia: Z = g<sup>${z}</sup> = ${el(Z)}`],
    [`caixa a abrir: α = ${el(alpha)}`],
    [`parte publicada: M = ${lies ? `α<sup>${z}</sup>·g (falsa)` : `α<sup>${z}</sup>`} = ${el(M)}`],
    [`compromissos: g<sup>${u}</sup> = ${el(a1)}, α<sup>${u}</sup> = ${el(a2)}`],
    [`desafio: c = SHA-256(Z, α, M, compromissos) mod 11 = ${c}; resposta v = ${u} + ${c}·${z} = ${v}`],
    [`base g: g<sup>${v}</sup> = ${el(pw(G, v))} e g<sup>${u}</sup>·Z<sup>${c}</sup> = ${el(mul(a1, pw(Z, c)))}`, ok1 ? 'ok' : 'mau'],
    [`base α: α<sup>${v}</sup> = ${el(pw(alpha, v))} e α<sup>${u}</sup>·M<sup>${c}</sup> = ${el(mul(a2, pw(M, c)))}`, ok2 ? 'ok' : 'mau'],
  ];
  if (lies && ok2) {
    lines.push(['o desafio deu 0, e com desafio 0 qualquer parte passa; no grupo real a chance disso é desprezível', 'obs']);
  } else {
    lines.push([ok1 && ok2 ? 'parte aceita: M usa o mesmo pedaço registrado' : 'parte rejeitada: M não usa o pedaço registrado', ok1 && ok2 ? 'ok' : 'mau']);
  }
  return lines;
});

// -- 7. the 0-or-1 proof -----------------------------------------------------------

let tentativas = 0;
let ultimaCaixa = '';

bench('run-disj', async (box) => {
  const m = Number(val(box, 'd-m'));
  const r = num(box, 'd-r');
  const key = `${m}/${r}`;
  tentativas = key === ultimaCaixa ? tentativas + 1 : 1;
  ultimaCaixa = key;
  const [alpha, beta] = enc(m, r);
  const p = await proveDisj(alpha, beta, m, r);
  const check = await verifyDisj(alpha, beta, p);
  const lines: Linha[] = [[`caixa: α = g<sup>${r}</sup> = ${el(alpha)}, β = g<sup>${m}</sup>·K<sup>${r}</sup> = ${el(beta)}, com K = ${KEY}`]];
  if (p.fake !== undefined) {
    const f = p.fake;
    const b = 1 - f;
    const cf = f === 0 ? p.c0 : p.c1;
    const vf = f === 0 ? p.v0 : p.v1;
    lines.push([`afirmação "${f}" (falsa): escolhe antes c<sub>${f}</sub> = ${cf} e v<sub>${f}</sub> = ${vf}, calcula A<sub>${f}</sub> = ${el(p.a[2 * f])}, D<sub>${f}</sub> = ${el(p.a[2 * f + 1])} de trás para frente`]);
    lines.push([`afirmação "${b}" (verdadeira): compromissos honestos A<sub>${b}</sub> = ${el(p.a[2 * b])}, D<sub>${b}</sub> = ${el(p.a[2 * b + 1])}`]);
    lines.push([`desafio: c = SHA-256(α, β, A<sub>0</sub>, D<sub>0</sub>, A<sub>1</sub>, D<sub>1</sub>) mod 11 = ${p.c}`]);
    lines.push([`o desafio que sobra: c<sub>${b}</sub> = ${p.c} − ${cf} mod 11 = ${b === 0 ? p.c0 : p.c1}; resposta com a senha r: v<sub>${b}</sub> = ${b === 0 ? p.v0 : p.v1}`]);
  } else {
    lines.push([`tentativa ${tentativas}, sem senha: chuta c<sub>0</sub> = ${p.c0}, v<sub>0</sub> = ${p.v0}, c<sub>1</sub> = ${p.c1}, v<sub>1</sub> = ${p.v1} e calcula os quatro compromissos de trás para frente`]);
    lines.push([`desafio: c = SHA-256(α, β, A<sub>0</sub>, D<sub>0</sub>, A<sub>1</sub>, D<sub>1</sub>) mod 11 = ${p.c}`]);
  }
  lines.push([`prova publicada: (c<sub>0</sub>, c<sub>1</sub>, v<sub>0</sub>, v<sub>1</sub>) = (${p.c0}, ${p.c1}, ${p.v0}, ${p.v1})`]);
  lines.push([`quem confere recalcula os compromissos e o hash: c = ${check.c}; c<sub>0</sub> + c<sub>1</sub> = ${mod(p.c0 + p.c1, Q)}`, check.ok ? 'ok' : 'mau']);
  if (m === 2) {
    lines.push([
      check.ok
        ? `a trapaça passou na tentativa ${tentativas}: no brinquedo há só 11 desafios. No grupo real seriam ≈ 7 × 10<sup>75</sup>`
        : `rejeitada. Aperte "Nova tentativa": no brinquedo, uma em cada 11 passa por sorte`,
      'obs',
    ]);
  } else {
    lines.push(['quem confere não tem como saber qual afirmação era a fingida', 'obs']);
  }
  return lines;
});

// -- 8. the whole ballot ----------------------------------------------------------

bench('run-cedula', async (box) => {
  const op = val(box, 'c-op');
  const names = ['A', 'B', 'branco'];
  const marks = names.map((n) => (op === n || (op === 'AB' && (n === 'A' || n === 'B')) ? 1 : 0));
  const rs = [4, 7, 2];
  const lines: Linha[] = [];
  const boxes: [number, number][] = [];
  for (let i = 0; i < 3; i += 1) {
    const [a, b] = enc(marks[i], rs[i]);
    boxes.push([a, b]);
    const proof = await proveDisj(a, b, marks[i], rs[i]);
    const ok = (await verifyDisj(a, b, proof)).ok;
    lines.push([`caixa ${names[i]}: (${el(a)}, ${el(b)}), prova de 0 ou 1`, ok ? 'ok' : 'mau']);
  }
  const A = mul(...boxes.map((x) => x[0]));
  const B = mul(...boxes.map((x) => x[1]));
  const rsum = mod(rs.reduce((n, x) => n + x, 0), Q);
  const X2 = mul(B, inv(G));
  const u = rand(Q);
  const a1 = pw(G, u);
  const a2 = pw(KEY, u);
  const c = await challenge('sum', A, X2, a1, a2);
  const v = mod(u + c * rsum, Q);
  const ok1 = pw(G, v) === mul(a1, pw(A, c));
  const ok2 = pw(KEY, v) === mul(a2, pw(X2, c));
  lines.push([`caixa-produto: (${el(A)}, ${el(B)}); senha da soma r = 4 + 7 + 2 = ${rsum} (mod 11)`]);
  lines.push([`prova de que a soma é 1: β ÷ g = ${el(X2)} tem de ser K<sup>${rsum}</sup> = ${el(pw(KEY, rsum))}; desafio c = ${c}`, ok1 && ok2 ? 'ok' : 'mau']);
  lines.push([
    ok1 && ok2
      ? 'cada caixa tem 0 ou 1 e a soma é 1: exatamente uma opção marcada'
      : c === 0 && op === 'AB'
        ? 'o desafio deu 0 e a prova passou por acaso; no grupo real isso não acontece'
        : 'a soma não é 1: a cédula é rejeitada, mesmo com cada caixa individualmente válida',
    'obs',
  ]);
  return lines;
});

// -- 9. the chain of codes ---------------------------------------------------------

let codigosIniciais: string[] | null = null;

bench('run-codigo', async (box) => {
  const ballots = [1, 2, 3].map((i) => val(box, `k-b${i}`));
  let head = await digest('chain-start', 'urna 7', 'sessão 1', 'zerésima');
  const lines: Linha[] = [[`cabeça inicial, da zerésima: ${short(head)}`]];
  const codes: string[] = [];
  for (let i = 0; i < 3; i += 1) {
    const code = await digest('code', head, await digest('ballot', ballots[i]));
    codes.push(code);
    head = await digest('chain', code, 'depositada');
    const changed = codigosIniciais !== null && codigosIniciais[i] !== code;
    lines.push([`código ${i + 1}: ${short(code, 20)}${changed ? ' <em class="mudou">(mudou)</em>' : ''}; cabeça seguinte: ${short(head)}`]);
  }
  if (codigosIniciais === null) codigosIniciais = codes;
  const any = codes.some((c, i) => c !== codigosIniciais![i]);
  lines.push([
    any
      ? 'mexer numa cédula mudou o código dela e de todas as seguintes; os eleitores com os comprovantes antigos percebem'
      : 'mude o texto da cédula 2 e veja os códigos 2 e 3 mudarem',
    'obs',
  ]);
  return lines;
});

// -- 10. audit or cast --------------------------------------------------------------

bench('run-benaloh', async (box) => {
  const voto = Number(val(box, 'b-voto'));
  const r = num(box, 'b-r');
  const swaps = checked(box, 'b-troca');
  const locked = swaps ? 1 - voto : voto;
  const [alpha, beta] = enc(locked, r);
  const code = await digest('code', alpha, beta);
  const [ra, rb] = enc(voto, r);
  const same = ra === alpha && rb === beta;
  let others = 0;
  for (let x = 0; x < Q; x += 1) {
    const [xa, xb] = enc(voto, x);
    if (xa === alpha && xb === beta) others += 1;
  }
  return [
    [`o eleitor escolhe ${voto}`],
    [`a urna tranca ${locked}${swaps ? ' (trocou!)' : ''}: α = ${el(alpha)}, β = ${el(beta)}`],
    [`a urna mostra o código ${short(code, 12)} antes de perguntar; a caixa não muda mais`],
    [`o eleitor aperta AUDITAR; a urna revela r = ${r} e diz ter trancado ${voto}`],
    [`o celular do eleitor tranca de novo ${voto} com r = ${r}: (${el(ra)}, ${el(rb)})`],
    [`compara com a caixa publicada (${el(alpha)}, ${el(beta)})`, same ? 'ok' : 'mau'],
    [
      same
        ? 'a urna trancou o que o eleitor escolheu'
        : `a troca foi pega. Testando os 11 valores possíveis de r, ${others === 0 ? 'nenhum' : others} faz a caixa bater com o voto ${voto}: α fixa r, e β fixa o voto`,
      'obs',
    ],
  ];
});

// -- 11. the board ----------------------------------------------------------------

const leaf = async (s: string) => sha256(new Uint8Array([0, ...utf8(s)]));
const node = async (l: Uint8Array, r: Uint8Array) => sha256(new Uint8Array([1, ...l, ...r]));

let raizAssinada: string | null = null;

bench('run-mural', async (box) => {
  const entries = ['manifesto da eleição', 'cerimônia de chaves', val(box, 'mu-e2'), 'pacote da urna 7'];
  const h = await Promise.all(entries.map(leaf));
  const h01 = await node(h[0], h[1]);
  const h23 = await node(h[2], h[3]);
  const root = toHex(await node(h01, h23));
  if (raizAssinada === null) raizAssinada = root;
  const recomputed = toHex(await node(h01, await node(h[2], h[3])));
  const s = (b: Uint8Array) => short(toHex(b), 8);
  return [
    [`folhas: h<sub>0</sub> = ${s(h[0])}, h<sub>1</sub> = ${s(h[1])}, h<sub>2</sub> (a sua) = ${s(h[2])}, h<sub>3</sub> = ${s(h[3])}`],
    [`nós: h<sub>01</sub> = H(01 ‖ h<sub>0</sub> ‖ h<sub>1</sub>) = ${s(h01)}, h<sub>23</sub> = H(01 ‖ h<sub>2</sub> ‖ h<sub>3</sub>) = ${s(h23)}`],
    [`raiz assinada pelo mural (4 entradas): ${short(raizAssinada, 16)}`],
    [`prova de inclusão da sua entrada: só [h<sub>3</sub>, h<sub>01</sub>], dois hashes`],
    [`você recalcula H(01 ‖ h<sub>01</sub> ‖ H(01 ‖ h<sub>2</sub> ‖ h<sub>3</sub>)) = ${short(recomputed, 16)}`, recomputed === raizAssinada ? 'ok' : 'mau'],
    [
      recomputed === raizAssinada
        ? 'a sua entrada está no mural assinado'
        : 'com a entrada alterada, a raiz não bate: o mural assinado não contém este texto',
      'obs',
    ],
  ];
});

// -- 12. the mixnet ---------------------------------------------------------------

const VOTOS = [1, 2, 2, 3];
const RS = [3, 5, 8, 9];

bench('run-mixnet', () => {
  const input = VOTOS.map((m, i) => enc(m, RS[i]));
  const perm = [0, 1, 2, 3];
  for (let i = perm.length - 1; i > 0; i -= 1) {
    const j = rand(i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const fresh = perm.map(() => 1 + rand(Q - 1));
  const output = perm.map((p, i) => {
    const [a, b] = input[p];
    return [mul(a, pw(G, fresh[i])), mul(b, pw(KEY, fresh[i]))] as [number, number];
  });
  const open = ([a, b]: [number, number]) => lg(mul(b, inv(pw(a, KEY_S))));
  const fmt = (list: [number, number][]) => list.map(([a, b]) => `(${a}, ${b})`).join('  ');
  const disjoint = output.every(([a, b]) => !input.some(([x, y]) => x === a && y === b));
  const sameVotes = [...output.map(open)].sort().join() === [...VOTOS].sort().join();
  return [
    [`entrada: ${fmt(input)}`],
    [`saída: ${fmt(output)}`],
    [`segredo do embaralhador (não publicado): saída i veio da entrada ${perm.map((p) => p + 1).join(', ')}, com r' = ${fresh.join(', ')}`, 'obs'],
    ['nenhuma caixa da saída é igual a uma da entrada', disjoint ? 'ok' : 'mau'],
    [`abrindo a saída: votos ${output.map(open).join(', ')}; mesma coleção da entrada (${VOTOS.join(', ')}), em outra ordem`, sameVotes ? 'ok' : 'mau'],
  ];
});
