// Small interactive figures for the Início page. Each one does the real
// arithmetic, with numbers small enough to follow by hand.
import './site.css';

// -- I. adding locked boxes ------------------------------------------------------

/** A toy group: the squares modulo the safe prime p = 2q + 1, which have prime order q. */
const P = 2039;
const Q = 1019;
const G = 4;

function powmod(base: number, exp: number, mod: number): number {
  let result = 1;
  let b = base % mod;
  let e = exp;
  while (e > 0) {
    if (e & 1) result = (result * b) % mod;
    b = (b * b) % mod;
    e = Math.floor(e / 2);
  }
  return result;
}

function randomBelow(n: number): number {
  return crypto.getRandomValues(new Uint32Array(1))[0] % n;
}

function toySomar(root: HTMLElement) {
  const list = root.querySelector<HTMLUListElement>('.caixas')!;
  const out = root.querySelector<HTMLElement>('[data-saida]')!;
  const sumBtn = root.querySelector<HTMLButtonElement>('[data-acao="somar"]')!;
  let secret = 1 + randomBelow(Q - 1);
  let key = powmod(G, secret, P);
  let boxes: { a: number; b: number }[] = [];

  const render = () => {
    list.replaceChildren(
      ...boxes.map((box, i) => {
        const li = document.createElement('li');
        li.innerHTML = `<span>caixa ${i + 1}</span>(${box.a}, ${box.b})`;
        return li;
      }),
    );
    sumBtn.disabled = boxes.length < 2;
    if (boxes.length === 0) out.textContent = 'Nenhuma caixa ainda.';
    else if (boxes.length === 1) out.textContent = 'Uma caixa. Vote mais para ter o que somar.';
    else out.textContent = `${boxes.length} caixas trancadas. Olhando os números, dá para saber quem votou em quem?`;
  };

  root.querySelectorAll<HTMLButtonElement>('[data-voto]').forEach((btn) =>
    btn.addEventListener('click', () => {
      if (boxes.length >= 12) {
        out.textContent = 'Doze caixas bastam para o exemplo. Junte e abra o total.';
        return;
      }
      const m = Number(btn.dataset.voto);
      const r = 1 + randomBelow(Q - 1);
      boxes.push({ a: powmod(G, r, P), b: (powmod(G, m, P) * powmod(key, r, P)) % P });
      render();
    }),
  );

  sumBtn.addEventListener('click', () => {
    const total = boxes.reduce((acc, x) => ({ a: (acc.a * x.a) % P, b: (acc.b * x.b) % P }), { a: 1, b: 1 });
    // Opening: β / α^s, then find which small m gives g^m.
    const gm = (total.b * powmod(total.a, Q - secret, P)) % P;
    let m = 0;
    while (m <= boxes.length && powmod(G, m, P) !== gm) m += 1;
    const luke = m;
    const vader = boxes.length - m;
    out.innerHTML =
      `Caixa do total: (${total.a}, ${total.b}), o produto das caixas, número a número, módulo ${P}.<br>` +
      `Aberta com a chave: <strong>Luke ${luke}, Vader ${vader}</strong>. Nenhuma caixa individual foi aberta.`;
  });

  root.querySelector<HTMLButtonElement>('[data-acao="limpar"]')!.addEventListener('click', () => {
    secret = 1 + randomBelow(Q - 1);
    key = powmod(G, secret, P);
    boxes = [];
    render();
  });

  render();
}

// -- II. the hidden line -----------------------------------------------------------

const SVG_NS = 'http://www.w3.org/2000/svg';
const NAMES: Record<number, string> = { 1: 'Conselho Jedi', 2: 'Aliança Rebelde', 3: 'Clã Bancário' };

function el(tag: string, attrs: Record<string, string | number>, text?: string): SVGElement {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  if (text !== undefined) node.textContent = text;
  return node;
}

function toyReta(root: HTMLElement) {
  const svg = root.querySelector<SVGSVGElement>('[data-plot]')!;
  const out = root.querySelector<HTMLElement>('[data-saida]')!;
  const buttons = [...root.querySelectorAll<HTMLButtonElement>('[data-g]')];
  let secret = 0;
  let slope = 0;

  const X0 = 56;
  const X1 = 500;
  const Y0 = 256;
  const Y1 = 16;
  const XMAX = 3.4;
  const YMAX = 30;
  const sx = (x: number) => X0 + (x / XMAX) * (X1 - X0);
  const sy = (y: number) => Y0 - (y / YMAX) * (Y0 - Y1);

  const newLine = () => {
    secret = 3 + randomBelow(10);
    slope = 2 + randomBelow(4);
  };

  /** Draws the line through (x, y) with intercept b, clipped to the plot. */
  const line = (b: number, x: number, y: number, cls: string) => {
    const m = (y - b) / x;
    let xEnd = XMAX;
    let yEnd = b + m * XMAX;
    if (yEnd > YMAX) {
      xEnd = (YMAX - b) / m;
      yEnd = YMAX;
    } else if (yEnd < 0) {
      xEnd = -b / m;
      yEnd = 0;
    }
    svg.append(el('line', { x1: sx(0), y1: sy(b), x2: sx(xEnd), y2: sy(yEnd), class: cls }));
  };

  const render = () => {
    svg.replaceChildren();
    // axes and ticks
    svg.append(el('path', { d: `M${X0} ${Y1} V${Y0} H${X1}`, class: 't' }));
    for (let y = 0; y <= YMAX; y += 5) {
      svg.append(el('path', { d: `M${X0 - 5} ${sy(y)} h5`, class: 't fino' }));
      svg.append(el('text', { x: X0 - 10, y: sy(y) + 4, 'text-anchor': 'end', class: 'num' }, String(y)));
    }
    for (let x = 1; x <= 3; x += 1) {
      svg.append(el('path', { d: `M${sx(x)} ${Y0} v5`, class: 't fino' }));
      svg.append(el('text', { x: sx(x), y: Y0 + 20, 'text-anchor': 'middle', class: 'num' }, String(x)));
    }
    svg.append(el('text', { x: X0 + 6, y: Y1 + 4, class: 'rot' }, 'o segredo fica neste eixo'));

    const chosen = buttons.filter((b) => b.getAttribute('aria-pressed') === 'true').map((b) => Number(b.dataset.g));
    const pts = chosen.map((x) => ({ x, y: secret + slope * x }));

    if (pts.length === 1) {
      const { x, y } = pts[0];
      for (let b = 0; b <= YMAX; b += 3) line(b, x, y, 's fino tracejado');
    }
    if (pts.length >= 2) {
      line(secret, pts[0].x, pts[0].y, 's');
      svg.append(el('circle', { cx: sx(0), cy: sy(secret), r: 6, class: 'cheio' }));
      svg.append(el('text', { x: sx(0) + 12, y: sy(secret) + 5, class: 'letra' }, `segredo = ${secret}`));
    }
    for (const p of pts) {
      svg.append(el('circle', { cx: sx(p.x), cy: sy(p.y), r: 5, class: 'cheio-tinta' }));
      const right = p.x === 3;
      svg.append(
        el(
          'text',
          { x: sx(p.x) + (right ? -9 : 9), y: sy(p.y) + 16, class: 'rot', 'text-anchor': right ? 'end' : 'start' },
          `${NAMES[p.x]} (${p.x}, ${p.y})`,
        ),
      );
    }

    if (pts.length === 0) out.textContent = 'Nenhum guardião presente: o segredo pode ser qualquer número.';
    else if (pts.length === 1)
      out.textContent = `Só o ${NAMES[pts[0].x]}: todas estas retas passam pelo ponto dele, e cada uma corta o eixo numa altura diferente. Ele não sabe nada sobre o segredo.`;
    else
      out.textContent = `${pts.map((p) => NAMES[p.x]).join(' e ')}: por dois pontos passa uma única reta. Ela corta o eixo em ${secret}.`;
  };

  buttons.forEach((b) =>
    b.addEventListener('click', () => {
      b.setAttribute('aria-pressed', b.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
      render();
    }),
  );
  root.querySelector<HTMLButtonElement>('[data-acao="nova"]')!.addEventListener('click', () => {
    newLine();
    render();
  });

  newLine();
  render();
}

// -- III. two caves, one password ----------------------------------------------------

type Lado = 'esquerda' | 'direita';
const outro = (l: Lado): Lado => (l === 'esquerda' ? 'direita' : 'esquerda');
const sorteiaLado = (): Lado => (randomBelow(2) === 0 ? 'esquerda' : 'direita');

/** One round of the two-cave game: what the judge sees, and what happened behind the scenes. */
function rodada(caixa: number): { juiz: string; bastidores: string; ok: boolean } {
  const iguais = randomBelow(2) === 0;
  const moeda = iguais ? 'iguais' : 'diferentes';
  const exige = (a: Lado): Lado => (iguais ? a : outro(a));

  if (caixa === 0 || caixa === 1) {
    // The honest machine fakes the cave whose password it lacks, by fixing its answer before the coin.
    const fingida = 1 - caixa;
    const ladoFingida = sorteiaLado();
    const entrouVerdadeira = sorteiaLado();
    const ladoVerdadeira = exige(ladoFingida);
    const lados: Record<number, Lado> = { [fingida]: ladoFingida, [caixa]: ladoVerdadeira };
    return {
      ok: true,
      juiz: `moeda: ${moeda} · caverna do 0 saiu pela ${lados[0]} ✓ · caverna do 1 saiu pela ${lados[1]} ✓`,
      bastidores:
        `fingiu a caverna do ${fingida}: entrou pela ${ladoFingida} e decidiu esse lado antes da moeda. ` +
        (entrouVerdadeira === ladoVerdadeira
          ? `Na caverna do ${caixa} já estava do lado certo.`
          : `Na caverna do ${caixa} estava na ${entrouVerdadeira} e usou a senha para atravessar a porta.`),
    };
  }

  // The cheater knows no password: both sides were fixed before the coin.
  const e0 = sorteiaLado();
  const e1 = sorteiaLado();
  const pedido1 = exige(e0);
  const ok = pedido1 === e1;
  return {
    ok,
    juiz: ok
      ? `moeda: ${moeda} · caverna do 0 saiu pela ${e0} ✓ · caverna do 1 saiu pela ${e1} ✓`
      : `moeda: ${moeda} · caverna do 0 saiu pela ${e0} ✓ · caverna do 1 anunciou ${pedido1}, ficou presa na ${e1} ✗`,
    bastidores: `sem senha nenhuma: entrou pela ${e0} e pela ${e1} e torceu para a moeda combinar.`,
  };
}

function toyCavernas(root: HTMLElement) {
  const list = root.querySelector<HTMLOListElement>('.rodadas')!;
  const out = root.querySelector<HTMLElement>('[data-saida]')!;
  const back = root.querySelector<HTMLInputElement>('#cav-bastidores')!;
  const boxes = [...root.querySelectorAll<HTMLButtonElement>('[data-caixa]')];
  let caixa = 1;

  boxes.forEach((b) =>
    b.addEventListener('click', () => {
      caixa = Number(b.dataset.caixa);
      boxes.forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      list.replaceChildren();
      out.textContent = '';
    }),
  );

  const showBack = () => list.classList.toggle('com-bastidores', back.checked);
  back.addEventListener('change', showBack);

  root.querySelector<HTMLButtonElement>('[data-acao="rodar"]')!.addEventListener('click', () => {
    const rounds = Array.from({ length: 20 }, () => rodada(caixa));
    list.replaceChildren(
      ...rounds.map((r) => {
        const li = document.createElement('li');
        li.className = r.ok ? '' : 'falhou';
        const juiz = document.createElement('span');
        juiz.textContent = r.juiz;
        const atras = document.createElement('span');
        atras.className = 'atras';
        atras.textContent = r.bastidores;
        li.append(juiz, atras);
        return li;
      }),
    );
    showBack();
    const erros = rounds.filter((r) => !r.ok).length;
    const primeira = rounds.findIndex((r) => !r.ok) + 1;
    if (erros === 0 && caixa !== 500) {
      out.textContent =
        `Passou nas 20 rodadas. O juiz se convence de que a caixa tem 0 ou 1. Rode com a outra caixa honesta: ` +
        `as linhas que o juiz vê têm a mesma cara, e nada nelas diz qual caverna era a verdadeira.`;
    } else if (erros === 0) {
      out.textContent = 'A trapaceira passou nas 20 rodadas por pura sorte. Isso acontece uma vez em cerca de um milhão.';
    } else {
      out.innerHTML =
        `<strong class="mau">Pega na rodada ${primeira}.</strong> Errou ${erros} de 20 rodadas. ` +
        `Sem a senha de nenhuma caverna, só passa quando a moeda combina com os dois lados que ela já tinha escolhido.`;
    }
  });
}

// -- IV. the chance of escaping an audit -------------------------------------------

function toyBenaloh(root: HTMLElement) {
  const k = root.querySelector<HTMLInputElement>('#b-k')!;
  const p = root.querySelector<HTMLInputElement>('#b-p')!;
  const kOut = root.querySelector<HTMLOutputElement>('[data-k]')!;
  const pOut = root.querySelector<HTMLOutputElement>('[data-p]')!;
  const out = root.querySelector<HTMLElement>('[data-saida]')!;
  const pct = (x: number) =>
    x < 0.0001 ? 'menos de 0,01%' : `${(x * 100).toLocaleString('pt-BR', { maximumFractionDigits: x < 0.01 ? 3 : 1 })}%`;

  const render = () => {
    const kv = Number(k.value);
    const pv = Number(p.value) / 100;
    kOut.textContent = String(kv);
    pOut.textContent = `${p.value}%`;
    const escape = Math.pow(1 - pv, kv);
    out.innerHTML =
      `Cada voto trocado escapa com chance ${pct(1 - pv)}. Para os ${kv} escaparem: ` +
      `(${(1 - pv).toLocaleString('pt-BR')})<sup>${kv}</sup> = <strong>${pct(escape)}</strong>.<br>` +
      `Chance de a urna ser pega: <strong class="${escape < 0.05 ? 'ok' : 'mau'}">${pct(1 - escape)}</strong>.`;
  };
  k.addEventListener('input', render);
  p.addEventListener('input', render);
  render();
}

// -- V. the chain of codes ------------------------------------------------------------

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function toyCorrente(root: HTMLElement) {
  const list = root.querySelector<HTMLOListElement>('.corrente')!;
  const start = ['caixa trancada nº 1', 'caixa trancada nº 2', 'caixa trancada nº 3', 'caixa trancada nº 4'];
  const inputs: HTMLInputElement[] = [];
  const codes: HTMLElement[] = [];
  let previous: string[] = [];

  start.forEach((text, i) => {
    const li = document.createElement('li');
    const label = document.createElement('label');
    label.htmlFor = `elo-${i}`;
    label.textContent = `Eleitor ${i + 1}`;
    const input = document.createElement('input');
    input.id = `elo-${i}`;
    input.value = text;
    input.disabled = i !== 1;
    const code = document.createElement('span');
    code.className = 'cod';
    li.append(label, input, code);
    list.append(li);
    inputs.push(input);
    codes.push(code);
  });

  const render = async () => {
    // head_0 comes from the zerésima; each code hashes the previous head and the box.
    let head = await sha256Hex('zerésima · Urna-Tatooine');
    const now: string[] = [];
    for (const input of inputs) {
      head = await sha256Hex(head + input.value);
      now.push(head);
    }
    now.forEach((c, i) => {
      const short = c.slice(0, 20).toUpperCase().match(/.{4}/g)!.join('-');
      codes[i].textContent = `código ${short}`;
      codes[i].classList.toggle('mudou', previous.length > 0 && previous[i] !== c);
    });
    if (previous.length === 0) previous = now;
  };

  inputs[1].addEventListener('input', () => void render());
  void render();
}

// -- wiring -----------------------------------------------------------------------

const toys: [string, (root: HTMLElement) => void][] = [
  ['toy-somar', toySomar],
  ['toy-reta', toyReta],
  ['toy-cavernas', toyCavernas],
  ['toy-benaloh', toyBenaloh],
  ['toy-corrente', toyCorrente],
];
for (const [id, init] of toys) {
  const root = document.getElementById(id);
  if (root) init(root);
}
