import { useEffect, useState, type ReactNode } from 'react';
import { useSim, type Snapshot, type Ui } from '../sim';

/** One step of the guided tour. `feito` says whether the election has got past it; manual steps have none. */
interface Passo {
  titulo: string;
  faca: ReactNode;
  porque: ReactNode;
  leia: { rotulo: string; href: string }[];
  feito?: (snap: Snapshot, ui: Ui) => boolean;
}

const PHASE_ORDER = ['setup', 'ceremony-done', 'polls-open', 'polls-closed', 'tallied'];
const atLeast = (snap: Snapshot, phase: string) => PHASE_ORDER.indexOf(snap.phase) >= PHASE_ORDER.indexOf(phase);
const printed = (ui: Ui, kind: string) => ui.strips.some((s) => s.data.kind === kind);
const sessions = (ui: Ui) => Object.values(ui.sessions);

const PASSOS: Passo[] = [
  {
    titulo: 'A eleição',
    faca: (
      <>
        Abra a aba <b>Candidatos</b> na bancada. É a eleição geral da República Galáctica: presidente e duas vagas de
        senador em cada um dos dez planetas. Anote o número de um candidato em quem vai votar.
      </>
    ),
    porque: (
      <>
        Tudo o que define a eleição (cargos, candidatos, guardiões, seções) está no <i>manifesto</i>, assinado e
        publicado antes de tudo. Nada disso pode mudar depois.
      </>
    ),
    leia: [{ rotulo: 'Início, Cap. VI', href: './#cap-6' }],
  },
  {
    titulo: 'Cerimônia de chaves',
    faca: (
      <>
        No <b>Palco</b>, aperte <b>Realizar cerimônia de chaves</b>. A aba Cerimônia mostra os três guardiões e as
        provas que cada um publicou.
      </>
    ),
    porque: (
      <>
        A chave da eleição nasce repartida: dois dos três guardiões, juntos, abrem a soma; um sozinho não abre nada. A
        chave inteira nunca existe em lugar nenhum.
      </>
    ),
    leia: [
      { rotulo: 'Início, Cap. II', href: './#cap-2' },
      { rotulo: 'Técnico, §4', href: './tecnico.html#t-shamir' },
    ],
    feito: (snap) => atLeast(snap, 'ceremony-done'),
  },
  {
    titulo: 'Abrir a votação',
    faca: (
      <>
        Aperte <b>Abrir votação</b>. A Justiça Eleitoral publica o cadastro de urnas e o registro de abertura.
      </>
    ),
    porque: (
      <>A partir daqui o cadastro está congelado: nenhuma urna ou seção nova pode entrar sem que o verificador acuse.</>
    ),
    leia: [{ rotulo: 'Técnico, §15', href: './tecnico.html#t-verificador' }],
    feito: (snap) => atLeast(snap, 'polls-open'),
  },
  {
    titulo: 'Abrir a seção',
    faca: (
      <>
        Escolha uma seção no Palco (por exemplo, Tatooine) e aperte <b>Abrir seção (zerésima)</b>. A zerésima sai na
        <b> Impressora</b>, à direita.
      </>
    ),
    porque: (
      <>
        A zerésima prova que a urna começou vazia e fixa o primeiro elo da corrente de códigos. Mesários e fiscais
        assinam e guardam uma cópia.
      </>
    ),
    leia: [{ rotulo: 'Início, Cap. VII', href: './#cap-7' }],
    feito: (_s, ui) => printed(ui, 'zeresima'),
  },
  {
    titulo: 'Liberar o eleitor',
    faca: (
      <>
        Aperte <b>Identificar eleitor e liberar a urna</b>. O mesário confere o documento e libera um voto.
      </>
    ),
    porque: (
      <>
        Cada voto consome uma autorização assinada pelo mesário. A urna nunca recebe quem é o eleitor, só a permissão
        para um voto.
      </>
    ),
    leia: [{ rotulo: 'Técnico, §12', href: './tecnico.html#t-apuracao' }],
    feito: (_s, ui) => sessions(ui).some((m) => m.authorized || m.pending || m.cast > 0 || m.spoiled > 0),
  },
  {
    titulo: 'Votar',
    faca: (
      <>
        Na aba <b>Urna</b>, digite o número de cada candidato e aperte <b>CONFIRMA</b>: senador da 1ª vaga, da 2ª vaga e
        presidente. Pode usar o teclado do computador. Ao fim, a urna mostra o <b>código de rastreamento</b>. Ainda não
        aperte nada.
      </>
    ),
    porque: (
      <>
        A urna já trancou o seu voto e calculou o código. Ela se comprometeu antes de saber se você vai depositar ou
        auditar. É isso que permite pegá-la no passo seguinte.
      </>
    ),
    leia: [
      { rotulo: 'Início, Cap. I', href: './#cap-1' },
      { rotulo: 'Técnico, §8', href: './tecnico.html#t-cedula' },
    ],
    feito: (_s, ui) => sessions(ui).some((m) => m.pending || m.cast > 0 || m.spoiled > 0),
  },
  {
    titulo: 'Auditar',
    faca: (
      <>
        Na tela do código, aperte a tecla azul <b>AUDITAR</b>. Sai um <b>recibo de auditoria</b> com as escolhas que a
        urna diz ter trancado. Confira se são as suas. Esse voto não vale: vote de novo.
      </>
    ),
    porque: (
      <>
        A urna é obrigada a revelar o segredo daquela caixa. Se ela tivesse trancado outra coisa, o recibo mostraria. O
        voto auditado nunca é contado, e fica público.
      </>
    ),
    leia: [
      { rotulo: 'Início, Cap. IV', href: './#cap-4' },
      { rotulo: 'Técnico, §10', href: './tecnico.html#t-benaloh' },
    ],
    feito: (_s, ui) => printed(ui, 'spoil'),
  },
  {
    titulo: 'Depositar',
    faca: (
      <>
        Vote de novo e, na tela do código, aperte <b>CONFIRMA</b>. Sai o <b>comprovante</b>, que traz só o código de rastreamento, sem nenhum candidato. Anote os primeiros grupos do
        código: você vai procurá-lo no mural.
      </>
    ),
    porque: (
      <>
        Ao depositar, a urna apaga o segredo da caixa. O comprovante prova que a caixa existe, não o que tem dentro: você
        não consegue provar a ninguém em quem votou.
      </>
    ),
    leia: [{ rotulo: 'Início, Cap. V', href: './#cap-5' }],
    feito: (_s, ui) => printed(ui, 'slip'),
  },
  {
    titulo: 'Mais eleitores',
    faca: (
      <>
        Aperte <b>Simular 5 votos aleatórios</b> algumas vezes para encher a seção. Se quiser, abra outras seções e vote
        nelas também.
      </>
    ),
    porque: (
      <>Uma seção com pouquíssimos votos revelaria demais ao ser aberta. Seções pequenas são somadas a um grupo maior.</>
    ),
    leia: [{ rotulo: 'Técnico, §12', href: './tecnico.html#t-apuracao' }],
    feito: (_s, ui) => sessions(ui).reduce((n, m) => n + m.cast, 0) >= 6,
  },
  {
    titulo: 'Encerrar a seção',
    faca: (
      <>
        Aperte <b>Encerrar seção</b>. Sai o <b>pré-boletim</b>: comparecimento, cédulas e a impressão digital da soma
        trancada. Nenhum número por candidato.
      </>
    ),
    porque: (
      <>
        A urna não sabe quantos votos cada um teve. O fiscal guarda a impressão digital; depois da apuração, o boletim
        tem de trazer a mesma.
      </>
    ),
    leia: [{ rotulo: 'Início, Cap. VII', href: './#cap-7' }],
    feito: (_s, ui) => printed(ui, 'prebu'),
  },
  {
    titulo: 'Conferir o recibo',
    faca: (
      <>
        Na Impressora, ache o recibo de auditoria e aperte <b>Conferir este recibo de forma independente</b>. O pacote da
        seção já está no mural, então a conferência recifra as escolhas e compara com a caixa publicada.
      </>
    ),
    porque: (
      <>
        Quem confere é um aparelho que não é a urna. Uma urna desonesta diria "está tudo certo" de qualquer jeito. Ligue a
        sabotagem "Urna troca votos" numa próxima eleição para ver a conferência falhar.
      </>
    ),
    leia: [{ rotulo: 'Técnico, §10', href: './tecnico.html#t-benaloh' }],
  },
  {
    titulo: 'Encerrar a votação',
    faca: (
      <>
        Aperte <b>Encerrar votação</b>. As seções ainda abertas são encerradas e o corte é publicado. Urnas que nunca
        abriram aparecem como ausentes no verificador.
      </>
    ),
    porque: <>Só entram na apuração os pacotes publicados antes do corte.</>,
    leia: [{ rotulo: 'Técnico, §11', href: './tecnico.html#t-mural' }],
    feito: (snap) => atLeast(snap, 'polls-closed'),
  },
  {
    titulo: 'Apurar',
    faca: (
      <>
        Aperte <b>Apurar votos</b> e veja a aba <b>Resultado</b>: votos válidos, brancos, nulos, se houve segundo turno e
        os senadores eleitos em cada planeta.
      </>
    ),
    porque: (
      <>
        Os guardiões abriram só as somas, cada um com a sua parte e uma prova. Nenhuma cédula individual foi aberta.
      </>
    ),
    leia: [
      { rotulo: 'Início, Cap. II', href: './#cap-2' },
      { rotulo: 'Técnico, §14', href: './tecnico.html#t-resultado' },
    ],
    feito: (snap) => atLeast(snap, 'tallied'),
  },
  {
    titulo: 'Boletins',
    faca: (
      <>
        Abra a aba <b>Boletins</b>. Cada seção tem o seu BU, com a impressão digital comparada à do pré-boletim que
        saiu na Impressora.
      </>
    ),
    porque: <>Se o pacote tivesse sido trocado no caminho, as impressões digitais não bateriam.</>,
    leia: [{ rotulo: 'Técnico, Prop. 12.1', href: './tecnico.html#t-apuracao' }],
  },
  {
    titulo: 'Verificar',
    faca: (
      <>
        Aperte <b>Rodar verificador</b>. A aba <b>Verificação</b> mostra os 16 passos, refeitos só com o mural público.
      </>
    ),
    porque: (
      <>
        O verificador não usa nenhuma chave nem confia em ninguém. Qualquer pessoa pode escrever o seu e chegar ao mesmo
        veredito. Se você abriu só uma seção, o passo 7 (Completude) falha: as outras seções não mandaram pacote, e o
        verificador acusa. Para ver tudo passar, use <i>Rodar eleição completa</i> numa nova eleição.
      </>
    ),
    leia: [
      { rotulo: 'Início, Cap. IX', href: './#cap-9' },
      { rotulo: 'Técnico, §15', href: './tecnico.html#t-verificador' },
    ],
    feito: (_s, ui) => ui.report !== null,
  },
  {
    titulo: 'Conferir o código',
    faca: (
      <>
        Ainda na Verificação, digite o código do seu comprovante em <b>Consultar meu código</b>. O mural mostra a sua
        caixa, a situação "depositada" e uma prova de inclusão.
      </>
    ),
    porque: <>A prova de inclusão liga a sua caixa à raiz assinada do mural, com poucos hashes.</>,
    leia: [{ rotulo: 'Técnico, §11', href: './tecnico.html#t-mural' }],
    feito: (_s, ui) => ui.lookup !== null,
  },
  {
    titulo: 'Sabotar',
    faca: (
      <>
        Abra <b>Sabotagem</b> no Palco e aperte <b>Nova eleição</b>. Ligue uma sabotagem, como "Resultado adulterado antes da assinatura" ou
        "Guardião mente na decifragem", rode a eleição (o atalho <b>Rodar eleição completa</b> serve) e veja qual passo
        do verificador a pega.
      </>
    ),
    porque: (
      <>
        Cada sabotagem diz quem deveria detectá-la. Uma delas, "Urna troca votos", o verificador público não pega: só a
        conferência do recibo de auditoria. É o limite mais importante deste desenho.
      </>
    ),
    leia: [{ rotulo: 'Início, problemas', href: './#problemas' }],
  },
];

const KEY = 'roteiro-passo';
const KEY_HIDDEN = 'roteiro-oculto';

function load(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function save(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // The tour still works; it just forgets its place on reload.
  }
}

/** The guided tour: one step at a time, ticked off when the election has got past it. */
export function Roteiro() {
  const { snap, ui } = useSim();
  const [i, setI] = useState(() => Math.min(Number(load(KEY) ?? 0) || 0, PASSOS.length - 1));
  const [hidden, setHidden] = useState(() => load(KEY_HIDDEN) === '1');

  useEffect(() => save(KEY, String(i)), [i]);
  useEffect(() => save(KEY_HIDDEN, hidden ? '1' : '0'), [hidden]);

  if (hidden) {
    return (
      <div className="roteiro roteiro-fechado">
        <button type="button" className="btn btn-small" onClick={() => setHidden(false)}>
          Mostrar roteiro (passo {i + 1} de {PASSOS.length})
        </button>
      </div>
    );
  }

  const p = PASSOS[i];
  const done = p.feito ? p.feito(snap, ui) : null;

  return (
    <section className="roteiro" aria-labelledby="roteiro-titulo">
      <div className="roteiro-cab">
        <span className="roteiro-rotulo">Roteiro</span>
        <ol className="roteiro-trilha" aria-label="Passos do roteiro">
          {PASSOS.map((q, n) => {
            const ok = q.feito ? q.feito(snap, ui) : n < i;
            return (
              <li key={q.titulo}>
                <button
                  type="button"
                  className={`roteiro-ponto ${n === i ? 'atual' : ''} ${ok ? 'ok' : ''}`}
                  aria-current={n === i ? 'step' : undefined}
                  aria-label={`Passo ${n + 1}: ${q.titulo}${ok ? ', feito' : ''}`}
                  title={q.titulo}
                  onClick={() => setI(n)}
                >
                  {n + 1}
                </button>
              </li>
            );
          })}
        </ol>
        <button type="button" className="btn btn-small roteiro-esconder" onClick={() => setHidden(true)}>
          Esconder roteiro
        </button>
      </div>

      <div className="roteiro-corpo">
        <div className="roteiro-texto">
          <h2 id="roteiro-titulo" className="roteiro-titulo">
            <span className="roteiro-num">{i + 1}.</span> {p.titulo}
            {done === true && <span className="roteiro-feito"> feito</span>}
          </h2>
          <p className="roteiro-faca">{p.faca}</p>
          <p className="roteiro-porque">
            <span className="roteiro-por">Por quê.</span> {p.porque}{' '}
            {p.leia.map((l, n) => (
              <span key={l.href}>
                {n > 0 && ' · '}
                <a href={l.href} target="_blank" rel="noreferrer">
                  {l.rotulo}
                </a>
              </span>
            ))}
          </p>
        </div>
        <div className="roteiro-nav">
          <button type="button" className="btn" disabled={i === 0} onClick={() => setI(i - 1)}>
            Anterior
          </button>
          <button
            type="button"
            className={`btn ${done !== false ? 'btn-primary' : ''}`}
            disabled={i === PASSOS.length - 1}
            onClick={() => setI(i + 1)}
          >
            Próximo
          </button>
        </div>
      </div>
    </section>
  );
}
