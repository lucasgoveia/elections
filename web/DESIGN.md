# Urna Lab: design brief

A test bench for the eg/v1 library, running entirely in the browser through
WebAssembly. One job: run a Brazilian polling day end to end, see every
artifact the protocol produces, and break things on purpose to watch the
checks catch them.

Audience: the protocol designer, auditors, party observers (fiscais). They know
the urna eletrônica and its paper (zerésima, boletim de urna). They are not
cryptographers.

## Tokens

| Token | Hex | Use |
|---|---|---|
| `--wall` | `#C9CFC7` | page ground: the pale green-grey of a school classroom, where Brazilians vote |
| `--slate` | `#24302B` | chalkboard: top rail and the bulletin-board ledger |
| `--paper` | `#FBFBF7` | thermal paper, only for printed strips and the audit sheet |
| `--ink` | `#161A18` | text |
| `--muted` | `#55605A` | secondary text |
| `--urna` | `#D8D2C2` | the voting machine body, only inside the urna component |
| `--lcd` | `#E3E9DF` | the urna screen |
| `--key` | `#111111` | keypad keys |
| `--confirma` | `#1F8A3B` | CONFIRMA key, and "check passed" |
| `--corrige` | `#E86A17` | CORRIGE key |
| `--branco` | `#F4F4F0` | BRANCO key |
| `--stamp` | `#B3261E` | failure stamps and failed checks |

Type (Google Fonts, each with a system fallback stack):
- Display: **Bricolage Grotesque** 700, used sparingly for phase titles and the
  result numbers.
- Body: **Public Sans** 400/600. It was designed for government services, which
  fits.
- Data: **Martian Mono** 300/500 for everything printed (strips, hashes,
  tracking codes, the urna screen).

Scale: 12 / 14 / 16 / 20 / 28 / 44 px. Radius: 2 px for panels, 6 px for keys.
No gradients. Shadows only on paper strips (paper lifts off the desk).

## Layout

```
┌ rail ─ eg/v1 Urna Lab │ Ceremony ▸ Polls ▸ Voting ▸ Close ▸ Tally ▸ Verify │ root 3fa2…91 ┐
├─ STAGE (300px) ──────┬─ WORKBENCH (fluid) ─────────────┬─ PRINTER (320px) ────────────┤
│ actions for this     │ ceremony: trustee cards         │ slot ═══════════════        │
│ phase: who acts      │ voting: the URNA                │ ┌ strip (newest) ┐          │
│ (mesário, trustee,   │ tally: results, seats, BU       │ │ zig-zag edges  │          │
│ EA) and the buttons  │   match chips                   │ │ mono text, QR  │          │
│                      │ verify: audit sheet + lookup    │ └────────────────┘          │
│ Sabotage (collapsed) │                                 │ older strips below          │
├──────────────────────┴─────────────────────────────────┴─────────────────────────────┤
│ BULLETIN BOARD drawer (slate): # · kind · detail · leaf hash → click opens JSON / hex │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

The phase rail is a real sequence, so it's numbered. Under 900 px the columns
stack in this order: stage, workbench, printer. The printer then scrolls
horizontally.

## Signature: the printer

Every artifact a polling place would print comes out of the printer column as
a thermal strip: zerésima, slip (comprovante), spoil receipt, pre-BU, final BU,
and the signed result.
- Size and type: 280 px wide, `--paper`, Martian Mono 11 px.
- Edges: zig-zag torn top and bottom (CSS mask), dashed rules between blocks.
- QR: a QR code (qrcode-generator) of the record's code or RecordId.
- Header: machine, section and session, in the style of a real BU.
- Hashes: printed in groups of four.
- Motion: a new strip feeds down out of a slot at the top (clip and translate,
  450 ms, ease-out). There is no animation under `prefers-reduced-motion`.

That is the one bold element. Everything else stays quiet.

## The urna

A beige body. The screen on the left (`--lcd`) uses Martian Mono. The keypad is
on the right: digits 1–9 then 0 in black keys with white numerals, and below
them BRANCO (white), CORRIGE (orange) and CONFIRMA (green), as on the real
machine.

Flow per contest:
- The screen shows the contest name in caps, then "Número:" and digit boxes
  sized to the candidates' number length.
- Typing a valid number shows the name and party.
- An unknown number shows "NÚMERO ERRADO" and, on CONFIRMA, records null.
- In proportional contests, the two digits of a party record the party vote
  (legenda).
- BRANCO records blank.
- Multi contests (Senador, L = 2): confirm each candidate. CONFIRMA on an empty
  number ends the contest early.
- Linked contests (1º and 2º Senador): a candidate chosen in the first is
  marked as already chosen in the second. Choosing it again warns that the vote
  will be null.
- Mixnet contests (Prefeito): same flow as a single contest. A small tag says
  "counted by mixnet".

After the last contest the screen shows the tracking code large, then:
"CONFIRMA = cast" and "CORRIGE = audit this ballot (spoil)". A note says this
step doesn't exist on today's urna.

## Copy

English, with the Brazilian terms kept: zerésima, BU, mesário (poll worker),
fiscal (observer). Sentence case. Buttons name what they do:
- Run key ceremony
- Open polls
- Open session
- Authorize voter
- Close session
- Close polls
- Run tally
- Sign tree head
- Run verifier
- Look up my code

Errors say what happened and what to do next.
