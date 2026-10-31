# eg/v1 — urna verificável de ponta a ponta

Proposta de protocolo para a urna eletrônica brasileira em que cada eleitor pode
conferir que o seu voto foi contado como depositado, e qualquer pessoa pode
conferir a apuração, sem que o voto deixe de ser secreto.

- Site explicativo: <https://urna-a-prova.pages.dev/>
- Especificação: [`SPEC.md`](SPEC.md) (rascunho 0.4)
- Questões em aberto: [`docs/spec-issues.md`](docs/spec-issues.md)

Este projeto não é um ataque à urna eletrônica nem à Justiça Eleitoral. É uma
proposta de alterações para que o eleitor possa verificar por conta própria.

## Estrutura

- `crates/eg-core` — implementação de referência do protocolo (Rust)
- `crates/eg-verify` — verificador público
- `crates/eg-wasm` — ligação WebAssembly usada pelo site
- `web/` — site (Início, Técnico, Tente você mesmo)
- `test-vectors/` — vetores de teste

## Licença

O código está disponível sob [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE),
à sua escolha.

A especificação (`SPEC.md`), a documentação em `docs/` e os textos do site
estão sob [CC BY 4.0](LICENSE-CC-BY-4.0).
