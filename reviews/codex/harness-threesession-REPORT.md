# Onda 10 — relatório offline para Maestro VANTA / OpenCode

Execução original: 2026-10-21T20:24:44Z. **23 testes pytest PASS; exit 0.**
Python 3.14.8, pytest 9.1.1, pluggy 1.6.0. Pytest reutilizado de ambiente local
restaurado; nenhuma instalação/download. Autoload de plugins e cache desativados.
Processo pytest isolado com `bwrap --unshare-net`; socket e DNS também bloqueados
na suíte. **Zero tráfego MELI, zero credenciais reais, zero mutações remotas.**

## Auditoria C1/C2/X1

| Caso | Identidade | Resultado da auditoria local |
|---|---|---|
| C1 | A, comprador 3780339606 | PASS estrutural: GET /orders/$ORDER_ID, Bearer $AUTH_TOKEN_A |
| C2 | C, vendedor test user novo | PASS estrutural: mesma rota/objeto, Bearer $AUTH_TOKEN_C |
| X1 | B, terceiro 3780339608 | PASS estrutural: mesma rota/objeto, Bearer $AUTH_TOKEN_B |

Host, User-Agent e Accept são idênticos nos três templates; Authorization é a
única diferença. Cabeçalhos sem duplicação, corpo vazio, sem cookie/CSRF,
query de enumeração, token literal ou verbo de mutação. Templates atuais com CRLF
estrito, sem CR/LF isolado e terminados em CRLF CRLF. Inputs estáveis durante a
revalidação; código e suíte mantêm os hashes da execução original.

**Ressalvas documentais concretas:**
- A síntese BOLA §§3.3/4 exige identidade/dado real e recomenda mutações. Isso
  conflita com SPEC v10 §§1/3/6: apenas test users, hipótese de leitura, sem
  cancelamento/reembolso/alteração. A síntese não amplia autorização; este
  harness segue a SPEC e não usa dados reais nem modela mutações.
- A rota dos templates é documental, não captura validada de C1. Identidade C,
  propriedade do pedido e observação da rota real permanecem pré-condições
  operacionais, não fatos comprovados por templates ou mocks.
- Ressalva de orçamento resolvida no README atual: teto de dez requisições inclui
  setup de C, anúncio, checkout simulado e C1/C2/X1; taxa 60/host/h, serial. O
  harness faz seis chamadas falsas e não comprova consumo de orçamento live.
- README atual substituiu md5sum por SHA-256 e inspeção de User-Agent. A
  igualdade dos cabeçalhos continua verificada diretamente pela suíte.

## Máquina de estados exercitada

Não existia motor de três sessões. Adicionado `bin/mitr3-threesession.py`, núcleo
exclusivamente offline com transporte injetado obrigatório, origem `.example.test`,
C/order/tokens sintéticos, sem cliente HTTP, CLI live ou leitura de credenciais.
`tests/test_threesession.py` executa esse núcleo e audita os templates reais.

Fluxo: NEW → identidades A/C/B → C1 → C2 → X1 → DONE; falha → STOPPED.
Instância de uso único; sem retries, concorrência ou mudança de objeto.
A/B usam os IDs especificados como labels da fixture; C é `fixture-new-seller-c`,
não um ID real criado. Flags test_user/new_test_user são contrato da fixture,
não alegação sobre schema/proveniência de uma API real.

Discriminantes comprovados **em fixtures**:
- C1=200 e C2=200 exigem mesmo pedido, buyer A, seller C, dados privados e
  concordância dos campos compartilhados entre controles.
- X1=403/404 sem dado do pedido → NEGATIVE; corpo vazio também é aceito.
- X1=200 com ownership/objeto vinculados e campo privado igual ao controle →
  BOLA_CANDIDATE. Cada classe (itens, valor, status, endereço) tem teste.
- 403/404 vazando os mesmos campos privados também é candidato, nunca negativo.
- 200 genérico, ID refletido, pedido de B, dado sem vínculo ou corpo de negação
  desconhecido/aninhado → INCONCLUSIVE, nunca um achado por status apenas.
- Identidades trocadas, vendedor não novo, controles divergentes, WAF/captcha,
  indicação de cobrança, 429/5xx, redirect, JSON inválido/duplicado, payload
  excessivo ou falha do transporte interrompem a sequência sem retry.
- Saída só contém metadados e hashes; testes verificam ausência de tokens,
  identificadores e endereço/valor privado da fixture.

## Reprodução e evidência

Comando pytest: `python3 -m pytest tests/test_threesession.py -p no:cacheprovider`.
Wrapper de isolamento e ambiente exatos estão em
`harness-threesession-20261021T202444Z/command.json`.
Logs stdout/stderr, exit e manifesto de inputs ficam no mesmo diretório.

Limites: não demonstra BOLA real, privacidade contratual dos campos em produção,
validade de sessões, seller C existente, limites reais de taxa ou autorização de
execução. Gates QA/JEV e aceite do emissor único continuam separados.
Sem canal direto Maestri disponível nesta sessão; este arquivo é handoff local,
não confirmação de entrega/ACK remoto. Relatório apresentado ao Maestro no chat.

## SHA-256 dos inputs atuais e resultados originais

Manifesto atualizado para a revalidação. Os logs originais permanecem preservados;
os novos logs estão identificados na seção de resselagem.

- `9b848364cbd21255a7806805b07f03c79a704f14a5434f1da38ce138ab90cd4c` — `bin/mitr3-threesession.py`
- `1576a7886d4752151c11a7abca5fb7a19d1c9a31633c2238f43dcf7de4a5174a` — `tests/test_threesession.py`
- `437ede737cdeadc500f506b67cd8bdcc2d26c82dbd2613b83eb42fddc567e07c` — `docs/H1-MELI-SPEC-V10.md`
- `8a55537926df6ec460bf26fd64d1cff315b76c31b154df5959b13cef3005a1a2` — `docs/H1-MELI-BOLA-WRITEUP-SYNTHESIS.md`
- `018f0bf1068f1347da9e375264bc6cda958a5c96f5c0b5110737f7e173404abf` — `engagements/burp_lane/h1_meli_onda10/README.md`
- `2aadaee593c9c0b46ccd8b955c80fd8451036403e6adcdf482e2286d56bc3586` — `engagements/burp_lane/h1_meli_onda10/templates/C1_comprador-A-le-pedido.req`
- `893b2f82620cd573cdcd77e958bd4379fb3701f004284464a6ad1ccab45b6e6d` — `engagements/burp_lane/h1_meli_onda10/templates/C2_vendedor-C-le-venda.req`
- `b6044998b42ea624f89de00985ed30172ad267dc2610f63f96d5eb4f89368537` — `engagements/burp_lane/h1_meli_onda10/templates/X1_terceiro-B-le-pedido-de-A.req`
- `ef37e60e1efa836518ff1ad7a53d5d9d5abf32360e3d7968b329e35d8dd5ea21` — `reviews/codex/harness-threesession-20261021T202444Z/command.json`
- `c4e829428d7b4008a59fde995012e1f2ec44911adb621225441de6c2ba99a153` — `reviews/codex/harness-threesession-20261021T202444Z/inputs-unchanged.json`
- `8c5d331098c362ec45f7b5f17e23b05bd4c405a5718b52852df9f2e59249617a` — `reviews/codex/harness-threesession-20261021T202444Z/inputs.sha256.json`
- `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.exit`
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.stderr`
- `e4b428f2777fdbf2061645782ed92a07e97a893a40cbe0866158e2ee6f422af7` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.stdout`

## Resselo — 20261021T204242Z

**23/23 pytest PASS; exit 0**, sem rede (`bwrap --unshare-net`), com autoload de
plugins e cache desativados. Recalculados os quatro hashes solicitados dos bytes
atuais: README e C1/C2/X1. CRLF estrito confirmado nos requests; README em LF.
Código, suíte e templates não foram alterados por Codex nesta missão.
G2A_STRUCTURAL_PASS e staging_gate.py 14/14 foram informados pelo Maestro;
staging_gate.py não foi reexecutado nesta resselagem.

Um README concorrente mudou após a tentativa `reseal-20261021T204140Z`; a
checagem final bloqueou aquela atualização antes de gravar o manifesto/relatório.
Esta execução usa a revisão mais recente, com orçamento integral e SHA-256.

O manifesto `harness-threesession-20261021T202444Z/inputs.sha256.json` representa
os inputs atuais. Relatório, manifesto e selos anteriores estão preservados com
prefixo `previous-` em `harness-threesession-20261021T202444Z/reseal-20261021T204242Z/`.
Comando exato, stdout/stderr e exit da revalidação estão no mesmo diretório.
Gate estrutural não autoriza execução live; QA/JEV operacional permanece separado.

SHA-256 da revalidação:

- `ef37e60e1efa836518ff1ad7a53d5d9d5abf32360e3d7968b329e35d8dd5ea21` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/command.json`
- `c4e829428d7b4008a59fde995012e1f2ec44911adb621225441de6c2ba99a153` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/inputs-unchanged.json`
- `8c5d331098c362ec45f7b5f17e23b05bd4c405a5718b52852df9f2e59249617a` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/inputs.sha256.json`
- `79f9c4ed8b22057dba20931b818280d0e939806cb829d6f333cf28a7e49f27f1` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/previous-SHA256SUMS`
- `63c4cb631926f895456ea1d4f1383326fa51f3c0167b447d5ef0a8f0f3422e1f` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/previous-harness-threesession-REPORT.md`
- `591b5c89237c755e97d0b8fcd55347dc5fa6d7711f91c9355c3aae257af0e527` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/previous-harness-threesession-REPORT.md.sha256`
- `8ad242ee779bf5e8f9c06b3796208a8e5daf6acf946f000386ed91b7dfc34b67` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/previous-inputs.sha256.json`
- `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/pytest.exit`
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/pytest.stderr`
- `e4b428f2777fdbf2061645782ed92a07e97a893a40cbe0866158e2ee6f422af7` — `reviews/codex/harness-threesession-20261021T202444Z/reseal-20261021T204242Z/pytest.stdout`
