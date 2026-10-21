# Onda 10 — relatório offline para Maestro VANTA / OpenCode

Execução: 2026-10-21T20:24:44Z. **23 testes pytest PASS; exit 0.**
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
query de enumeração, token literal ou verbo de mutação. Templates preservados;
hashes antes/depois da execução idênticos, assim como os demais inputs.

**Ressalvas documentais concretas:**
- A síntese BOLA §§3.3/4 exige identidade/dado real e recomenda mutações. Isso
  conflita com SPEC v10 §§1/3/6: apenas test users, hipótese de leitura, sem
  cancelamento/reembolso/alteração. A síntese não amplia autorização; este
  harness segue a SPEC e não usa dados reais nem modela mutações.
- A rota dos templates é documental, não captura validada de C1. Identidade C,
  propriedade do pedido e observação da rota real permanecem pré-condições
  operacionais, não fatos comprovados por templates ou mocks.
- README contabiliza três requests de leitura, não a criação de C, anúncio,
  compra ou chamadas de browser previstas na SPEC. O teto de dez exige ledger
  da onda inteira. O harness faz seis chamadas falsas: três identidades e três
  leituras; não implementa nem autoriza uma onda live.
- `md5sum` dos arquivos completos não verifica igualdade de User-Agent. A suíte
  compara os cabeçalhos diretamente e a evidência usa SHA-256.

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

## SHA-256 dos inputs e resultados

- `9b848364cbd21255a7806805b07f03c79a704f14a5434f1da38ce138ab90cd4c` — `bin/mitr3-threesession.py`
- `1576a7886d4752151c11a7abca5fb7a19d1c9a31633c2238f43dcf7de4a5174a` — `tests/test_threesession.py`
- `437ede737cdeadc500f506b67cd8bdcc2d26c82dbd2613b83eb42fddc567e07c` — `docs/H1-MELI-SPEC-V10.md`
- `8a55537926df6ec460bf26fd64d1cff315b76c31b154df5959b13cef3005a1a2` — `docs/H1-MELI-BOLA-WRITEUP-SYNTHESIS.md`
- `e55dc6e3f13b1d558e4628b2a46546d280edd19a5276f0d0c394c681e6332929` — `engagements/burp_lane/h1_meli_onda10/README.md`
- `9d4b7c82d29fa638291ba2291d6ceb6f981bfd1bab24dd524b62216ca43bbffb` — `engagements/burp_lane/h1_meli_onda10/templates/C1_comprador-A-le-pedido.req`
- `cdbf41f8f911ede48eb0b406d1b2814b71ad08b159b8ac01a6e9f27680a16e65` — `engagements/burp_lane/h1_meli_onda10/templates/C2_vendedor-C-le-venda.req`
- `81346607a8431519ad8d9ac7bcaac5496b32c44ed7fd026166777d41ca68358e` — `engagements/burp_lane/h1_meli_onda10/templates/X1_terceiro-B-le-pedido-de-A.req`
- `ef37e60e1efa836518ff1ad7a53d5d9d5abf32360e3d7968b329e35d8dd5ea21` — `reviews/codex/harness-threesession-20261021T202444Z/command.json`
- `c4e829428d7b4008a59fde995012e1f2ec44911adb621225441de6c2ba99a153` — `reviews/codex/harness-threesession-20261021T202444Z/inputs-unchanged.json`
- `8ad242ee779bf5e8f9c06b3796208a8e5daf6acf946f000386ed91b7dfc34b67` — `reviews/codex/harness-threesession-20261021T202444Z/inputs.sha256.json`
- `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.exit`
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.stderr`
- `e4b428f2777fdbf2061645782ed92a07e97a893a40cbe0866158e2ee6f422af7` — `reviews/codex/harness-threesession-20261021T202444Z/pytest.stdout`
