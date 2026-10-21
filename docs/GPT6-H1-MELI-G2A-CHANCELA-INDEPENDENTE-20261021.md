# MITR3 — GPT QA independente | Chancela G2A H1-MELI Onda 10

Data: 2026-10-21 · Hipótese: H-ORDER10.1 · Programa: HackerOne #33462 · Maestro: VANTA / Antigravity  
Natureza: verificação local no Arch, **sem tráfego contra Mercado Livre**.

## Parecer formal

| Subportão | Decisão | Alcance |
|---|---|---|
| G2A-STRUCTURAL | **PASS** | C1/C2/X1 homologados como templates HTTP raw com placeholders apenas |
| G2A-SIMULATED-HARNESS | **PASS (23/23)** | Motor de sessões A/C/B aprovado em fixtures sintéticas e sem rede |
| G2A-PRETRAFFIC OPERACIONAL | **CONDITIONAL_ALLOW — EXECUTION_HELD** | Preparação offline aprovada, ainda SEM liberação de sondas ao alvo |
| G2B-POSTCHECK (Constituição V10) | **NOT_STARTED** | Nenhuma evidência primária da Onda 10 foi analisada |

### Provas reproduzidas nesta auditoria

- Linter estrutural existente: **PASS_STRUCTURAL_ONLY**, zero errors, zero warnings, zero network calls.
- 14/14 testes do staging_gate: PASS.
- 23/23 testes do mitr3-threesession: PASS, exit 0, com bwrap no-network.
- 23/23 testes também PASS em bwrap endurecido com namespaces network/pid/ipc, home pessoal mascarado, workspace em bind read-only.
- 3/3 arquivos .req: GET /orders/$ORDER_ID HTTP/1.1, exatamente seis CRLF cada, terminador CRLF CRLF, somente quatro headers, Host e UA iguais, Authorization com placeholder A/C/B segregado e mesmo order ID.
- Nenhum dos oito inputs mudou durante a segunda reexecução.
- Git diff --check padrão sinaliza os CR como whitespace em arquivos raw intencionalmente CRLF. Git com core.whitespace=cr-at-eol diff --check: PASS. Não transformar templates raw em LF apenas para obter PASS convencional.

### Hashes atuais

| Arquivo | SHA-256 |
|---|---|
| bin/mitr3-threesession.py | 9b848364cbd21255a7806805b07f03c79a704f14a5434f1da38ce138ab90cd4c |
| tests/test_threesession.py | 1576a7886d4752151c11a7abca5fb7a19d1c9a31633c2238f43dcf7de4a5174a |
| engagements/burp_lane/h1_meli_onda10/README.md | 31ba37348b4a982e938f9beaffab7da5a812b8508c4188e54eaf21ae3670f9a5 |
| engagements/burp_lane/h1_meli_onda10/templates/C1_comprador-A-le-pedido.req | 2aadaee593c9c0b46ccd8b955c80fd8451036403e6adcdf482e2286d56bc3586 |
| engagements/burp_lane/h1_meli_onda10/templates/C2_vendedor-C-le-venda.req | 893b2f82620cd573cdcd77e958bd4379fb3701f004284464a6ad1ccab45b6e6d |
| engagements/burp_lane/h1_meli_onda10/templates/X1_terceiro-B-le-pedido-de-A.req | b6044998b42ea624f89de00985ed30172ad267dc2610f63f96d5eb4f89368537 |

Manifesto complementar, sem credenciais: reviews/gpt6/h1_meli_onda10/reports/gate2a-independent-latest.json (0600). Script reproduzível: reviews/gpt6/h1_meli_onda10/attest_gate2a.py.

### Ressalva de rastreabilidade

Os hashes do código e testes coincidem com reviews/codex/harness-threesession-20261021T202444Z/inputs.sha256.json. **Quatro dos oito inputs divergem** do manifesto original do Codex (README e três templates), porque o VANTA corrigiu os arquivos após aquela execução. O relatório Codex preserva a prova da versão anterior; **não constitui selo da versão corrigida**. Regerar manifesto/release com os hashes acima e um commit revisado. Hash SHA-256 não é assinatura digital.

### Pendências para autorização operacional

1. Rota GET /orders/{id} ainda é hipótese de template: comprovar rota real observada legitimamente na UI/API do comprador A e confirmar escopo vigente. Se rota de vendedor C for diferente, atualizar SPEC antes de mudar C2 ou sondar.
2. O harness usa pedidos, vendedor e tokens **sintéticos**, transport injetado (sem cliente HTTP). Não comprova order_id real, sessão C válida, buyer=A, seller=C, B não participante, nem BOLA no servidor.
3. Orçamento de tráfego: README agora separa três GET manuais, mas não explicita teto global de **10 requests para toda Onda 10**; três verificações /users/me no mock já levam o fluxo de seis requests, sem contar criação C, anúncio, pagamento de teste, browser e redirects. Exigir ledger completo e reserva de margem antes de tráfego; se o plano não couber, voltar à SPEC.
4. Acesso do emissor: o contrato anterior previa OpenCode como único executor de tráfego. VANTA deve documentar mudança formal de atribuição antes de qualquer operação real; não transferir tokens para QA, chat ou LLM.
5. Scope HackerOne e policy sem drift devem ser rechecados just-in-time com Gate 1, JEV e autorização por conta/host/método; usar somente test users e pagamentos de teste. Stop-check fail-closed permanece obrigatório.
6. README ainda usa md5sum de arquivos completos para alegar User-Agent igual, embora isso não teste igualdade de UA. Corrigir instrução: extrair/comparar diretamente esse header; usar SHA-256 para integridade. Não é falha do parser, mas é dívida do handoff.
7. Wrapper Codex original usava bwrap --ro-bind / /: isola rede, não oculta credenciais do host que o UID pode acessar. O QA independente comprovou 23 PASS com /home/nielz mascarado e workspace reexposto read-only. Preferir esta variante.

### Handoff

- **VANTA:** aceitar PASS estrutural, manter execução suspensa até resolver as seis condições operacionais; reconciliar G2A Pré-Tráfego com G2B Pós-Sonda no plano constitucional.
- **Codex:** atualizar manifesto SHA de README e três templates; revisar commit; preservar harness sem transporte real.
- **DeepSeek:** esclarecer README quanto ao orçamento global e comparar UA corretamente, sem alterar CRLF homologado.
- **GPT QA + JEV:** fazer nova validação independente do pacote FINAL e escopo just-in-time antes de qualquer decisão de envio ao alvo.

**Chancela: G2A-STRUCTURAL = PASS | G2A-OPERATIONAL = CONDITIONAL_ALLOW / EXECUTION_HELD | G2B = NOT_STARTED.**

Este parecer não autoriza tráfego real nem constitui confirmação de vulnerabilidade.
