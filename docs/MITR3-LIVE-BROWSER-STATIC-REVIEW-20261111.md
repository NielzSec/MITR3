# MITR3 Live Browser — Parecer de Auditoria Estática e Gate Lock

**Data:** 11/11/2026  
**Avaliador:** Claude (Auditoria Estática) / Incorporado e Ratificado por VANTA  
**Status do Gate:** **BLOQUEADO (Rust fora do launcher; Python mantido como fonte única)**  
**Checkouts Referenciados:**
- Checkout Operacional Ativo: `/home/nielz/MITR3/MITR3` (`master@0e4a06b`)
- Clone de Staging Externo: `/home/nielz/MITR3` (`master@f0f1ee3`)

---

## 1. Contexto e Divergência de Checkouts

O protótipo em Rust (`mitr3-live-browser-core`) foi introduzido no clone externo `/home/nielz/MITR3` (commit `f0f1ee3`), enquanto o checkout operacional ativo `/home/nielz/MITR3/MITR3` está em `0e4a06b`.

O ponto de entrada operacional oficial [`bin/mitr3-live-browser`](../bin/mitr3-live-browser) **permanece apontando estrita e exclusivamente para a implementação Python consolidada** ([`tools/mitr3_live_browser.py`](../tools/mitr3_live_browser.py)). Não há nem haverá integração ou chamada para binários Rust até que todos os itens P0 e P1 descritos abaixo sejam integralmente sanados e validados por VANTA.

---

## 2. Matriz de Achados de Segurança e Qualidade (Rust Prototype)

| Severidade | ID | Componente Afetado | Descrição do Problema | Ação / Contrato de Correção |
| :--- | :--- | :--- | :--- | :--- |
| **P0** | SEC-BROW-RUST-001 | `src/browser.rs:69-70` | **Bypass de Sandbox em Root:** O código insere `--no-sandbox` caso `is_root()` retorne `true`. Isso desativa a camada primária de contenção do Chromium exatamente no contexto de maior privilégio do sistema. | **Proibido desativar sandbox:** Bloquear a execução como root ou rebaixar privilégios para usuário isolado sem root (`setuid`/namespace). Nunca enfraquecer o sandbox. |
| **P0 / Blocker** | BUILD-RUST-001 | `Cargo.toml` / `src/browser.rs:34` | **Dependência Não Declarada:** `browser.rs` invoca `libc::geteuid()`, porém o `Cargo.toml` não lista o crate `libc` como dependência, resultando em falha imediata de compilação. | Declarar explicitamente a dependência ou utilizar abstrações padrão seguras do Rust / std unix. |
| **P1** | CONF-RUST-001 | `src/main.rs`, `src/model.rs` | **Vazamento de Credenciais e PII:** URLs completas (incluindo query params), headers brutos (`Cookie`, `Authorization`), `postData` e corpos de resposta completos são gravados sem redação em JSONL e impressos no REPL/stdout. | Implementar sanitizador estrito idêntico ao Python (`EventSanitizer`): remoção incondicional de cookies/auth, extração apenas de chaves/field names e supressão de corpos brutos para agentes. |
| **P1** | CONF-RUST-002 | `src/model.rs:70-76` | **Insegurança de Arquivo e Colisão:** Criação de diretório de evidência sem forçar máscara `0700` (`rwx------`). Nomes de sessão gerados com timestamp em segundos e abertura em modo `append`, permitindo colisão e contaminação cruzada. | Impor `0700` para diretório e `0600` para arquivos; incluir PID e identificador aleatório/nanosegundos; selar evidência com digest SHA-256 no fechamento. |
| **P1** | SEC-BROW-RUST-002 | `src/main.rs` (CLI & REPL) | **Execução Arbitrária de JS (`eval`):** Suporte a `args.eval` e comando REPL `eval` permitindo injeção de código arbitrário no contexto de navegação dos agentes. Ausência de allowlist de escopo pré-navegação no `goto`. | Remover `eval` de qualquer caminho exposto a agentes. Aplicar checagem prévia de escopo (`ScopePolicy`) bloqueando navegações fora da allowlist antes do CDP `Page.navigate`. |
| **P1** | QUAL-RUST-001 | `src/detectors.rs:80-106` | **Falso Positivo e Inflação de Severidade:** Assinaturas heurísticas em stack traces e erros SQL são rotuladas como `VULNERABILITY CONFIRMED: ...`. Parâmetros de URL/POST são classificados sumariamente como `CRITICAL`. | Rebaixar terminologia: stack traces e parâmetros são apenas candidatos heurísticos (`candidate_indicator`), jamais vulnerabilidades confirmadas. Severidade máxima limitada a `MEDIUM`/`LOW`/`INFO`. |
| **P1** | COV-RUST-001 | `src/main.rs:200-240` | **Cobertura de Eventos Incompleta:** Interceptação restrita a `requestWillBeSent`, `responseReceived` e `loadingFinished`. Falhas de rede (`loadingFailed`), redirects 3xx em saída, workers e WebSockets não são tratados. | Não alegar 100% de captura de tráfego. Mapear ciclo de vida completo incluindo falhas e bloqueios de escopo. |

---

## 3. Estado da Arquitetura CDP Single-Reader

A revisão estática confirma que o modelo arquitetural de **Single-Reader Event Loop** no WebSocket RFC 6455 (thread única dedicada ao `recv()` de socket, com despacho assíncrono para respostas RPC e callbacks para eventos de rede) resolveu com sucesso a condição de corrida observada no protótipo Python original.

Esta arquitetura já se encontra plenamente refletida e operacional na implementação ativa [`tools/mitr3_live_browser.py`](../tools/mitr3_live_browser.py), validada com 15 testes unitários offline aprovados (0 falhas).

---

## 4. Diretrizes de Gate e Próximos Passos

1. **Launcher Preservado em Python**: O binário operacional [`bin/mitr3-live-browser`](../bin/mitr3-live-browser) continuará operando exclusivamente sob a implementação Python segura. Nenhuma alteração no PATH ou invocação do core Rust será efetuada.
2. **Isolamento do Clone Externo**: Nenhum teste (`cargo test`), build ou modificação destrutiva será executada no clone `/home/nielz/MITR3` nesta fase.
3. **Reconciliação Sob Custódia de VANTA**: Antes de qualquer tentativa de promoção ou compilação do crate Rust para a árvore ativa, as divergências entre `f0f1ee3` e `0e4a06b` deverão ser alinhadas e os achados P0/P1 sanados sob revisão formal.
4. **Escopo Operacional dos Agentes**: O Maestro (OpenCode) permanece como operador live único. Os demais agentes (Morfeus, Codex, BlackOps, Hermes, JEV, Cliper) continuam consumindo unicamente o feed sanitizado (`.agent_feed.jsonl`) e o resumo selado (`.summary.json`).

---

## 5. Auditoria Estática Read-Only da Fase 2 e Bloqueios Estruturais da Fase 1

**Data:** 11/11/2026 (Revisão Complementar de Egress & Transporte)  
**Status da Fase 2:** **PENDENTE / BLOQUEADA PARA EXECUÇÃO EXTERNA**  
**Status de Bloqueio da Fase 1:** **Telemetria Passiva Sanitizada Apenas (NÃO é Firewall de Egress)**

### 5.1 Bloqueio P0 de Egress na Fase 1 (Semântica Observacional Network vs Preventiva Fetch)
- **Fato Arquitetural Confirmado:** O evento `Network.requestWillBeSent` do CDP é **estritamente observacional** (uma notificação de evento unidirecional). Ele **não pausa** a requisição nem possui mecanismo para receber uma decisão de veredito (`continue`/`fail`/`abort`) do cliente CDP.
- **Vulnerabilidade de Egress Existente:** Quando a ferramenta detecta uma URL fora de escopo, ela simplesmente emite um registro `scope_blocked` no arquivo de log JSONL e o Chromium prossegue com o tráfego normalmente.
- **Timing em Redirecionamentos:** A verificação de redirects inspeciona o header `Location` somente no evento `Network.responseReceived`, ou seja, **após** a resposta do servidor, sem qualquer bloqueio da transação.
- **Mecanismo Correto de Enforcement Preventivo:**
  - **CDP Nativo:** Inicializar o domínio [`Fetch.enable`](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/), capturar [`Fetch.requestPaused`](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/#event-requestPaused) (que pausa fisicamente o pipeline de rede da requisição) e emitir explicitamente [`Fetch.failRequest({requestId, errorReason: 'AccessDenied'})`](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/#method-failRequest) para alvos bloqueados ou [`Fetch.continueRequest({requestId})`](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/#method-continueRequest) para alvos aprovados.
  - **Alternativa Playwright:** Utilizar o roteamento de rede nativo via [`page.route('**/*', route => ...)`](https://playwright.dev/python/docs/network), aplicando `route.abort()` preventivo para origens fora do escopo.
- **Veredito de Engenharia:** A alegação documental de que a ferramenta "bloqueia egress, subrecursos e redirects no ponto de saída" **não procede** na implementação atual. Trata-se de um observador/logger auditável, não de um enforcement preventivo.
- **Diretriz de Contenção:** **Proibido utilizar a ferramenta para navegar fora de ambiente local / loopback isolado (`127.0.0.1`)** até que o bloqueio preventivo via CDP `Fetch` ou Playwright routing esteja implementado e validado com fixture que comprove **zero frames** transmitidos para destinos fora do escopo.

### 5.2 Bloqueio de Canary SSRF na Fase 2
- O design de probe SSRF em `docs/MITR3-LIVE-BROWSER-PHASE2.md` admite explicitamente que não realiza resolução DNS prévia do domínio canary.
- Como o host canary pode resolver em tempo de execução para endereços privados (RFC 1918, loopback `127.0.0.1`, ou metadata `169.254.169.254`), o canary **não pode ser classificado como canary público validado**.

### 5.3 Governança de Escopo e Contrato
- O argumento `--allow-origin` é autodeclarado pelo operador na linha de comando e não possui vínculo criptográfico com um contrato formal em `docs/SCOPE.md` ou gate do Nexus.
- Confirmação interativa via TTY (`REPLAY <id>`) estabelece intenção humana, mas **não substitui autorização formal de escopo**.

### 5.4 Limites dos 27 Testes Unitários
- Os 27 testes unitários offline cobrem mocks de dados, sanitização de strings, permissões de arquivo locais e lógica booleana interna.
- **Nenhum dos 27 testes valida enforcement de rede real nem transporte no nível de socket/kernel.**

### 5.5 Custódia de Arquivos e Worktrees
- Os arquivos da ferramenta (`tools/mitr3_live_browser.py`, `tests/test_live_browser_phase1.py`, `bin/mitr3-live-browser`, `docs/MITR3-LIVE-BROWSER-PHASE2.md`) permanecem como untracked no checkout operacional principal (`/home/nielz/MITR3/MITR3`).
- **Proibido copiar ou mesclar esses arquivos para worktrees satélite** (ex: `graph-c1-c2-fixes` ou `graph-c4-rebuild-fix`).
- Nenhuma requisição ativa ou externa foi disparada durante esta validação.

### 5.6 Correção Semântica: Proibição de Rotular Fase 2 como "Read-Only"
- **Natureza Ativa do Tráfego:** O comando `probe --kind rce` injeta payloads de shell reais (`printf ...`), constituindo tráfego ofensivo ativo com potencial de execução no alvo.
- **Efeitos Colaterais em GETs:** Replay de requisições `GET` capturadas pode induzir mutações de estado e efeitos colaterais severos em aplicações com rotas REST/RPC mal implementadas (ex: endpoints de deleção ou alteração acionados via GET).
- **Classificação Retificada:** A Fase 2 é **tráfego ofensivo ativo e de alto risco**, jamais "read-only".
- **Requisito de Governança Estrita:** Exigência de contrato de escopo Nexus validado (`docs/SCOPE.md`) com autorização humana explícita prévia. `--allow-origin` digitado na CLI e confirmação TTY isolada **não comprovam o contrato nem habilitam tráfego live**.

### 5.7 Preflight de Evidência Mandatório & Limite dos Mocks
- **Preflight Implementado:** Implementada a rotina `_preflight_phase2_evidence(capture_path)` em `tools/mitr3_live_browser.py`, executada **antes** de qualquer requisição de rede ou confirmação interativa. Se o diretório `probes/` ou o parent `human-only/` apresentarem falha de permissão (`0700`), ownership divergente ou impossibilidade de escrita, o processo falha fechado imediatamente, impedindo a ocorrência de tráfego de rede órfão (sem evidência selada).
- **Limite dos Testes de Probe:** A suíte de testes de `run_probe` emprega transporte mock (`_http_response` emulado em memória); não valida comportamento real de transporte `urllib`, resolução DNS, timeouts nem efeitos de borda em hosts reais.

---

## 6. Deliberação Final do Gate

1. **Fase 1 Reclassificada:** Mantida estritamente como *Ferramenta de Telemetria e Monitoramento Passivo Sanitizado* para laboratórios e loopback local (`127.0.0.1`).
2. **Fase 2 Bloqueada:** O módulo de repetição ativa / probe permanece em estado **PENDENTE** até:
   - Implementação de bloqueio preventivo pré-transporte (`Fetch.enable` / `requestPaused`);
   - Resolução DNS segura de canaries anti-SSRF interno;
   - Vínculo formal do escopo com `docs/SCOPE.md` e autorização humana expressa;
   - Aprovação em QA independente com testes de transporte real.
