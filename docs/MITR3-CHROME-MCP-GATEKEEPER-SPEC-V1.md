# MITR3 — SEC-BROW-001 v1.0
## Especificação formal: Gatekeeper de Navegação — Chrome DevTools MCP Guarded

**Data:** 2026-10-21 · **Status:** ESPECIFICAÇÃO / NÃO IMPLEMENTADA · **Maestro interino:** VANTA / Antigravity · **Build:** Codex · **QA:** GPT-6

**Propósito:** limitar a automação de navegador aos alvos expressamente homologados de cada investigação e impedir vazamento de sessão, segredos, artefatos e requisições para origens não autorizadas. A autorização do usuário para construir o laboratório não implica que sites de terceiros estejam em escopo.

### 1. Baseline verificado no host Arch

- OpenCode usa Chrome DevTools MCP 1.11.0 com --isolated, --no-usage-statistics, --no-performance-crux e --executablePath /usr/bin/brave.
- Browser atual: Brave 155.1.97.59. O projeto upstream declara suporte oficial a Chrome e Chrome for Testing, não a Brave; testes de compatibilidade no Brave são obrigatórios antes de usar proteção baseada em feature Chrome.
- A versão MCP instalada possui --allowed-url-pattern (aplica allowlist em navegação, redirects e subrecursos segundo a documentação do pacote; requer Chrome 149+), --no-javascript-evaluation, --no-file-navigations e --redact-network-headers.
- O próprio pacote alerta: --no-javascript-evaluation NÃO desativa scripts da página, cliques ou DevTools experimental; --no-file-navigations NÃO substitui isolamento de filesystem; --redact-network-headers mascara ALGUNS headers, não conteúdo integral.
- Processos Brave com portas de depuração estão ativos no host. Esta é uma rota potencial de bypass caso outros processos tenham acesso ao CDP fora do gateway; não alterar os processos atuais sem coordenação do maestro.
- O Chrome MCP disponibiliza ferramentas como new_page, navigate_page, list_pages, take_snapshot, take_screenshot, evaluate_script, list_network_requests, get_network_request, click, fill, upload_file. Restrição somente pelo parâmetro URL de navegação NÃO é suficiente.
- Esta especificação não habilita alterações de configuração, reinícios ou tráfego externo. Nenhum alvo de terceiro consta pré-autorizado.

### 2. Modelo de arquitetura e confiança

Agente com identidade/role -> MCP Guarded (authn/authz por caso, validação de argumentos, quotas, audit) -> Chrome DevTools MCP pinado -> Browser descartável com CDP privado via pipe -> network namespace/UID segregado -> ÚNICA rota pelo proxy de egress/DNS com allowlist positiva -> ORIGEM HOMOLOGADA.

**São dois mecanismos mandatórios e independentes:** (A) filtro RPC de ferramentas e argumentos e (B) filtro de rede na saída efetiva do processo do navegador. Nenhum permite fallback para acesso irrestrito. Scripts de páginas, service workers, imagens CSS, fetch, sendBeacon, iframes, popups, forms, redirects HTTP/meta/JS e WebSockets também são considerados tráfego do navegador.

**Manifesto de escopo obrigatório:** case_id, agent_id/role, operador, aprovador, instante e prazo de expiração, versão/hash da policy, origens HTTPS exatas (esquema, host IDNA, porta), paths e métodos permitidos, hosts de subrecursos com justificativa, política DNS/IP IPv4+IPv6, contas sintéticas, quotas de tempo/requests/bytes/abas, retenção, classificação de dados. Sem case ativo, todas as ferramentas de navegação NEGADAS. O manifesto é imutável durante a sessão e validado por componente fora do browser.

**Validação de URL:** parse/canonicalize antes da comparação; proibir userinfo, scheme não previsto, hostname com confusão de sufixo, trailing-dot bypass, IDNA ambíguo, IP numérico hexadecimal/decimal, IPv4-mapped IPv6, CNAME/rebinding, redirects e resolução alternativa. Filtro network deve verificar destino final por conexão e egress proxy controlar DNS/SNI/TLS. Localhost, RFC1918, link-local e metadata cloud NEGADOS, exceto fixtures de loopback aprovadas dentro de namespace de laboratório isolado. Não permitir CDP por websocket compartilhado.

### 3. Matriz de riscos

| ID | Vetor | Prob. | Impacto | Risco antes do gate | Evidência exigida |
|---|---|---|---|---|---|
| BR-01 | URL fora de escopo, redirects 30x/meta/JS, subdomínio sósia | Alta | Alto | CRÍTICO | Redirects sintéticos tentam sair do escopo; zero conexões proibidas |
| BR-02 | Exfiltração via fetch, WebSocket, CSS, iframe, sendBeacon e SW | Alta | Crítico | CRÍTICO | Coletores locais registram zero egress não aprovado de todas as classes |
| BR-03 | Sessão/cookies pessoais por perfil compartilhado e CDP exposto | Alta | Crítico | CRÍTICO | Não acessar perfil pessoal; CDP privado pipe/namespace e bloqueio de attach externo |
| BR-04 | SSRF, DNS rebinding, RFC1918/localhost, IPv6, cloud metadata | Média | Crítico | CRÍTICO | Proxy DNS/IP rejeita resolução e requisições fora do escopo mesmo após redirect |
| BR-05 | evaluate_script, click, fill, upload_file, DevTools UI, métodos imprevistos | Alta | Alto | ALTO | tools/list filtrado e tools/call de ação não permitida recebe DENY sem execução |
| BR-06 | Cookie/JWT/API key em DOM, logs, network body, console, screenshot, HAR | Alta | Alto | ALTO | Sentinelas fictícias não aparecem em saídas nem logs |
| BR-07 | Bypass via --browserUrl, --wsEndpoint, --autoConnect, --userDataDir, CDP direto | Média | Crítico | CRÍTICO | Cliente/UID externo não conecta CDP e configuração não aceita tais argumentos |
| BR-08 | Escrita não autorizada via POST/form/click/download/upload | Média | Alto | ALTO | Requests de mutação e download/upload não aprovados são negados no egress |
| BR-09 | Prompt injection dentro de página/DOM/snapshot | Alta | Alto | ALTO | Página hostil própria não consegue mudar escopo, roles ou allowlist |
| BR-10 | Falha de audit, proxy, DNS ou rate-limit levando a fallback | Média | Crítico | CRÍTICO | Falhas injetadas desligam navegação e impedem bypass |

Estimativas qualitativas para priorização, não números medidos. Nenhum risco pode ser declarado mitigado antes de teste adversarial no plano de dados e evidência.

### 4. As CINCO REGRAS INEGOCIÁVEIS

**R1 — ORIGEM EXATA E EGRESS DENY-BY-DEFAULT.** Nenhuma conexão do browser a destino não homologado, inclusive subrecursos, redirects, JS, frames, WebSockets e service workers. O controle obrigatório fica também fora do browser: namespace sem rede direta e proxy egress com política positiva por destino, porta, método, IP/DNS. Revalidar após cada redirect e resolução. --allowed-url-pattern é defesa em profundidade, não substituto da contenção de rede. Sem policy válida: sem rede.

**R2 — SESSÃO DESCARTÁVEL E CDP PRIVADO.** Uma identidade, um case, um navegador novo e perfil temporário 0700; nunca importar cookies, tokens, extensões, downloads ou storage do Brave pessoal. CDP apenas pipe privado; proibir --browserUrl, --wsEndpoint, --autoConnect, --userDataDir, --no-sandbox, ignore-certificate-errors e TLS inseguro. UID/processos segregados, mounts mínimos, sem acesso aos perfis externos. Destruição do perfil e término da árvore de processos ao expirar ou falhar.

**R3 — GATE RPC POR CAPACIDADE, TOOL E ARGUMENTO.** tools/list filtrado; tools/call, requests, notifications e parâmetros não autorizados negados ANTES de encaminhar. Etapa inicial permite condicionalmente apenas list_pages, select_page, new_page, navigate_page, take_snapshot, take_screenshot; estes exigem identidade/case, destino autorizado e redaction. Por padrão negar evaluate_script, click, click_at, type_text, fill, fill_form, press_key, upload_file, drag, get_network_request, traces, extensions, Console, DevTools experimental e qualquer ferramenta nova. Back/forward/reload e novas abas precisam passar pela mesma validação. Ampliação exige autorização nova por ação.

**R4 — ZERO VAZAMENTO DE SESSÃO OU DADOS SENSÍVEIS.** Antes de devolver conteúdo a qualquer agente ou persistir evidência, mascarar ou negar cookies, Authorization, Set-Cookie, JWT, tokens CSRF/refresh, valores de forms, querystrings sensíveis, segredos em DOM, network/console/HAR/screenshot. Em caso de redaction insuficiente, bloquear resposta e marcar INCONCLUSIVE; nunca transmitir perfil, headers brutos, credenciais ou conteúdo sensível ao MegaBrain/chat/log. Canary sintético precisa provar ausência de vazamento. Nunca enviar credenciais a destino fora do allowlist.

**R5 — AUDIT, QUOTAS E FAIL-CLOSED COMPROVADOS.** Cada decisão registra case_id, policy hash, agente, tool, destino canônico sem query, allow/deny, reason, timestamp e contadores; nunca payload/cookies. Logs privados 0600 append-only com fsync e integridade encadeada/WORM, backup e retenção. Limites estritos por requests, bytes, abas e duração. Crash/proxy offline/audit indisponível/TTL vencido/DNS-TLS inesperado/quota excedida -> DENY e encerramento da sessão, sem fallback. Estado sem evidência = BLOCKED, não PASS.

### 5. Política inicial de ferramentas

- CONDICIONAL: list_pages/select_page (somente páginas do caso), new_page/navigate_page (destinos exatos e tráfego restrito), take_snapshot/take_screenshot (somente após filtragem testada).
- NEGADO: evaluate_script, upload_file, fill, type_text, click, press_key, get_network_request, list_network_requests, console, tracing, extension tools, emulation, experimental DevTools e todo nome desconhecido.
- PROIBIDO: navegar em browser pessoal, usar perfil existente, baixar para a pasta pessoal, preencher senhas reais ou reutilizar sessões de terceiros.

### 6. Testes de aceite T01–T18 — exclusivamente fixtures sintéticas

T01 URL fora do escopo; T02 redirects 301/302/307 cross-origin; T03 fetch/WebSocket/beacon/CSS/iframe para origem proibida; T04 popup e form; T05 userinfo, IDNA, trailing dot e host sósia; T06 IPv4 decimal/hex, IPv6 e v4-mapped; T07 DNS rebinding para endereço privado/metadados; T08 javascript/data/file/view-source/chrome/blob; T09 service worker; T10 JS evaluation/upload/network request raw/tool desconhecida; T11 cookie/API key fictícia em DOM/header/query/screenshot; T12 clique/POST fora da policy; T13 queda do proxy e DNS; T14 indisponibilidade de audit; T15 attach ao CDP e profile externo; T16 TTL/policy expirada; T17 limites de bytes/tempo/páginas; T18 conteúdo web com instruções para alterar políticas. Todos devem negar o vetor sem nenhum pacote de saída não autorizado. Repetir regressão após update do Chrome MCP/browser.

### 7. Gate formal de homologação

G0 — Fontes pinadas, manifest de escopo aprovado, browser suportado/compatibilidade comprovada e inventário de clientes/config sem segredos.
G1 — Browser em UID/namespace separado, CDP privado, profile descartável, sem montagem de perfis pessoais.
G2 — Testes T01–T09 comprovam zero egress fora da allowlist, medido no plano de dados (não somente pelo JSON-RPC).
G3 — Testes T10–T12 comprovam denials e nenhuma exposição de canaries em respostas/logs.
G4 — Testes T13–T18 comprovam fail-closed, quotas, anti-bypass e isolamento.
G5 — Deploy sob nome NOVO chrome-devtools-guarded-lab em cliente de laboratório, mantendo sessões existentes; depois migração aprovada de cada agente, com rollback e ACK dos responsáveis.

**CRITÉRIO PASS:** zero bypass, todas as negativas PASS, caso sintético permitido funciona e auditoria íntegra. Qualquer ausência de evidência ou bypass -> BLOCKED/INCONCLUSIVE. A existência de chrome-devtools MCP direto em cliente com acesso ao mesmo browser impede reivindicar enforcement global.

### 8. Coordenação e ownership

VANTA/Antigravity, maestro interino: aprova origens, organiza execução, gates e migração; decide GO/NO-GO.
Codex, Build/QA: proxy MCP com autenticação por agente, egress proxy/UID/namespace, teste sintético T01–T18, rollback atômico.
GPT-6, QA independente: revisa autenticação, evidências negativas de rede, contenção de sessão, redaction e falsos positivos; emite relatório independente.
Hermes/MegaBrain: indexa só política aprovada e metadados curados, nunca logs de browser, capturas brutas, cookies, tokens ou HAR.
OpenCode: retoma coordenação após transferência formal do VANTA.

**SEM MODIFICAÇÃO PRODUTIVA NESTA ENTREGA.** A SPEC não é o proxy. Testes sintéticos e implantação lateral precedem qualquer remoção da entrada chrome-devtools existente.
