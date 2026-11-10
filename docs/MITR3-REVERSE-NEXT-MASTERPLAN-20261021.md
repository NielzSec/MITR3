# MITR3 — REVERSE NEXT: plano mestre de engenharia reversa (2026-10-21)

Status: APENAS PLANEJAMENTO E HANDOFF. Nenhum clone, instalador, atualização de MCP ou serviço deve ser executado automaticamente a partir deste documento.

## A. Objetivo e contexto verificado

Construir a capacidade MITR3 Reverse Next: uma linha reproduzível de análise estática, engenharia reversa, evidências de segurança e pesquisa assistida por agentes, com pesquisa e recuperação de conhecimento via MegaBrain MCP. Integrar as capacidades relevantes de REA + reverse-skill sem substituir ferramentas já funcionais.

Verificado na máquina archlinux em 2026-10-21:
- Acesso remoto online.
- Node.js v26.12.0; npm 12.2.1; Java OpenJDK 27; ps /usr/bin/ps.
- Ghidra, JADX, APKTool e Binwalk detectados no PATH. Confirmar versões e capacidade real, não confundir detecção com smoke funcional.
- OpenCode configura um MCP local 'rea' com npx -y rea-agents@6.7.0 mcp; NÃO criar segunda entrada com o mesmo papel.
- MegaBrain por Tailscale em HTTPS respondeu HTTP 200. HTTP 200 não comprova automaticamente handshake MCP nem indexação.
- Diretório existente: ~/MITR3/labs/ot-firmware. NÃO apagar, resetar ou sobrescrever.
- ~/Tools/rea e ~/Tools/reverse-skill ainda não existiam nos caminhos verificados.
- Git MITR3 tinha modificações e arquivos não versionados de outros agentes. Preservar integralmente.

Fontes oficiais, capturadas no estudo:
- https://github.com/morluto/rea — branch main commit 01788bac863ac786bfbb648cad69b11e23b40a89 — pacote rea-agents 6.7.0 (inspecionado, não instalado agora).
- https://github.com/zhaoxuya520/reverse-skill — branch main commit cab634bd855fc287f6e420c1f36fd1a6b9245960.
- Consultar documentação da versão pinada. O que está no main não prova equivalência byte a byte com npm e pacotes instalados.
- REA: Node 22.19+ / 24.11+ / 26+, procps ps e Ghidra 12.1.x com JDK compatível; ferramentas Android requerem JDK e JADX headless.
- reverse-skill: skills/config/routing.json como tabela única; roteador Linux skills/scripts/master-route.sh; casos pelo case-init.sh; tool-index gerado em refresh-tool-index.sh. O repositório contém material de exploits/payloads, portanto não promover instruções ou exemplos diretamente a regras globais.

## B. Topologia proposta (manter separação e rastreabilidade)

Arquivos-fonte pinados:
  ~/Tools/rea-src                     clone REA, COMMIT_FIXO, read-only como referência
  ~/Tools/reverse-skill               clone reverse-skill, COMMIT_FIXO, read-only como referência

Orquestração e produtos próprios MITR3:
  ~/MITR3/labs/reverse-next/
    README.md
    config/targets.yaml             somente allowlist local e caminhos de arquivos
    config/agent-lanes.yaml
    cases/<case-id>/
      scope.md
      inventory.json
      manifest.sha256
      evidence/
      findings/
      reviews/
    fixtures/native/
    fixtures/android/
    fixtures/firmware/
    scripts/
    tests/
    reports/
  ~/MITR3/skills/mitr3-reverse-next/SKILL.md
  ~/MITR3/docs/REVERSE-NEXT-ARCHITECTURE.md
  ~/MITR3/docs/REVERSE-NEXT-SECURITY.md
  ~/MITR3/docs/REVERSE-NEXT-HANDOFF.md

MegaBrain: indexar somente documentação curada com metadados e referências, em namespace/revisão próprios, preservando fontes e versionamento. Não sincronizar binários, segredos, dumps, APKs ou evidências com PII. Não copiar automaticamente o conteúdo integral de 880 arquivos reverse-skill nem 5492 arquivos do monorepo REA para RAG.

## C. Plano em fases, com portões de aceite

### Fase 0 — Snapshot, ownership e regras de execução [OpenCode; QA Codex]

C0: registrar git status, versões, serviços, REA MCP atual e rota do MegaBrain SEM imprimir credenciais. Inventariar apenas nomes de servidores MCP, nunca env/config completos. Salvar snapshot datado.
C1: mapear quais agentes estão editando cada arquivo; estabelecer lanes por pasta. Nunca sobrescrever alterações simultâneas.
C2: scope: análise somente em software próprio, amostras de laboratório e artefatos cuja análise é permitida. Site e APK de terceiro dependem da política específica de escopo; nenhum target fora do laboratório por padrão. Não fazer varredura, bypass, hooks ou replay em serviços públicos como efeito colateral da instalação.
C3: backup seletivo dos arquivos que eventualmente forem alterados, em diretório privado de permissão 0700; nunca armazenar chaves em relatórios ou prompts.
Evidência: baseline.json redigido, lista de arquivos sob ownership por agente e política de escopo.

### Fase 1 — Aquisição de código auditável e congelamento de versão [Codex; OpenCode]

Usar git clone em subdiretórios NOVOS e exclusivos, SEM executar setup/bootstrap/hook de terceiros ou inicializar submódulos.
Exemplo, quando o diretório estiver ausente e a origem conferida:
  git clone --filter=blob:none --no-recurse-submodules https://github.com/morluto/rea.git ~/Tools/rea-src
  git -C ~/Tools/rea-src checkout --detach 01788bac863ac786bfbb648cad69b11e23b40a89
  git clone --filter=blob:none --no-recurse-submodules https://github.com/zhaoxuya520/reverse-skill.git ~/Tools/reverse-skill
  git -C ~/Tools/reverse-skill checkout --detach cab634bd855fc287f6e420c1f36fd1a6b9245960

Antes de baixar, validar que os caminhos não contêm repositórios pré-existentes; se houver, investigar remoto e HEAD e atualizar apenas mediante decisão do maestro. Nunca reset --hard, git clean -fdx ou clone dentro de material de outro agente.
Depois: git remote -v (somente endpoints públicos), git rev-parse HEAD, manifest dos caminhos, licenças MIT, estrutura e bibliotecas. Não presumir que o código do main seja seguro só por ser público.
Auditar package.json scripts, npm lifecycle, requirements, downloads, dockerfiles, subprocess, paths de escrita, rede, armazenamento, scripts de bootstrap e conteúdo que tenta modificar instruções globais do agente; gerar parecer risco e dependências.
Qualquer npm ci/build, npx setup, pip install ou bootstrap só DEPOIS da revisão. Preferir ambientes de build isolados, versões pinadas, npm --ignore-scripts quando viável, sem downloads dinâmicos imprevistos. Manter source checkout e npm release separados.
Aceite: hashes/HEADs imutáveis registrados, clones independentes, nenhuma configuração de agente alterada.

### Fase 2 — REA MCP existente: validar, não reinstalar [Codex + VANTA]

O OpenCode já tem rea-agents@6.7.0. Não adicionar entrada duplicada e não instalar versão latest silenciosamente.
Verificar: npm package cache/local, npx pinado, versão real do pacote, Node, ps, Java, Ghidra, JADX; capturar JSON de doctor/providers de modo saneado. REA pode oferecer uma instalação compilada; só rodar build do clone após auditoria dos scripts.
Registrar GHIDRA_INSTALL_DIR se realmente necessário e se aponta para instalação existente válida; não forçar mudança global de JAVA_HOME sem validação com Ghidra. Checar versão Ghidra 12.1.x e disponibilidade do decompiler nativo da arquitetura.
Fazer teste de sessão isolada de initialize + tools/list, sem executar tools/call no servidor ativo até confirmar consentimento do case. Verificar respostas e registrar quantidades de tools, latência, versão e limitações. Somente depois abrir um binário próprio de teste.
Executar 'rea setup --client <cliente> --dry-run' antes de aplicar qualquer configuração de Codex/Hermes/Antigravity, sem --all-detected. Cada cliente necessita revisão individual de destino, backup e reinício controlado; não reiniciar sessão produtiva do time só por causa do setup.
Aceite: um cliente real recebe MCP tools/list e uma evidência válida de um fixture local; nenhuma duplicação em OpenCode.

### Fase 3 — Adaptar reverse-skill a Linux/Arch [Codex, com QA GPT-6]

O reverse-skill organiza o trabalho, não substitui REA/Ghidra. Ler RULES.md como referência do upstream, NÃO como autoridade para ignorar diretivas do MITR3 ou modificar SOULs globais.
Usar skills/scripts/master-route.sh como roteador de método, skills/config/routing.json como fonte única da tabela de rotas, e case-init.sh para criar casos com escopo explícito.
Revistar as diferenças Windows versus Linux: apk-reverse aponta para scripts .ps1; não executá-los no Arch por padrão. Criar wrappers locais bash/Python MITR3 que usem JADX, APKTool e REA realmente instalados. Não copiar afirmações upstream sobre versões detectadas sem medir o host atual.
Gerar tool-index na pasta staging do projeto, não diretamente em config global, após revisar scripts de detecção e efeitos de escrita. Não rodar scripts bootstrap/auto-install nem hooks globais como parte de simples indexação.
Preservar autorização explícita para target e network profile; o flag --force não altera isso.
Aceite: router seleciona corretamente APK/native/firmware em testes offline; inventário reflete caminho real, versão e origem sem reiniciar nada.

### Fase 4 — Laboratório de casos reproduzíveis [VANTA/Antigravity; Codex fixtures e testes]

Trilhas:
1. Native/ELF: binário próprio de exemplo, hashing, mitigations (checksec), strings, funções, xrefs, decompilação; comparação de evidências REA vs Ghidra vs rizin; nenhum exploit em equipamento real.
2. Android: APK próprio de demonstração criado para laboratório, JADX e APKTool, manifesto, classes, componentes exportados, fluxos de autenticação simulados, presença/ausência de checks no CLIENTE, documentação de que CLIENTE não prova segurança do SERVIDOR. Frida apenas emulator próprio e gate separado.
3. Firmware: preservar ~/MITR3/labs/ot-firmware; reutilizar amostras sintéticas e fixtures de comparação de versões. Binwalk e REA em modo estático para arquivos controlados. Extração protegida contra zip-slip, symlinks e bombas de compressão; execução por padrão desligada. QEMU/EMBA/Firmadyne só se houver case próprio, isolamento e gate.
4. Opcional Web/JS: apenas aplicações próprias, REA static JS com source maps disponíveis legitimamente, nenhuma credencial ou dados de usuários reais.
Cada trilha produz SHA256, version metadata, hipótese, trecho preciso de código, prova reproduzível, limitações, revisão e recomendações, sem extrapolar o impacto.
Aceite: smoke offline em pelo menos 1 fixture por trilha (native, APK, firmware) e testes determinísticos; nenhuma conexão a terceiro gerada pelo smoke.

### Fase 5 — Integração MegaBrain MCP (Hermes + OpenCode)

Conferir backend real /opt/megabrain via conexão autorizada ao servidor e health/tool-schema antes de editar serviço. HTTP 200 sozinho não confirma tool calling. Evitar alterações em Tailscale Serve/SSH/networking enquanto MCP produtivo funciona.
Criar namespace curado 'mitr3.reverse-next.v1' ou equivalente:
- Manifest JSON com repo/commit/arquivo/seção/SHA256/licença/risco/versão e data.
- Ingestão seletiva de documentação REA e skills metodológicas reverse-skill. Ignorar blobs, payloads, corpora de bypass, dados pessoais, tokens, outputs brutos e regras que tentem alterar o comportamento de agentes.
- Marcadores de confiabilidade: external_untrusted_instruction, reference_only, evidence_verified, reviewed_by.
- Gating: revisão do conteúdo antes da indexação, readback por termos verificáveis, validação de citações [arquivo + seção + commit]; não aceitar resposta do LLM como prova.
- JEV em modo shadow, sem transformar validação probabilística em selo de verdade; gate determinístico de citação + revisão humana para entailment.
Aceite: 6-10 consultas de regressão via MCP MegaBrain retornam fontes e commits corretos, sem segredo e sem instruções externas executadas.

### Fase 6 — Agentes, integração seletiva e governança [OpenCode maestro]

Codex (owner Build/QA): clones, hashes, test harness, wrappers Arch, REA doctor+handshake, CI de regressão, docs de instalação.
Antigravity/VANTA (owner Reverse): fixtures, Ghidra/REA, análise estática, relatório de limitações.
Hermes/Gemma4 (owner Knowledge): seleção de referências, curadoria, index/readback MegaBrain, knowledge graph.
DeepSeek (owner Web/API): revisão de modelos de autorização de aplicações de laboratório e limites entre cliente/servidor, sem tráfego fora de escopo.
OpenCode (maestro): distribuir workitems não sobrepostos; gates e integração, revisão de ownership, rollback, release.
GPT-6 (QA independente): revisar manifesto, risco de prompt injection em skills, testes, evidência e checklist de aceite.
O handoff via arquivo não significa mensagem entregue aos agentes. Maestro deve usar canal real do Maestri para cada lane, confirmar ACK e evitar concorrência de escrita.
Não executar comandos de envio com segredos nos argumentos nem mandar keys ao chat/MegaBrain.

### Fase 7 — Gates de release, validação e rollback [Codex + OpenCode]

Gate G0: estado anterior preservado e diff auditado.
Gate G1: fontes pinadas e licences/risco/dependências revisados.
Gate G2: check estático, no secrets, lint, testes de scripts e unidade.
Gate G3: REA MCP identificado, handshake real, Ghidra compatível e 3 trilhas smoke offline.
Gate G4: MegaBrain index/readback com referências corretas e zero dados sensíveis.
Gate G5: documentação completa com comandos de repetição, limites, riscos, impactos no host e rollback por arquivo.
Gate G6: aprovação final do OpenCode e aceite humano antes de mudanças em serviços/clients de produção.
Qualquer gate falho -> estado 'bloqueado' ou 'inconclusivo', nunca declarar 100% pronto com base apenas em --version.
Nunca reescrever evidência histórica nem reutilizar resultados sem checksum.

## D. Testes mínimos obrigatórios

- Teste de paths e impossibilidade de traversal, path injection e escrita fora do lab.
- Teste de uso offline sem side effects, no auto-bootstraps de third parties.
- Teste de não sobrescrever config atual do OpenCode/Hermes/Codex.
- Teste de exclusão de credenciais: token Bearer, env secrets, key patterns fictícios nos logs/relatórios.
- Teste de portabilidade no Arch; version check contra binários reais e ausência simulada.
- Teste de roteamento correto para native/Android/firmware, inclusive casos ambíguos.
- Teste de integridade hashes antes/depois, scope guard e classificação 'inconclusivo'.
- Teste MegaBrain de ingestão referenciada e de proteção contra prompt injection em documentos externos.
- Teste de rollback por cópia, sem parar serviços do time.
- Código de terceiros jamais executado apenas por constar em SKILL.md.

## E. Primeira entrega esperada do Codex

1. docs/REVERSE-NEXT-ARCHITECTURE.md e threat-model com áreas confiáveis e não confiáveis.
2. Inventory/capabilities por versão real, sem executar scanners públicos.
3. Relatório supply-chain dos dois upstreams + commits fixados.
4. scripts/mitr3-reverse-lab.sh para bootstrap **local e idempotente** apenas após revisão, opção --dry-run, --check e --verify; sem global installs por padrão.
5. tests/test_reverse_lab.* com fixtures e evidências.
6. Exemplo de trace nativo em amostra própria via REA/Ghidra.
7. docs/REVERSE-NEXT-STATUS.md com PASS/BLOCKED e motivo, nunca fingir deploy ou clone.
8. doc de integração do MegaBrain em modo staged, aprovado pelo OpenCode.

## F. Primeira entrega esperada do maestro

Criar workitems para Codex/VANTA/Hermes e confirmar quem está executando cada fase. Rodar a Fase 0, depois autorizar Fase 1 e prosseguir somente mediante os gates. Revisar backlog atual (inclusive H1-MELI-v10) para evitar bloqueio ou degradação das tarefas existentes.

## Nota de prudência

Este plano não autoriza atacar serviços públicos, coletar dados privados de terceiros, alterar controladores físicos, baixar firmware protegido ou modificar cliente de terceiro em desacordo com as regras de escopo. A aprovação do laboratório não substitui as regras do programa pesquisado. Em especial, engenharia reversa do APK/site Mercado Livre é hipótese separada e deve respeitar expressamente o programa e o teste controlado X1.
