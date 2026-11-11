# MITR3 — Modular Intelligence, Threat Research & Reconnaissance Repository

Host Linux (`Arch Linux`) · Coordenação declarada via **Orca** e **Morfeus/OpenCode** · Última sincronização de custódia: 11/11/2026.

> Estado operacional verificado em 11/11/2026: [auditoria cruzada](docs/MITR3-CROSS-AUDIT-20261111.md). Papéis declarados, testes reportados e processos observados são registrados separadamente.

---

## 1. Visão Geral e Arquitetura

O **MITR3** é um ecossistema integrado para auditoria de segurança de alta precisão, pesquisa ofensiva/defensiva autorizada, engenharia reversa e orquestração de enxames de agentes (*Agentic Swarm*).

### Estrutura de Diretórios

```
~/MITR3/
├── bin/                          # Motores centrais, CLI tools, harnesses e utilitários
│   ├── mitr3-vuln-harness.py     # Camada 1: AI Vulnerability Harness determinístico
│   ├── mitr3-graph-normalizer.py # Camada 2: Normalizador de Grafo e contexto IaC
│   ├── mitr3-code-graph.py       # Camada 3: Motor de Grafo de Código e ATT&CK
│   ├── mitr3-attack-graph.py     # Camada 3: Gerador do Grafo de Ataque STIX/ATT&CK
│   ├── mitr3-graph-verify.py     # Camada 4: Verificador de Evidências e Poda de Caminhos
│   ├── mitr3-health.sh           # Auditoria completa do ambiente e matriz de 75 ferramentas
│   ├── mitr3-secrets-audit.py    # Auditoria de superfície de segredos e credenciais
│   └── mitr3-context-bridge.py   # Ponte de contexto multi-agente
├── docs/                         # Especificações formais, doutrinas e cadernos operacionais
│   ├── MITR3-AI-VULNERABILITY-HARNESS-SPEC.md
│   ├── MITR3-GRAPH-ENGINEERING-CONSENSUS-20261110.md
│   ├── MITR3-ATTACK-GRAPH-LAYER3-20261110.md
│   ├── MITR3-ATTACK-GRAPH-LAYER4-20261110.md
│   ├── SCOPE.md                  # Procedimento e contrato de escopo humano (Nexus)
│   └── TOOLCHAIN.md              # Matriz de cobertura e proveniência de ferramentas
├── hackbots/                     # Framework de Hackbots, contratos e Skill Builder
│   ├── contracts/                # Schemas JSON para missões, steering e asserções
│   └── skill-builder/            # Construtor determinístico obrigatório de mini-skills
├── tests/                        # Suíte determinística de testes unitários e de integração
│   ├── test_vuln_harness.py      # Testes da Camada 1
│   ├── test_graph_normalizer.py  # Testes da Camada 2
│   ├── test_code_graph.py        # Testes da Camada 3
│   └── test_graph_verify.py      # Testes da Camada 4
└── tools/                        # Ferramentas operacionais e pontes de comunicação
    └── mitr3_slack.py            # Bridge assíncrona Composio MCP para Slack (#all-mitr3)
```

---

## 2. Diretriz de Branching e Protocolo de Custódia

A partir de 10/11/2026, o repositório opera sob estrita segregação de ambientes e política de custódia supervisionada pelo operador **dj**:

- **Branch `master` ([`/home/nielz/MITR3`](file:///home/nielz/MITR3))**:
  - Ambiente operacional de **staging** e desenvolvimento ativo.
  - Recebe inicialmente todos os lotes desenvolvidos pelos agentes após validação unitária e auditoria pré-commit de segredos (`bin/mitr3-secrets-audit.py`).
  - Sincronizado remotamente com `origin/master`.
- **Branch `main` ([`/home/nielz/MITR3/MITR3`](file:///home/nielz/MITR3/MITR3))**:
  - Ambiente de **release pública sanitizada**.
  - **Bloqueio total de push direto**: nenhuma alteração é promovida de `master` para `main` sem liberação oficial e explícita do operador dj.
  - Sincronizado remotamente com `origin/main`.
- **Custódia Git e Auditoria**:
  - O agente **VANTA** é responsável pela custódia, organização de lotes seletivos, auditoria de segredos e sincronização remota via Git / GitHub CLI.

---

## 3. Papéis declarados do Squad

O quadro descreve responsabilidades planejadas. Um registro em `hackbots/bots.json` não prova que o agente está implementado, configurado no host, ativo ou executando uma missão. Consulte [Hackbots](hackbots/README.md) para a definição dos estados.

| Assento | Agente | Motor | Responsabilidade Primária |
| :--- | :--- | :--- | :--- |
| **Maestro** | Morfeus / OpenCode | DeepSeek V4.1 Flash | Coordenação lógica, testes ativos e orquestração de runtime |
| **Build & QA** | Codex | GPT-6-Sol | QA independente, contratos formais, testes unitários e revisões de código |
| **Research** | Hermes / Gemma4 | gemma4:31b-cloud | MegaBrain, inteligência OSINT, síntese de write-ups e documentação |
| **Reverse & Custódia** | Antigravity / VANTA | Gemini 3.8 Flash | Engenharia reversa, análise de baixo nível, integridade de toolchain e custódia Git |
| **Exploit & AppSec** | DeepSeek | DeepSeek-V4-Flash | Auditoria de APIs, WebSec e validação de vetores de ataque |

### Orquestração via Orca
- O **Orca** atua como painel de controle, transporte de dispatch e isolamento de worktrees.
- Morfeus/OpenCode é o coordenador lógico declarado; a integração Morfeus → Orca → Runner ainda não tem um handoff real documentado com run ID e log sanitizado.
- O registry define máximo de 2 workers para o piloto offline. Isso não comprova execução integrada nem custo zero; cada missão precisa de evidência própria e aceite humano.

### Doutrina Operacional de Comunicação (Slack Loop)
- **Regra obrigatória**: Todo agente deve ler o canal `#all-mitr3` antes de iniciar qualquer tarefa operacional e publicar os resultados, commits e hashes SHA256 ao concluir:
  ```bash
  # Leitura de histórico recente
  python3 tools/mitr3_slack.py

  # Publicação de relatório
  python3 tools/mitr3_slack.py post "Mensagem do relatório..."
  ```

---

## 4. Pipeline de Graph Engineering (Camadas 1 a 4)

O repositório contém um pipeline implementado para normalizar e correlacionar dados em grafo. Revisões independentes dos lotes C1–C4 foram registradas; isso não substitui validação de dados operacionais nem prova todas as rotas de ponta a ponta:

```
[Código / IaC / Scanners]
          │
          ▼
┌────────────────────────────────────────────────────────┐
│ Camada 1: AI Vulnerability Harness                     │
│ (mitr3-vuln-harness.py)                                │
│ Consenso multi-scanner, AST gate e parser IaC          │
└─────────────────────────┬──────────────────────────────┘
                          │ Finding Unificado + Evidências
                          ▼
┌────────────────────────────────────────────────────────┐
│ Camada 2: Graph Normalizer                             │
│ (mitr3-graph-normalizer.py)                            │
│ Canonicalização SQLite, evidência segura em disco      │
└─────────────────────────┬──────────────────────────────┘
                          │ attack_nodes, attack_edges
                          ▼
┌────────────────────────────────────────────────────────┐
│ Camada 3: Attack Graph & Code Graph Engine             │
│ (mitr3-code-graph.py & mitr3-attack-graph.py)          │
│ Mapeamento de fluxo FLOWS_TO/CALLS e links ATT&CK      │
└─────────────────────────┬──────────────────────────────┘
                          │ Grafo Normalizado & Caminhos
                          ▼
┌────────────────────────────────────────────────────────┐
│ Camada 4: Evidence & Verification (Path Pruner)        │
│ (mitr3-graph-verify.py)                                │
│ Poda dinâmica, prova ast_gate e histórico append-only  │
└────────────────────────────────────────────────────────┘
```

1. **Camada 1 — AI Vulnerability Harness** ([`bin/mitr3-vuln-harness.py`](file:///home/nielz/MITR3/bin/mitr3-vuln-harness.py)):
   - Validação determinística de findings com filtro AST (tolerância zero a alucinações de LLMs).
   - Consenso entre múltiplos scanners estáticos e parsers de infraestrutura como código (IaC).
2. **Camada 2 — Graph Normalizer** ([`bin/mitr3-graph-normalizer.py`](file:///home/nielz/MITR3/bin/mitr3-graph-normalizer.py)):
   - Canonicalização e persistência transacional em SQLite.
   - Materialização de evidências em disco ancoradas por `parent_fd` com proteção estrita contra symlinks (`O_NOFOLLOW`, `O_DIRECTORY`, permissões `0700`/`0600`).
3. **Camada 3 — Attack Graph & Code Graph Engine** ([`bin/mitr3-code-graph.py`](file:///home/nielz/MITR3/bin/mitr3-code-graph.py) & [`bin/mitr3-attack-graph.py`](file:///home/nielz/MITR3/bin/mitr3-attack-graph.py)):
   - Ingestão de grafos de código com nós de Source, Sink, Call e Flow.
   - Preservação de tabelas de Layer 3 durante reconstruções de STIX/ATT&CK sem perda de estado.
4. **Camada 4 — Evidence & Verification Engine** ([`bin/mitr3-graph-verify.py`](file:///home/nielz/MITR3/bin/mitr3-graph-verify.py)):
   - Avaliação e poda de caminhos de ataque baseada em mitigação real comprovada por artefatos em disco.
   - Tabelas de evidências, revogações e veredictos preservam histórico. Evidências novas ficam vinculadas ao hash do snapshot C3 e deixam de contar quando o grafo muda. Schema v1 exige migração explícita; evidências históricas sem snapshot permanecem sem contagem até nova análise.

---

## 5. Inventário da Toolchain

O inventário documenta 75 ferramentas candidatas e usa [`bin/mitr3-health.sh`](file:///home/nielz/MITR3/bin/mitr3-health.sh) para uma verificação pontual do host. O total do inventário não deve ser apresentado como estado operacional atual sem um resultado datado e vinculado ao host:

- **Active Directory / Kerberos**: `bloodhound-python`, `kerbrute`, `responder`, `crackmapexec`, `certipy`.
- **Cloud Security**: `aws` (CLI v2), `gcloud` (Google Cloud SDK), `az` (Azure CLI), `prowler`, `scout` (ScoutSuite), `cloudfox`, `pacu`.
- **Engenharia Reversa & Binários**: `ghidra` (v12.1.2), `rizin`, `radare2`, `jadx`, `frida`, `capa`, `floss`, `gdb`, `angr`, `ropper`, `ROPgadget`.
- **Web, API & Rede**: `nmap`, `ffuf`, `nuclei`, `sqlmap`, `trivy`, `semgrep`, `osv-scanner`.
- **Supply Chain & Segredos**: `trufflehog`, `syft`, `zizmor`, `mitr3-secrets-audit.py`.

### Plano de Servidores MCP (Model Context Protocol)

O arquivo `~/.config/opencode/opencode.json` declara 16 servidores MCP. A configuração não prova que todos estão conectados ou saudáveis no momento:
- `megabrain`: Base de conhecimento com embeddings, busca semântica e histórico operacional.
- `mitr3-nexus`: Portão constitucional de escopo humano (`docs/SCOPE.md`).
- `rea`: Suíte de engenharia reversa conectada diretamente ao Ghidra headless.
- `chrome-devtools`: Instrumentação headless de navegador para exploração web e inspeção de DOM.
- `playwright`: Automação de browser e interação com cenários complexos.
- `apisec-ng`: Automação e análise estruturada de endpoints REST / GraphQL.
- `context7`: Documentação e resolução de bibliotecas e padrões de código.
- `gemini-research`: Pesquisa aprofundada via modelos de raciocínio.

---

## 6. Procedimentos de Verificação e Segurança

### Diagnóstico de Saúde do Ambiente
```bash
# Verificação geral da toolchain e MCPs
~/MITR3/bin/mitr3-health.sh

# Auditoria em formato JSON
~/MITR3/bin/mitr3-health.sh --json
```

### Execução da Suíte de Testes
Para garantir isolamento em ambiente Arch Linux (PEP 668), execute os testes utilizando o virtualenv de referência:
```bash
/opt/mitr3/cairn/cairn/.venv/bin/pytest tests/test_vuln_harness.py tests/test_graph_normalizer.py tests/test_code_graph.py tests/test_graph_verify.py -v
```

### Auditoria de Segredos Pré-Commit
Nenhum artefato deve ser commitado sem a execução prévia da auditoria determinística:
```bash
python3 bin/mitr3-secrets-audit.py <caminhos_a_commitar>
```

### Política de Skill Builder Obrigatório
Toda nova skill ou mini-skill para os agentes MITR3 deve ser criada através de [`hackbots/skill-builder/skill_builder.py`](file:///home/nielz/MITR3/hackbots/skill-builder/skill_builder.py) com especificação `methodology.json`, testes no Evaluator e validação de QA independente. É estritamente proibida a criação manual de arquivos `SKILL.md` em diretórios ativos.
