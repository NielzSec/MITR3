# Avaliação de Arquitetura e Segurança: ECC (Everything Claude Code / Agent Harness OS)

- **Target:** `affaan-m/ECC` (v2.2.3, 284k★, MIT)
- **Data da Avaliação:** 2026-10-19
- **Escopo:** Análise estática profunda do repositório em `/tmp/opencode/ecc-eval` (sem execução de instaladores, sem injeção de hooks).
- **Avaliador:** VANTA / MITR3 AI-Research Lane

---

## 1. Veredito Executivo

**Veredito:** **Aproveitamento seletivo de padrões e prompts (Cherry-pick estático); REJEIÇÃO de instalação global e execução de runtime hooks não auditados.**

O ECC é um repositório massivo de orquestração agentic ("agent harness OS") contendo 71 agentes especializados, 311 skills, 97 comandos de workflow e adaptadores para mais de 10 harnesses (Claude Code, OpenCode, Codex, Gemini, Cursor, Zed, Hermes, etc.). Contudo, sua camada operacional baseia-se em mutação invasiva de ambientes de usuário (`~/.config/opencode`, `~/.claude`, `~/.codex`), injeção de hooks de interceptação síncrona de comandos (`PreToolUse`, `PostToolUse`) e orquestração de MCPs dinâmicos via `npx -y`/`uvx`.

No contexto de alta garantia do MITR3 (onde tooling deve ser reprodutível, auditável e imutável), o ECC não deve ser instalado como runtime global ou plataforma viva, mas serve como catálogo de referência para extração de prompts de agentes e técnicas de harness.

---

## 2. Análise de Superfície de Ataque e Segurança

### 2.1 Hooks e Interceptação em Tempo de Execução
- **Mecanismo:** O ECC injeta hooks em `hooks/hooks.json` e `.opencode/plugins/ecc-hooks.ts`. Intercepta eventos de `Bash`, `PowerShell`, `Write`, `Edit` e `session.created`.
- **Risco de RCE e Overhead:** Cada comando executado pelo harness passa pelo dispatcher Node (`scripts/hooks/pre-bash-dispatcher.js`), acionando scripts como `gateguard-fact-force.js` (94 KB de parsing AST/regex) e `block-no-verify.js`. Falhas no parsing, timeouts ou bypasses colocam em risco a integridade do harness.
- **Risco de Shell Hijack:** O script `scripts/codex/install-global-git-hooks.sh` executa `git config --global core.hooksPath "$HOME/.codex/git-hooks"`, redirecionando hooks de Git de todos os repositórios do sistema operacional para scripts do ECC.

### 2.2 Configurações de MCP (Model Context Protocol)
- **Vetor de Supply-Chain:** `mcp-configs/mcp-servers.json` recomenda servidores MCP executados via `npx -y <pacote>` e `uvx <pacote>` sem versionamento restrito por hash (ex.: `@modelcontextprotocol/server-github`, `chrome-devtools-mcp`, `omega-memory`).
- **Exposição de Credenciais:** As configurações exemplificam injeção de tokens com variáveis de ambiente abertas (`GITHUB_PERSONAL_ACCESS_TOKEN`, `JIRA_API_TOKEN`, `FIRECRAWL_API_KEY`).
- **Servidores Locais Não Publicados:** O config referencia MCPs locais opcionais como `ito-compute` e `ecc-memory-vault` (`scripts/memory-mcp.mjs`), que requerem bins globais no PATH.

### 2.3 Permissões e Mutação de Sistema de Arquivos
- O instalador (`scripts/install-apply.js`) opera em nível de usuário escrevendo em:
  - OpenCode: `$OPENCODE_CONFIG_DIR`, `$XDG_CONFIG_HOME/opencode` ou `~/.config/opencode/`
  - Claude: `~/.claude/`
  - Codex: `~/.codex/`
- Instalações não flagadas com `--dry-run` gravam arquivos de regras, skills e shims de comando, com reconciliação automática de estado que deleta ou sobrescreve arquivos preexistentes fora do manifesto.

### 2.4 AgentShield
- O repositório faz referência frequente ao **AgentShield** (`github.com/affaan-m/agentshield`), criado pelo mesmo autor.
- **Natureza:** Trata-se de um scanner de segurança externo para detectar hooks suspeitos, injeções indiretas de prompt em skills e configurações permissivas de MCP.
- **Status:** Não é um motor embutido no ECC, mas sim um projeto satélite recomendado para auditoria prévia.

---

## 3. Aderência ao Stack MITR3

| Componente ECC | Avaliação MITR3 | Ação Recomendada |
| :--- | :--- | :--- |
| **OpenCode Seats** | `.opencode/opencode.json` define 71 subagentes com flags `tools` granulares (read, edit, bash). | **Adaptar**: Extrair as personas de subagentes (planner, architect, security-reviewer, tdd-guide) para modelos de assento locais sem instalar o plugin runtime. |
| **Skills (311 skills)** | Repositório abrangente de prompts markdown em formato `SKILL.md`. | **Cherry-pick**: Absorver pontualmente skills relevantes (ex: TDD, API design, RAG evaluation) na árvore `~/.agents/skills/` ou `MITR3/skills/`. |
| **Memória (Continuous Learning / Homunculus)** | Sistema de logging de instintos em SQLite/JSONL (`~/.claude/homunculus/`). | **Não adotar**: Conflita com a arquitetura de memória e evidências estruturadas do MITR3 (MegaBrain MCP / REA / SARIF). |
| **AgentShield** | Scanner de integridade de harness e skills. | **Avaliar separadamente**: Pode ser rodado como ferramenta de auditoria de skills em sandbox isolada. |

---

## 4. Caminho de Integração Faseado

### Fase 0 — Avaliação Estática (Concluída)
- Inspeção em `/tmp/opencode/ecc-eval` sem executar `npm install` ou `install.sh`.
- Catalogação de riscos de hooks e dependências.

### Fase 1 — Extração de Catálogo Estático (MITR3 Template Library)
- Isolar e portar para o MITR3 apenas definições declarativas:
  - Prompts de agentes em `.opencode/prompts/agents/` (ex: `security-reviewer.txt`, `planner.txt`, `architect.txt`).
  - Subconjunto de skills puramente documentais em formato aberto (sem scripts auxiliares).

### Fase 2 — Piloto em 1 Seat Isolado (Container / VM)
- **Ambiente:** Seat piloto em container descartável (Docker/devcontainer).
- **Restrição:** Configuração estritamente local de projeto (`.opencode/` na raiz do repositório alvo), **nunca** no home do host (`~/.config/opencode`).
- **Flags Mandatórias:** Execução com `--no-hooks` e desativação de download automático de MCPs.

### Fase 3 — Auditoria de Hardening (AgentShield / SAST)
- Utilização de scanners independentes para auditar qualquer regra ou skill antes de disponibilizá-la aos operadores MITR3.

---

## 5. Matriz de Riscos & Supply-Chain

1. **Typosquatting & Unpinned MCPs:** O uso de `npx -y` em configs de MCP expõe o operador ao ecossistema npm em tempo de execução sem pinning de SHA-256.
2. **Hook Poisoning:** Um repositório clonado contendo configurações maliciosas pode acionar scripts de hooks arbitrários caso o harness auto-aprove configurações locais de projeto.
3. **Drift de Configuração Global:** A execução do instalador padrão sobrescreve o ambiente de desenvolvimento diário do operador.

---

## 6. O Que NÃO Fazer (Regras Explícitas de Bloqueio)

> [!CAUTION]
> **DIRETIVAS NEGATIVAS MANDATÓRIAS:**
> 1. **NÃO executar `install.sh` ou `npm run install` no host** (`~/.config/opencode`, `~/.claude` ou `~/.codex`).
> 2. **NÃO executar `scripts/codex/install-global-git-hooks.sh`**: Isso sequestra o `git config --global core.hooksPath` do operador.
> 3. **NÃO habilitar hooks automáticos de execução** (`--enable-hooks` ou interceptadores de shell) em ambientes de produção/auditoria.
> 4. **NÃO importar arquivos de MCP (`mcp-servers.json`) contendo `npx -y`** sem empacotar localmente e verificar o hash da ferramenta.
> 5. **NÃO sincronizar diretórios de memória do ECC (`homunculus`) com dados confidenciais de engajamento MITR3.**
