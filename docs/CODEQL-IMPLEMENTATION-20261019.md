# MITR3 — CodeQL End-to-End — Handoff GPT-6
Data: 2026-10-19 | Execução no Arch `nielz` via Remote Desktop Commander.
Status: **validado**, sem reiniciar os agentes e sem apagar artefatos existentes.

## CLI e query packs
- `~/Tools/codeql/codeql/codeql` executa versão **2.27.2**.
- `codeql resolve languages` confirma Python, JavaScript, Go.
- `codeql pack download codeql/python-queries codeql/javascript-queries codeql/go-queries` não baixou nada: packs já locais (`python-queries@1.8.12`, `javascript-queries@2.4.7`, `go-queries@1.6.12`).
- Symlink `~/.local/bin/codeql` existente, funcional e apontando para a CLI.

## Implementado
- `bin/mitr3-codeql.sh <repo> [python|javascript|go]`: database create + analyze suite security-extended, logs, SARIF, findings, SHA256.
- `bin/mitr3-codeql-report.py`: severity scoring (rule security-severity; fallback SARIF level), até 25 achados query id + arquivo:linha.
- `tests/test_codeql_report.py`: três testes `unittest` passaram (vazio, HIGH/CRITICAL e localização, fallback por nível).
- `docs/TOOLCHAIN.md` e `docs/RUNBOOK.md` atualizados para refletir os caminhos e a restrição do Go.
- Skill `skills/mitr3-codeql/SKILL.md` exposta por symlinks nas skills de `~/.agents` (Codex), `~/.hermes`, `~/.config/opencode` e `~/.gemini/antigravity-cli`.
- `.gitignore` ajustado para impedir commit acidental dos SARIF locais e saídas de CodeQL.
- Bancos ficam em `/tmp/opencode/codeql-db-<nome>-<lang>-<timestamp>`, sem sobrescrever bancos anteriores.
- Relatórios e evidências ficam por execução em `~/MITR3/engagements/codeql_<repo>_<hash>/runs/<timestamp>_<lang>/`, não na raiz do alvo.

## Testes end-to-end e resultados
| alvo | modo | extração | security-extended | evidência |
|---|---|---:|---:|---|
| `~/MITR3` (Python) | none | 4/4 arquivos | **0** | SARIF + SHA256 verificados |
| `~/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re` (Python) | none | 23/23 | **0** | SARIF + SHA256 verificados |
| fixture JavaScript em `/tmp/opencode` | none | 1/1 | **0** | SARIF + SHA256 verificados |
| fixture Go em `/tmp/opencode` | autobuild opt-in | 1/1 | **0** | SARIF + SHA256 verificados |

**Aviso de semântica:** 0 findings é resultado de suite e cobertura específicas, não comprova ausência de vulnerabilidades. Validar manualmente hipóteses/falsos positivos, comparar Semgrep/Trivy e executar somente dentro do escopo autorizado.

## Go exige autorização explícita para build
O CodeQL 2.27.2 não suporta `--build-mode=none` em Go (CLI e documentação oficial).
Por padrão o wrapper rejeita Go, em vez de compilar código potencialmente hostil.
Para repositório local confiável:
```bash
MITR3_CODEQL_ALLOW_GO_BUILD=1 ~/MITR3/bin/mitr3-codeql.sh /absolute/path/to/go-repo go
```

## Checagem operacional (última)
`~/MITR3/bin/mitr3-health.sh --json` registrou **46 ok / 0 missing / 0 warn**, incluindo `codeql`. Isto confirma inventário/serviços testados pelo script, não equivale a pentest do host.

## Comunicação e reversibilidade
- OpenCode continua maestro. Este arquivo é entrega **assíncrona**, não mensagem `maestri ask`.
- Skills novas podem requerer nova sessão ou refresh do catálogo dos agentes. Nenhum processo ativo foi reiniciado.
- Backups dos Markdown e `.gitignore` anteriores em `~/.local/share/mitr3-config-backups/*before-codeql-20261019*`.
- Foram preservados os relatórios SARIF na raiz de `~/MITR3` criados anteriormente por outros agentes; este wrapper jamais os sobrescreve.
- Antes de indexar no MegaBrain, saneie paths, snippets e dados privados.
