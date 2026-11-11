# MITR3 — Camada 3: Attack Graph (código / cadeias de ataque)

**Data:** 2026-11-10 | **Branch:** `master` (staging) | **Spec:** `docs/MITR3-GRAPH-ENGINEERING-CONSENSUS-20261110.md`, Fase 2
**Arquivos:** `bin/mitr3-code-graph.py` (novo), `bin/mitr3-attack-graph.py` (+35 linhas, `carry_code_graph`), `tests/test_code_graph.py` (25 testes)

## 1. Papel no pipeline

Camada 2 (`mitr3-graph-normalizer.py --jsonl`) → **Camada 3 (este módulo)** → Camada 4 (Evidence & Verification, futura `mitr3-graph-verify.py`).
A C3 grava estrutura. Não prova nada: toda aresta nasce `STRUCTURAL_HYPOTHESIS`. Promoção para `FEASIBLE_PATH` ou `PROVEN` é exclusiva da C4.

## 2. Contrato

| Item | Regra |
|---|---|
| Entrada | JSON-L da C2 (`entity` = `node` \| `edge`). Validação completa antes de abrir o banco; um registro inválido aborta tudo (`arquivo:linha: motivo`). |
| Banco | `state/mitr3-attack.sqlite3`, tabelas próprias: `attack_nodes`, `attack_edges`, `technique_links`, `graph_snapshots`, `attack_revisions`, `code_graph_meta`. Tabelas STIX (`entities`, `edges`, `metadata`) nunca são escritas. |
| Forma das arestas | `FLOWS_TO` SOURCE→FINDING; `CALLS` FINDING→SINK; `MITIGATED_BY` FINDING→MITIGATION; `MAPS_TO` FINDING→ATTACK_TECHNIQUE. Imposta por trigger (INSERT e UPDATE), sem depender de `PRAGMA foreign_keys`. |
| Integridade | Trigger bloqueia DELETE de nó referenciado e mudança de `id`/`type`. CHECK de hash (64 hex), `weight` em [0,1], `verification_state` em 3 valores. |
| Escrita | Transação única `BEGIN IMMEDIATE`, tudo ou nada. Upsert sem `INSERT OR REPLACE` (evita cascata de DELETE). |
| Revisão | Conteúdo ou evidência alterados geram linha em `attack_revisions`; aresta alterada volta a `STRUCTURAL_HYPOTHESIS`. Entrada idêntica não altera nada (preserva resultado da C4). |
| ATT&CK | Nó `T####` liga ao `attack-pattern` STIX por `technique_links` (`RESOLVED`/`UNRESOLVED`, com `bundle_sha256`). Sem sobrescrever entidade, sem aresta cruzando domínios. |
| Tabelas de terceiros | Se `attack_nodes`/`attack_edges` existirem sem `code_graph_meta` (ex.: `normalizer --sqlite`), a C3 recusa e não reaproveita. |
| Rebuild ATT&CK | `build()` troca o arquivo inteiro; agora copia as tabelas da C3 (linhas, índices, triggers) para o banco novo. Sem C3 no banco, o relatório não muda. |

## 3. Três hashes, nunca misturados

- `content_sha256`: JSON canônico (`sort_keys`, separadores compactos) dos campos da própria linha.
- `evidence_sha256`: proveniência fornecida pela C2 (opaco para a C3; só o formato é validado).
- Snapshot: hash sobre `id/type/content/evidence` de todos os nós e arestas ordenados por id. Independe de ordem de entrada, de timestamps e do arquivo de banco.

## 4. Uso

```bash
python3 bin/mitr3-graph-normalizer.py findings.json --jsonl /tmp/l2.jsonl
python3 bin/mitr3-code-graph.py ingest /tmp/l2.jsonl          # saída JSON
python3 bin/mitr3-code-graph.py stats
python3 bin/mitr3-code-graph.py paths [--source ID] [--sink ID] [--limit N]
python3 bin/mitr3-code-graph.py snapshot                      # registra o hash atual
python3 bin/mitr3-code-graph.py relink                        # reresolve ATT&CK após novo build
# --db <caminho> aceito antes da ação (padrão: state/mitr3-attack.sqlite3)
```

`paths` lista SOURCE→FINDING→SINK. Mitigações aparecem como anotação (`effect: ANNOTATION_ONLY`, `pruned: false`). Findings sem SOURCE ou sem SINK saem em `unanchored_findings`; a C3 não inventa caminho.

## 5. Lacunas e riscos (registrados, não corrigidos)

1. **C2, nó SINK dependente de ordem.** O normalizer grava a `line` do finding no nó SINK compartilhado (`snk:<arquivo>:<função>`). Dois findings no mesmo arquivo com o mesmo sink produzem conteúdo diferente conforme a ordem. A C3 recusa o conflito (teste `test_shared_sink_with_different_lines_fails_closed`). Correção sugerida na C2: não gravar `line` no SINK.
2. **C2, `persist_sqlite` fraco.** Usa `INSERT OR REPLACE` com FK `ON DELETE CASCADE`, sem trigger de UPDATE/DELETE e sem CHECK. Se apontado para `state/mitr3-attack.sqlite3`, a C3 recusa o banco. Recomendação: `--sqlite` só para banco descartável; produção entra por `mitr3-code-graph.py ingest`. Não verificado empiricamente se o REPLACE dispara a cascata (não foi testado).
3. **C2, `weight` sem limite.** `multiplier` de mitigação não é limitado a 1.0; a C3 rejeita fora de [0,1].
4. **Evidência = hash do dict em memória**, não de artefato em disco (consenso exige artefato físico). A C3 guarda o hash, mas não consegue provar a origem. Depende da C2/C4.
5. **Poda AST + IaC** continua só especificada. Nada na C3 elimina ou suprime caminho; a decisão `SUPPRESSED_BY_IAC` / `AST_UNREACHABLE` é da C4.
6. **Links ATT&CK podem ficar defasados** após rebuild do bundle (guardam o `bundle_sha256` antigo). `relink` corrige; não é automático.
7. **Arestas** não têm guarda de DELETE (só nós). Remoção de aresta perde proveniência; política de revogação fica para a C4.

## 6. Validação

- `tests/test_code_graph.py`: 25/25 (contrato real C2→C3 usando o exportador da C2, guardas de schema, hashes, revisão, separação STIX, rebuild, caminhos, CLI).
- `tests/test_attack_graph.py`: 12/12, reexecutado porque `mitr3-attack-graph.py` mudou.
- Dados reais em cópia do banco: 1.827 entidades / 20.957 arestas idênticas após ingest e após `build()` com o bundle em cache; T1190 resolvido para o `attack-pattern` real; snapshot idêntico após o rebuild (única diferença em `metadata`: `built_at`).
- C1 e C2 não foram retestadas (sem alteração).
