# Rebuild STIX com preservação C3/C4 — staging

Data: 2026-11-11. Base local: `origin/master`, HEAD
`21213cfb4c5b6ead7697328c3f36bf973688122a`, worktree Orca
`graph-c4-rebuild-fix`, branch `NielzSec/graph-c4-rebuild-fix`.
AGENTS.md, Ponytail e #all-mitr3 foram lidos antes da alteração.
Contexto Slack consultado: https://mitr3.slack.com/archives/C0C9ZLLU094/p1794366205094269
(auditoria anterior); a correção foi autorizada pelo despacho atual.

## Alteração e dependências

O rebuild anteriormente preservava somente C3, perdendo evidências, revogações
e veredictos C4 enquanto carregava FEASIBLE_PATH. Agora preserva as seis tabelas
C3 e as quatro C4, suas definições SQL, índices explícitos e triggers, incluindo
`verify_nodes_delete_guard`, associado a `attack_nodes`. Autoíndices de PK/UNIQUE
são recriados pelas definições das tabelas.

A ordem de linhas é `code_graph_meta`, `attack_nodes`, `attack_edges`,
`technique_links`, `graph_snapshots`, `attack_revisions`, `verify_meta`,
`verification_evidence`, `evidence_revocations`, `path_verdicts`.
Assim, nós antecedem arestas/evidências, evidências antecedem revogações e
snapshots/nós antecedem veredictos. Triggers são restaurados depois das linhas,
evitando reexecutar validações de escopo atual sobre histórico de snapshots
anteriores. Índices explícitos são restaurados antes dos triggers.

O rebuild exige tabelas completas e versões 1 de C3/C4; C4 é opcional apenas
quando inteiramente ausente. Exige também os oito triggers C4 esperados por
nome. Verifica `integrity_check` e FKs na origem e no destino. Falhas SQLite,
schema parcial/desconhecido, guards C4 ausentes ou FEASIBLE_PATH sem C4 impedem
a substituição, com erro explícito; o arquivo antigo fica preservado.

Todas as arestas FEASIBLE_PATH são rebaixadas no destino, sem apagar os
veredictos históricos ou modificar seus snapshots. Uma nova execução explícita
de C4 `verify --write`, com raiz de evidências correta, restaura apenas as
promoções atualmente suportadas. PROVEN preexistente é preservado conforme o
contrato C4. Nenhuma alteração foi necessária em `mitr3-graph-verify.py`.

O relatório mantém a chave existente `code_graph_carried`, agora com contagens
C4. O teste C3 de preservação passou a usar PROVEN preexistente; a promoção
FEASIBLE_PATH sem C4 é coberta por novo teste de recusa.

## Verificação executada

Apenas bancos e artefatos temporários, sem rede alvo ou banco operacional:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_graph_verify.py -k RebuildTests -v
8 testes PASS (0.143s na execução final)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_code_graph.py -k StixSeparationTests -v
4 testes PASS (0.027s)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_attack_graph.py -k rebuild -v
1 teste PASS (0.006s)
git diff --check
PASS
python3 bin/mitr3-secrets-audit.py <os cinco arquivos alterados/listados neste relatório>
5 arquivos analisados, 0 hits, 0 exposed_modes
```

Os testes novos verificam duas reconstruções sucessivas, igualdade de linhas
históricas/revisões/snapshots e SQL de tabelas/índices/triggers, guards append-only
e de remoção de nó, FKs, integridade, artefato ausente, promoção posterior,
schema parcial/versão desconhecida, trigger ausente, revogação órfã, WAL,
conflito de índice no destino e exclusão de escritor durante `os.replace`.
Nos erros injetados, `os.replace` não é chamado, SHA256 do banco anterior fica
igual e o temporário é removido. Compatibilidade C3 sem C4, relink e STIX foi
verificada pelos testes selecionados existentes.

## SHA256 e diff

```text
8ead90f4e5fcdf5d28a97c6de5309032df2464ff5cca198a7d1adca268fe29f0  bin/mitr3-attack-graph.py
52ad2a179a3d38d47228a35d3e77704ace1275172ad5007edd96e69f93d53ba5  tests/test_code_graph.py
62d5080b8dea1f6f13d633c7ea3b7ddc35e1f0da823a2e0bcdb8ee75987e2fe5  tests/test_graph_verify.py
08348c9c54e8962fea85c8f0c190f113f66ecb0a19186f9242b3d855b85740d6  docs/MITR3-ATTACK-GRAPH-LAYER4-20261110.md
```

Diff revisável: `git diff -- bin/mitr3-attack-graph.py tests/test_code_graph.py
tests/test_graph_verify.py docs/MITR3-ATTACK-GRAPH-LAYER4-20261110.md`.
Esses quatro arquivos somam 194 inserções e 18 remoções; este relatório é o
quinto arquivo, novo. Sem commit, push, checkout ou edição de skills.

## Limites e riscos residuais

- Parar todos os usuários do banco e fechar suas conexões é pré-condição
  operacional. `BEGIN IMMEDIATE` impede commits concorrentes durante a cópia
  e permanece até a troca; não impede uma conexão antiga de usar posteriormente
  o inode substituído. WAL é recusado sem conversão automática. Não foi testado
  uso concorrente por processos de produção nem comportamento em outros SOs.
- Evidências C4 versão 1 continuam vinculadas aos IDs, sem hash do conteúdo ou
  snapshot de gravação. Uma evidência antiga ainda pode contar após reingest
  sob os mesmos IDs e nova execução de verify; exigir revisão/revogação humana.
  Corrigir isso exige migração explícita e política para evidências antigas,
  ultrapassando uma mudança pequena e segura neste rebuild. Sem integração nova.
- A cópia preserva definições existentes; não autentica schema contra alteração
  administrativa maliciosa. Marcadores/versões e nomes de guards não são uma
  atestação criptográfica de todas as definições SQL.
- Suites C1/C2 e partes não afetadas de C3/C4 não foram reexecutadas. Banco vivo
  não foi aberto nem migrado. QA independente e aceite humano permanecem pendentes.
