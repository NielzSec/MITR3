# C1/C2 — correções de staging offline, 2026-11-11

Implementação local para revisão, sem aceite operacional. QA independente será feita pelo coordenador depois deste handoff.

## Escopo e leituras

Worktree: `/home/nielz/orca/workspaces/MITR3/graph-c1-c2-fixes`.
Lidos AGENTS.md, Ponytail de `/home/nielz/MITR3/skills/ponytail/SKILL.md` e o canal Slack #all-mitr3 (35 mensagens recentes, incluindo os registros de C1/C2 e achados C3).
Referência de achados: https://mitr3.slack.com/archives/C0C9ZLLU094/p1794362313338889
Referência de auditoria pós-release: https://mitr3.slack.com/archives/C0C9ZLLU094/p1794366205094269
A tarefa atual autoriza as correções locais; o handoff anterior no Slack descrevia uma etapa de auditoria somente leitura.

Nenhum commit, push, checkout, migração operacional, acesso ao banco operacional ou tráfego de alvo foi realizado. Nenhum SKILL.md foi criado/revisado; sem workers auxiliares. C1, C3 e C4 não tiveram runtime alterado.

## Diff entregue

Patch completo dos três arquivos de código/testes: [MITR3-GRAPH-C1-C2-FIXES-20261111.patch](MITR3-GRAPH-C1-C2-FIXES-20261111.patch).
Também disponível com `git diff -- bin/mitr3-graph-normalizer.py tests/test_graph_normalizer.py tests/test_code_graph.py`.

- SINK compartilhado não recebe mais a linha do finding; a linha permanece no FINDING. Endpoints SOURCE/SINK repetidos precisam ter conteúdo idêntico, ou a ingestão falha por conflito, sem escolher o último. Testes cobrem ordem reversa, conflito explícito e ingestão dos dois exports pela C3.
- SQLite direto usa UPSERT, sem REPLACE nem ON DELETE CASCADE. CHECKs validam IDs, tipos, linha, hash, JSON e peso; triggers INSERT/UPDATE exigem endpoints existentes com a forma correta. DELETE de nó referenciado e alteração de identidade são bloqueados mesmo com foreign_keys desligado. DELETE de aresta e DELETE posterior do nó não referenciado continuam permitidos.
- Schema novo recebe `c2_graph_meta`, versão 1. Bancos preexistentes sem esse marcador/versão são recusados antes de qualquer DDL ou materialização de evidência. Não há migração automática de bancos C2 antigos nem adoção do banco C3. Escritas no banco são transacionais; falha de aresta reverte também os updates de nós.
- GraphEdge rejeita pesos fora de [0,1], booleanos e números não finitos. Multiplicadores não são clampados. Valores exatamente 0 e 1 continuam aceitos.
- `sink_pattern` e `enclosing_function` deixam de gerar SINK: representam trecho de scanner ou contexto, não destino de fluxo confirmado. Campos explícitos `sink_function`/`sink` continuam aceitos para entradas enriquecidas; SOURCE continua condicionado a `source_entrypoint`/`source`/`entrypoint` explícito.

## Proveniência física e contrato de hashes

A CLI passa o arquivo físico como `artifact_path` tanto para SARIF quanto para findings/report/lista. FINDING e arestas derivadas usam SHA-256 dos bytes exatos desse arquivo, incluindo whitespace. A API verifica se o dado recebido pertence ao documento físico informado antes de aceitar a associação.

`export_jsonl` e `persist_sqlite` materializam cópias identificadas por conteúdo em `evidence/<evidence_sha256>`, relativo ao diretório do JSONL ou do banco C2. `metadata.evidence_artifact` fornece esse caminho relativo; `metadata.evidence_kind=C2_INPUT_ARTIFACT` identifica cópia dos bytes do documento físico. Se JSONL e SQLite forem para diretórios diferentes, cada diretório recebe seus artefatos.

A API sem `artifact_path` preserva compatibilidade por snapshots físicos dos dados de entrada, com `evidence_kind=C2_INPUT_SNAPSHOT`. Os bytes são JSON ordenado em UTF-8 para objetos, ou UTF-8 literal para strings; a gravação ocorre no export/persist, não na ingestão em memória. SOURCE/SINK/MITIGATION usam esses snapshots dos seus descritores de entrada, evitando vincular a identidade compartilhada ao finding processado por último. Esses snapshots demonstram o dado fornecido ao normalizador; não demonstram execução, reachability nem falha no alvo. Não se apresentam como arquivo original do scanner.

O export/persist recusa digest manual sem bytes correspondentes e recusa sobrescrever artefato existente alterado. A pasta `evidence` é aberta com descritor relativo e `O_NOFOLLOW`; diretórios com symlink, dono diferente ou modo diferente de 0700 são recusados. A pasta pai precisa pertencer ao usuário e não ser gravável por grupo/outros. Arquivos novos são criados com `O_EXCL|O_NOFOLLOW` e modo 0600; arquivos já existentes são abertos sem seguir symlinks e precisam ser arquivos regulares do usuário com modo 0600. Isso mantém a gravação ancorada no diretório validado mesmo se o nome for trocado durante a abertura. O SHA é dos bytes do artefato físico; não é o `content_sha256` da entidade canônica C3 nem hash de snapshot do grafo C3/C4. C3/C4 continuam responsáveis por seus próprios contratos de conteúdo/verificação; nenhuma evidência C2 promove estado de verificação automaticamente.

Mudanças no formato/whitespace do relatório físico mudam sua proveniência, mesmo quando o JSON parseado é equivalente. Isso é intencional. Os snapshots de descritores compartilhados permanecem determinísticos entre arquivos e ordens.

## Contrato C1 → C2 e limites reais

O dataclass `EvaluatedFinding` da C1 contém local, regras, scanners, consenso, ast_gate/ast_details, mitigações e scores. Não contém source_entrypoint, sink_function, sink_pattern ou enclosing_function. `CandidateFinding.sink_pattern` pode vir de `extra.lines` do Semgrep e não é propagado pelo evaluator. Texto de ast_details não é um contrato de dataflow.

Portanto a C1 atual não fornece dados suficientes para produzir SOURCE→FINDING→SINK com fidelidade. Não foi inventado endpoint a partir de função envolvente, chamada em texto diagnóstico ou snippet. O novo teste de contrato executa o evaluator C1 real sobre uma fixture Python local com chamada válida e confirma que seu resultado permanece sem SOURCE/SINK na C2. Não foi necessário alterar a C1.

A busca local de nomes em reports/state não encontrou export de harness/SARIF para comprovar um fluxo real; apareceu somente o relatório de QA do attack graph. Validação de SOURCE/SINK em dados reais continua NÃO VERIFICADA. Entradas enriquecidas e fixtures que declaram os endpoints sustentam apenas hipóteses estruturais, não prova de fluxo.

## Verificação executada

Comandos finais (só C2 e seu contrato afetado com C3):

```text
python3 -m unittest discover -s tests -p test_graph_normalizer.py
Ran 36 tests in 0.199s — OK
python3 -m unittest discover -s tests -p test_code_graph.py
Ran 25 tests in 0.398s — OK
git diff --check
exit 0
python3 bin/mitr3-secrets-audit.py bin/mitr3-graph-normalizer.py tests/test_graph_normalizer.py tests/test_code_graph.py
3 arquivos, 0 hits, 0 exposed_modes
```

C2 tem 16 testes adicionais, com subcasos para limites de multiplicador, SQL com foreign_keys ON/OFF, UPDATE/DELETE/INSERT, rollback, UPSERT parcial, bytes físicos, SARIF CLI, vínculo documento/dado, adulteração de artefato, symlink na pasta/arquivo de evidência e falta de artefato. O teste afetado de C3 agora exige aceitação de SINK compartilhado consistente, em vez de exigir a falha antiga.

Durante desenvolvimento: os 20 testes C2 originais passaram; depois 32 passaram; uma execução C3 falhou porque o teste novo desempacotava dois valores de load(), que retorna três. O teste foi corrigido e C3 passou 25/25; a versão final C2 passou 34/34 após adicionar rollback/artefato ausente e ampliar subcasos SQL. Não houve falha de runtime remanescente nesses testes. O comando de auditoria chamado com `--help` foi tratado pelo script como um caminho inexistente (zero arquivos); esse resultado não foi usado como validação, e a auditoria foi executada depois com caminhos reais.

C1 não foi retestada integralmente porque seu runtime não mudou; só o caminho evaluator→C2 afetado foi exercitado. C4, attack-graph rebuild, concorrência, crash/fsync e datasets operacionais não foram testados. Os testes de SQL usaram apenas bancos temporários. A revisão adicional de symlink executou somente o módulo C2 afetado; o contrato C2→C3 não mudou nessa revisão.

## Riscos e pendências

- QA independente e aceite humano permanecem pendentes; não há autorização de release/promoção neste handoff.
- Bancos C2 legados precisam de uma decisão de migração separada; esta mudança falha com segurança e solicita um banco novo de staging.
- Novos metadados de proveniência e semântica CLI de evidence_sha256 mudam conteúdo/digests consumidos pela C3; reingestão posterior pode gerar revisões e voltar arestas ao estado estrutural. Nenhuma reingestão operacional foi feita.
- Copiar só JSONL/SQLite perde os artefatos: transportar também o diretório evidence. Inputs físicos completos podem conter dados sensíveis; mantê-los sob a mesma custódia dos relatórios originais. Nenhum input real foi copiado nesta tarefa.
- Transação SQLite não inclui filesystem: uma falha pode deixar artefatos não referenciados, sem sobrescrevê-los nem efetivar alterações parciais no banco.
- A proteção contra troca de symlink ancora a escrita num descritor de diretório e rejeita pais graváveis por grupo/outros. Processos com o mesmo UID do agente compartilham a mesma autoridade local; essa proteção não pretende isolar processos hostis do mesmo usuário.
- Os valores default de mitigação string e a modelagem de IaC preexistentes não foram redesenhados. MITIGATED_BY isolado continua sem provar bloqueio.

## SHA-256

Código/testes, patch e C1 consultada sem edição:

```text
42304859bb5eb0d4a1f0600cdb551283c1bc15e1497c549fd5e7abbe504e67dc  bin/mitr3-graph-normalizer.py
cde72271fea5045f0520318e3ff7d4b053188be0d2da92b3d4e885c8d6d0de07  tests/test_graph_normalizer.py
8ac0dd78e29cadb3ee64fe0929eb7141df7647d0053107a833dc3c155f695b92  tests/test_code_graph.py
ecd9bfca7a2b219453ee21df4f70e8427993b4ce41a1e409bc4f44076114f221  docs/MITR3-GRAPH-C1-C2-FIXES-20261111.patch
6f684bf43fe5e95e11ea793cc525da56b93aef8c1d5b446fdbb5639cae800209  bin/mitr3-vuln-harness.py
```

O SHA deste relatório é retornado no handoff para evitar autorreferência. Não há hashes de banco operacional porque ele não foi aberto nem copiado.
