# MITR3 — Camada 4: evidências e verificação

Data: 2026-11-10. Implementação: `bin/mitr3-graph-verify.py`.
Testes: `tests/test_graph_verify.py`. Apenas biblioteca padrão, processamento
local/offline; não envia tráfego, não executa o artefato e não aprova findings.

## Contrato e armazenamento

A C4 lê cadeias SOURCE → FINDING → SINK do banco da Camada 3 e registra
as bases da decisão, preservando os nós e as arestas. O banco padrão é
`state/mitr3-attack.sqlite3`. Não usar o SQLite produzido diretamente pelo
normalizer da C2: primeiro executar o ingest da C3.

As tabelas próprias são `verify_meta` (versão `1`), `verification_evidence`,
`evidence_revocations` e `path_verdicts`. Escritas inicializam o schema C4;
`verify` sem `--write` e `list` exigem inicialização anterior e não escrevem.
Schemas C4 incompletos, desconhecidos ou sem marcador são recusados.
Para avaliar um grafo ainda sem evidências, usar `verify --write` para
inicializar a C4. Essa operação também persiste os veredictos estruturais.

Evidências, revogações e veredictos são append-only por triggers de UPDATE e
DELETE. Os vínculos de evidência são conferidos contra a estrutura do grafo:
finding do tipo FINDING, mitigação ligada por MITIGATED_BY e endpoints ligados
por FLOWS_TO/CALLS. Nós referenciados não podem ser removidos. As conexões de
escrita ativam foreign keys. O mecanismo não protege contra um administrador
que remova os triggers ou substitua o arquivo SQLite.

## CLI

Opções globais ficam **antes** do subcomando:

```bash
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 --evidence-root /tmp/artifacts record /tmp/evidence.json
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 --evidence-root /tmp/artifacts list
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 --evidence-root /tmp/artifacts verify --json
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 --evidence-root /tmp/artifacts verify --write --json
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 revoke EVIDENCE_ID --reason 'análise substituída' --by operador
python3 bin/mitr3-graph-verify.py --db /tmp/graph.sqlite3 --evidence-root /tmp/artifacts verify --exposure unauthenticated
```

`record`, `revoke` e `list` retornam JSON. `verify` retorna um resumo textual;
`--json` inclui todas as cadeias, bases, contagens, problemas e limites.
`--exposure` aceita `any`, `unauthenticated`, `authenticated` e `unknown`, sem
distinguir maiúsculas/minúsculas. Não combinar filtro com `--write`: uma escrita
parcial poderia rebaixar arestas de cadeias omitidas. Exposição vem do booleano
`metadata.authenticated` do SOURCE; valor ausente resulta em UNKNOWN.
Sucesso retorna `0`; erro de argumento, validação, arquivo ou SQLite retorna `2`
com mensagem em stderr.

## Formato da evidência

Exemplo AST (substituir os IDs pelos existentes no banco):

```json
{
  "kind": "AST_REACHABILITY",
  "finding_id": "fnd:exemplo",
  "source_id": "src:exemplo",
  "sink_id": "snk:exemplo",
  "verdict": "REACHABLE",
  "artifact": "reports/ast-analysis.txt",
  "analyzer": "analisador offline / versão",
  "justification": "Descrever a análise e suas limitações",
  "recorded_by": "operador"
}
```

AST aceita `REACHABLE` ou `UNREACHABLE`, sem `strength` nem `mitigation_id`.
SOURCE/SINK são opcionais para AST; omiti-los amplia a aplicação ao finding.
IaC exige `kind: IAC_CONTROL`, `mitigation_id` ligado ao finding, `strength`
numérico e `applies_to` como objeto de strings:

| Veredicto IaC | Requisitos |
|---|---|
| `REDUCES` | `0 <= strength < 1`, `applies_to.environment` preenchido |
| `BLOCKS` | `strength = 1`, SOURCE e SINK exatos, `applies_to.environment`, `flow`, `identity`, `condition` preenchidos |

`artifact` aponta para arquivo físico sob `--evidence-root` (padrão: raiz do
checkout). Caminhos absolutos dentro da raiz são normalizados para relativos.
São rejeitados arquivos ausentes, diretórios, escapes por `..` ou symlink,
caminhos `.git` e arquivos acima de 256.000.000 bytes.
O SHA-256 é calculado pelo programa; o JSON não pode fornecer um hash declarado.
Campos desconhecidos, JSON não finito e pares kind/verdict inválidos são recusados.

O ID é SHA-256 do registro canônico, incluindo conteúdo, escopo, justificativa,
analisador, caminho e hash do artefato, sem autor/timestamp. Registro idêntico
retorna `already_recorded` e preserva o primeiro autor. Revogar exige motivo e
autor; mantém o histórico. Repetir `record` não reativa uma evidência revogada.

Cada `verify`/`list` revalida os artefatos e hashes. Apenas evidências não
revogadas com artefato `VERIFIED` contam. `HASH_MISMATCH`, `MISSING`, escape da
raiz e demais problemas aparecem na saída e deixam de influenciar o resultado.
Um hash comprova integridade do arquivo observado, não a verdade da análise.

## Resultados e promoção

A precedência para cada cadeia é:

| Resultado | Condição |
|---|---|
| `CONFLICT` | REACHABLE e UNREACHABLE válidos, ou REACHABLE com `ast_gate` negativo |
| `AST_UNREACHABLE` | UNREACHABLE válido ou `ast_gate` negativo, sem conflito |
| `SUPPRESSED_BY_IAC` | BLOCKS válido para SOURCE e SINK exatos, sem condição anterior |
| `ACTIVE` | Demais casos, inclusive mitigação apenas declarada pela C2 |

`ast_gate` aceita `0`/`1`, booleanos e strings `FAIL`/`PASS`. É uma checagem
sintática de linha, não prova de alcançabilidade: a decisão baseada somente no
gate permanece `STRUCTURAL_HYPOTHESIS` e sua origem aparece na base AST.
Somente ACTIVE com evidência REACHABLE válida recebe `FEASIBLE_PATH`.
**A C4 nunca atribui PROVEN**; eventual estado PROVEN preexistente em arestas
é preservado, sem transformar o veredicto calculado em prova.

Confiança é um score de ordenação, não probabilidade:

```text
0,30 × (agreement_ratio × min(scanner_count, 3) / 3)
+ 0,25 × (ast_gate positivo)
+ 0,45 × (REACHABLE verificado)
```

Entradas numéricas inválidas usam os defaults conservadores do módulo; contagem
de scanners inválida assume 1, agreement_ratio inválido assume 0. Resultados
são arredondados a quatro casas decimais. Para cada mitigação usa-se a maior
força comprovada; entre mitigações, `strength = 1 - produto(1 - força)`.
Isso **assume independência dos controles**. Exploitability é
`confidence × (1 - strength)` para ACTIVE e zero para outros resultados.

`verify --write` grava veredictos e promove as arestas FLOWS_TO/CALLS dos
caminhos viáveis numa transação `BEGIN IMMEDIATE`. Arestas FEASIBLE_PATH sem
suporte atual são rebaixadas para STRUCTURAL_HYPOTHESIS. O histórico não é
apagado. Snapshot estrutural + endpoints + fingerprint de evidências válidas
identificam o veredicto, permitindo repetição idempotente. A promoção em si
não altera o hash estrutural do grafo. Findings sem SOURCE/SINK aparecem em
`unanchored_findings`, sem criação de cadeia artificial.

## Limites operacionais conhecidos

- O escopo textual environment/flow/identity/condition é registrado, mas não
  confrontado com um inventário externo de ambientes. Usar banco/raiz de
  evidências coerentes com o contexto aprovado pelo operador.
- Evidências se vinculam aos IDs dos nós, sem fixar o hash de conteúdo/snapshot
  na gravação. Reingest que muda o conteúdo sob os mesmos IDs exige revisão e
  revogação das evidências antigas; hash do artefato inalterado não garante
  que a evidência ainda se aplique ao código novo.
- O rebuild STIX agora preserva C3 e C4, incluindo histórico, índices e triggers.
  Requer parada dos usuários do banco e conexões fechadas antes de iniciar;
  mantém `BEGIN IMMEDIATE` no arquivo antigo até a substituição e recusa WAL,
  sem converter journal mode automaticamente. Conexões antigas abertas podem
  continuar apontando ao inode substituído: o lock não substitui essa parada.
  Schemas incompletos/versões desconhecidas, ausência dos triggers C4 esperados,
  falhas de integridade/FKs e conflitos na cópia impedem `os.replace`, preservando
  o banco anterior. A cópia usa uma transação estável da origem, cria as tabelas,
  copia pais C3 antes de filhos C4 e restaura índices/triggers por último; a guarda
  C4 de `attack_nodes` também é preservada. Histórico não é revalidado contra o
  grafo atual, pois pode representar snapshots anteriores.
  Todas as arestas FEASIBLE_PATH voltam a STRUCTURAL_HYPOTHESIS no rebuild:
  o rebuild não conhece a raiz dos artefatos para revalidar sua aplicabilidade.
  Veredictos históricos e PROVEN preexistente são preservados; executar
  `verify --write` com a raiz correta antes de usar novas promoções. C3 sem C4
  continua suportada, mas FEASIBLE_PATH sem histórico C4 provoca recusa explícita.
  O campo de relatório `code_graph_carried` inclui as contagens das tabelas C4.
- As tabelas são append-only, mas a chave de veredicto usa apenas evidências
  válidas. Se diferentes problemas de evidência produzirem o mesmo conjunto
  válido e o mesmo snapshot, o novo diagnóstico será visível na consulta, mas
  não gerará outra linha histórica para a mesma chave.
- Verificação de caminho, tamanho e hash não bloqueia alterações concorrentes
  do sistema de arquivos; realizar avaliação sobre artefatos estáveis.

## Validação

```bash
python3 -m unittest discover -s tests -p test_graph_verify.py -v
```

Resultado executado nesta entrega: **34/34 testes passaram (100%)**, sem falhas,
erros ou skips.

A suíte exercita schema, triggers append-only, escopo exato entre cadeias,
validação/registro idempotente, revogação, integridade viva dos artefatos,
os quatro resultados, confiança, filtros, promoção/rebaixamento, preservação
de PROVEN preexistente, rollback e CLI em subprocessos. Usa bancos e artefatos
temporários, sem banco operacional nem rede. C1/C2/C3 não são reexecutadas;
C3 é usada como produtora do banco real da fixture.

A revisão independente desta entrega examina código, testes e documentação;
aceite operacional humano e custódia Git permanecem com operador/VANTA.
