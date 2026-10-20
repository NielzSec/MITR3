# Roteamento e intenção — QA de f97d6ab

Base: `f97d6ab`. Esta entrega corrige exclusão automática de fontes e confusão entre papéis de ator e artefatos. Não altera o fixture `intel-relevance-v1.json`, feeds, curadoria, relações ou delta KEV.

## Ranking e aceitação

A busca FTS consulta todas as fontes, salvo `--source` explícito. `routed_source()` só sugere o bônus; não fornece um filtro automático a SQL. Permanecem o corte de cobertura ≥60% e o pool de candidatos por BM25 (mínimo 60, conforme limite solicitado).

Score: `cobertura + 0.5 × (-bm25)/(1 + abs(bm25)) + 0.15 × fonte_sugerida`. BM25 do FTS5 é negativo, menor é melhor. Seu bônus fica abaixo de 0.5; com o bônus de fonte, soma menos de 0.65. Assim, um termo adicional coberto sempre vence a preferência de fonte. Na mesma cobertura, BM25 forte pode superar o viés. O bônus não permite passar pelo corte de cobertura. Testes com documentos controlados verificam cada propriedade.

| Consulta | Resultado no índice real |
|---|---|
| SAP HTTP request smuggling | CVE-2022-22536 em #1 |
| Starlette HTTP request smuggling | CVE-2026-48710 em #1 |
| ASVS HTTP request smuggling | ASVS-V4.2.2 e ASVS-V4.2.1 em #1/#2 |
| cache poisoning | exatamente CASE-ps-practical-cache-poisoning-2018 e CASE-ps-cache-2024; sem ASVS |
| esxi encryptor | vazio |
| LockBit ESXi encryptor | vazio |
| ransomware campaign participant | vazio |
| ransomware source / lockbit builder | intenção permitida; vazios por falta de ficha no catálogo atual |

Os três casos de abstenção são testados também com documentos sintéticos que cobrem literalmente as consultas: a barreira de intenção continua prevalecendo. Os três casos permitidos (`cache poisoning`, `ransomware source`, `lockbit builder`) retornam seus documentos em um índice temporário. Esses documentos não entram no catálogo real nem no fixture do eval. Palavras de artefato não anulam um papel explícito: `lockbit builder operator` ainda pede ator e abstém.

## Padrões de papel e motivos

A intenção usa `casefold` e NFKD para tratar caixa, acentos e versões sem acento. Os padrões completos estão nas constantes `*_RE` e no relatório JSON. As extensões são:

| Padrão | Contexto exigido | Por que é papel, não artefato |
|---|---|---|
| `affiliates?`, `afiliad[oa]s?`, `operators?`, `operador(?:es)?`, `operadoras?`, `participants?`, `participantes?` | ocorrência de substantivo de papel | Descreve afiliação, operação ou participação de pessoa/grupo. `affiliate` e `operator` singulares já eram cobertos; entraram plurais, português e participante. Não inclui `source` ou `builder`. |
| `partners?`, `parceir[oa]s?`, `members?`, `membros?`, `associates?`, `associad[oa]s?` | vocabulário de ameaça/ator/campanha (`THREAT_CONTEXT_RE`) | Descreve pertencimento ou parceria. O contexto evita tratar qualquer uso genérico de “member”/“partner” como atribuição de ameaça. |
| `attributions?`, `atribuicao`, `atribuicoes` | vocabulário de ameaça/ator/campanha | Solicita identidade/responsabilidade de ator, não código ou ferramenta. Inclui ator, C2 e campanha em inglês/português. |
| `campaigns?`/`campanhas?` junto de `who`, `whom`, `quem`, `behind`, `por tras`, `responsavel`, `responsaveis`, `involved`, `involvement`, `envolvid[oa]s?`, `envolvimento` | ambos presentes | Pergunta quem está por trás, responsável ou envolvido na campanha. “Campanha” sozinha não prova pedido de papel: `ransomware campaign source` e `lockbit campaign builder` continuam permitidos. |

`encryptor`/`decryptor` mantêm o gatilho legado de capacidade sem ficha; não foram reclassificados como pessoas. A justificativa retornada agora distingue capacidade de atribuição. `builder` e `source` não são padrões de papel. Isso é um gate lexical limitado; não é um classificador semântico nem um controle de autorização operacional.

## Verificação e métricas

- Suite do repositório: **67/67** (58 anteriores + 9 novos métodos, com subtestes).
- Eval candidate: **recall@5 0.975**, **abstenção 1.000**, hit@5 1.000 e P@5 0.240.
- Precisão dos retornados: **0.935 → 0.917**. Sem filtro automático, `web cache deception` também retorna ASVS-V14.2.5 e `HTTP request smuggling` também retorna CVE-2022-22536. O fixture continua com seus rótulos originais; não foi ampliado para melhorar métricas.
- Fonte explícita ainda restringe resultados; o viés automático deixa CVEs/normas competirem com casos. A ausência de ficha de artefato no índice real continua produzindo vazio.

## Replay dos oito testes adversariais históricos

Executados literalmente a partir do texto de testes guardado na revisão em `/tmp/opencode/build_proposal.py`, contra os módulos atuais; sem aplicar o antigo patch proposto. **2/8 métodos passam**, zero erros de execução. Esse conjunto de propostas nunca integrou o suite verde do repositório. Não removi asserts para inflar o placar.

| Método original | Resultado e causa |
|---|---|
| `test_ambiguous_corpus` | falha somente no assert de que `source=public-cases` deveria retornar vazio para SAP. Os três alvos cruzando fontes são encontrados. Com cobertura de 60%, o filtro explícito permite quatro casos genéricos; o teste antigo assumia AND. O teste novo verifica o contrato atual: filtro explícito respeitado, automático sem exclusão. |
| `test_query_framing_preserves_target` | falha somente em `Faultline writeup`; normalização de writeup/write-up continua pendente. |
| `test_no_unknown_identifier_or_content_fallback` | passa |
| `test_semantics_after_token_15_are_preserved` | a consulta longa com `ransomware partner` agora abstém, mas falha no assert adicional de que 65 termos deveriam lançar ValueError. Limite/truncamento de tokens não foi alterado. |
| `test_delta_tracks_unpersisted_fields` | falha: descrição, CWE e notas seguem fora do snapshot do delta |
| `test_duplicate_ids_rejected` | falha na função isolada de snapshot; o build do fluxo completo continua rejeitando duplicatas |
| `test_snapshot_schema_migration_rebaselines` | falha: migração do snapshot KEV não foi implementada; schema 2 da tabela de relações é independente |
| `test_order_and_20k` | passa |

Separadamente, as **oito consultas legítimas** da revisão anterior acertam **7/8**; a única pendente é `Faultline writeup`. As dez paráfrases curtas agora retornam vazio **10/10** (antes 9/10), sem atribuir esse resultado inteiro ao gate: consultas de artefato sem ficha também ficam vazias por recuperação lexical. A consulta longa de parceiro de ransomware abstém pelo padrão de papel contextual.

Resultados por consulta, regex completos, hashes dos insumos e placar em `reports/intel-routing-intent-v1-qa.json`. Log literal da suíte histórica: `/tmp/opencode/routing-intent/eight-original-tests.log`.
