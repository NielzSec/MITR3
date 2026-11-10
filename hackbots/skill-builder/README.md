# MITR3 Skill Builder v0.2 — geração e avaliação offline de saídas
**Estado:** piloto experimental. Cria um **rascunho não aprovado** de skill. Nenhuma promoção automática, instalação, shell do agente, rede, custo de tokens, execução de scripts da metodologia ou escrita no MegaBrain.

## Fontes técnicas verificadas
- Agent Skills — https://agentskills.io/specification : frontmatter, nome igual à pasta, conteúdo sob demanda.
- Trail of Bits fp-check — https://github.com/trailofbits/skills/blob/main/plugins/fp-check/README.md : verificação sistemática e gates por achado.
- Trail of Bits c-review — https://github.com/trailofbits/skills/blob/main/plugins/c-review/README.md : cobertura medida pelo parser/ledger, com isolamento do verificador e revisores.
- OpenAI — https://developers.openai.com/blog/eval-skills : avaliações de processo, resultado, estilo e custo comparadas por versão.

## Comandos (não enviam tráfego)
Execute no diretório `~/MITR3`:

```sh
python3 hackbots/skill-builder/skill_builder.py new hackbots/skill-builder/examples/js-inventory.method.json
python3 hackbots/skill-builder/skill_builder.py audit mitr3-hb-js-inventory-candidate
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/skill-builder/tests -v
```

Se a candidata já existir, use `audit`: `new` continua recusando sobrescrita.

## Pipeline
`methodology.json (proposta + origem/hash) -> new -> drafts/<name>/{SKILL.md, methodology.json,manifest.json} -> audit -> REVIEW`

O método define **um objetivo**, entradas, saída, passos atômicos identificados, evidências exigidas, ferramentas declaradas, condições de parada e casos positivos/negativos. Todos ficam visíveis no arquivo gerado, sem sumir por resumo de LLM. O builder mede a cobertura **da geração** por IDs, não a execução semântica da skill.

Um `structural_gate: PASS` significa que nenhum passo/caso foi omitido da geração e que os arquivos são consistentes com os hashes apresentados. Os hashes **não autenticam autoria nem bloqueiam alterações coordenadas** da metodologia, skill e manifesto. Uma âncora externa revisada é necessária para detectar essa substituição. `state: REVIEW` significa: **faltam ensaios comportamentais reais e aprovação humana**. Nunca significa encontrar vulnerabilidade, obter bounty ou estar pronto para produção.

## Skill Evaluator: resultados observados contra oráculo independente

`skill_evaluator.py` lê uma suíte e um pacote de saídas já produzidas. Confere os arquivos originais e seus SHA256, verifica todos os casos declarados na metodologia e compara cada saída JSON inteira com um resultado esperado. A suíte/oráculo precisa ser elaborada e revisada independentemente do produtor; o programa não autentica essa independência.

Exemplo reproduzível, após criar ou auditar a candidata acima:

```sh
python3 hackbots/skill-builder/skill_evaluator.py mitr3-hb-js-inventory-candidate \
  hackbots/skill-builder/examples/evaluator/suite.json \
  hackbots/skill-builder/examples/evaluator/run.json

# Regressão intencional: E01 perdeu o endpoint; retorna código 1.
python3 hackbots/skill-builder/skill_evaluator.py mitr3-hb-js-inventory-candidate \
  hackbots/skill-builder/examples/evaluator/suite.json \
  hackbots/skill-builder/examples/evaluator/regressed-run.json \
  --baseline hackbots/skill-builder/examples/evaluator/run.json
```

As entradas são sintéticas: rota literal, solicitação com hash incorreto e comentário contendo instrução não confiável. **As saídas `.observed.json` foram escritas à mão para demonstrar o verificador. Não são traces nem execuções de agente.** O caso de comentário só demonstra igualdade do resultado final; não comprova resistência a prompt injection ou ausência de tráfego.

### Fixar a suíte com um hash externo

O revisor pode fornecer `--suite-sha256 DIGEST_REVISADO` ao avaliador. O hash deve vir de um registro separado, previamente conferido pelo revisor. Uma divergência retorna `BLOCKED` e código 2, inclusive se alguém atualizar simultaneamente oráculos, suíte e pacote de saídas para torná-los consistentes entre si.

O relatório informa `suite_pin: MATCH` ou `NOT_PROVIDED`. A opção é compatível com os pacotes atuais. Calcular o hash da suíte atual automaticamente e passá-lo na mesma execução não oferece uma âncora independente. `MATCH` não autentica o revisor, não aprova a metodologia e não comprova execução.

Nas comparações com baseline, `regression.persistent_failures` lista casos que falham nas duas versões; `baseline_outputs_passed` e `baseline_outputs_evaluated` mostram a qualidade da baseline. `regression.state: PASS` significa somente ausência de novas regressões: o `output_gate` geral continua `FAIL` enquanto houver qualquer saída divergente.

### Contratos (JSON estrito, sem campos extras)

Todos os caminhos são relativos à raiz MITR3. Uma referência de arquivo tem `path` e `sha256`; seu hash deve corresponder aos bytes originais, inclusive espaços e quebras de linha.

| Arquivo | Campos obrigatórios |
| --- | --- |
| Suíte | `schema_version: 1`, `cases` |
| Caso da suíte | `id` (`Exx`), `kind` (`positive`/`negative`), `step_ids` (`Mxx`), `input` (referência), `expected` (referência de JSON) |
| Pacote de saídas | `schema_version: 1`, `name`, `method_sha256`, `skill_sha256`, `suite_sha256`, `cases` |
| Caso observado | `id`, `input_sha256`, `output` (referência de JSON) |

Use os hashes de método e skill retornados por `audit`. A suíte deve corresponder exatamente aos IDs e tipos de casos da metodologia, e mapear todas as etapas, sem inventar IDs. Cada caso, inclusive negativo, exige uma saída real em arquivo; saída ausente nunca significa bloqueio correto. O hash do input observado deve coincidir com a fixture da suíte.

A comparação ignora ordem de chaves e espaços JSON; exige igualdade de conteúdo, ordem de arrays e tipos (`false`, `0` e `0.0` são distintos). Decimais preservam sua precisão; `1.0` e `1.00` têm o mesmo valor decimal. Chaves duplicadas, números não finitos, arquivos especiais, arquivos acima de 1 MB e symlinks são rejeitados. Nenhum comando, expressão ou script informado na suíte é executado.

`--baseline` reavalia os arquivos da versão anterior, incluindo a auditoria de sua própria candidata e os hashes do método e skill. Ambas precisam usar **a mesma suíte byte a byte**. Não aceita um relatório `PASS` como prova. Comparações usam somente os artefatos apresentados: não autenticam quando/como eles foram produzidos.

| Campo de resultado | Significado |
| --- | --- |
| `output_gate: PASS` | Todas as saídas JSON conferem com os oráculos apresentados |
| `steps_with_passing_outputs` | União dos IDs mapeados pela suíte aos casos aprovados; não prova execução de passos |
| `outputs_evaluated` / `outputs_passed` | Casos efetivamente comparados / iguais ao esperado |
| `regression` | IDs que passaram a falhar ou melhoraram; `NOT_COMPARED` sem baseline |
| `evals_executed: 0`, `behavioral_gate: NOT_RUN` | Nenhum agente foi executado ou comportamento monitorado |
| `human_approved: false`, `promotable: false` | Revisão humana e promoção permanecem pendentes |

O relatório registra hashes da suíte, pacote, método, skill, verificador e arquivos de cada caso, sem copiar o conteúdo das saídas. Para preservar evidência local, redirecione stdout para um arquivo **novo fora de `drafts/<nome>/`** e registre seu SHA256 em um armazenamento controlado pelo revisor. O avaliador não altera rascunhos, saídas nem baselines. Relatórios e hashes sob controle do mesmo usuário não são um log autenticado ou imutável.

Códigos de saída: `0` = comparação completa aprovada, ainda em `REVIEW`; `1` = saída divergente (`FAILED`); `2` = contrato/arquivo/hash inválido (`BLOCKED`). Uma entrada inválida invalida toda a avaliação; não há aprovação parcial.

## Política de promoção (ainda não implementada)
O [Execution Verifier](../docs/EXECUTION-VERIFIER.md) implementa consistência e cobertura
de bytes; o runner sintético integrado está em `../runner/README.md`. O contrato
também descreve requisitos ainda pendentes de custódia independente e aceite.

**Não há comando `promote`** nesta versão. A próxima fase deverá exigir:
1. runner isolado com instrumentação confiável, testes positivos/negativos e experimentos com modelos, com evidências e traces reais;
2. verificação de cobertura por *unidades reais de entrada* (não por checkbox), com oráculo independente;
3. avaliação de regressões (comparar versão atual com versão candidata sob mesmos casos);
4. revisão independente do conteúdo da metodologia e das afirmações, separada do agente produtor;
5. decisão humana externa ao processo agente (não basta um campo JSON `approved: true`), versão e backup;
6. só então autorização explícita para copiar o artefato ao catálogo oficial de skills.

**Restrições v0.2:** somente arquivos regulares sob `~/MITR3`, sem symlinks, limite de 1 MB por arquivo, skills geradas <=200 linhas, toolbox offline read-only e Python stdlib. O leitor usa descritores de diretório e `O_NOFOLLOW` no Linux. O diretório do projeto deve permanecer sob controle do operador: não é uma sandbox contra processos hostis com o mesmo usuário, nem protege contra hardlinks ou alterações concorrentes de conteúdo. Não validar projetos privados ou amostras sensíveis por upload a modelos. O valor `allowed_tools` escrito no SKILL.md **não configura permissões do OpenCode**. Não executar tarefas de bug bounty sem escopo humano específico.

O formato de rascunho v0.1 foi preservado; não é preciso regenerar candidatas existentes. A v0.2 adiciona validação estrita e avaliação externa de saídas. Entradas antigas malformadas antes toleradas agora são bloqueadas.

Os arquivos de candidatas em `drafts/` ficam ignorados pelo Git; somente `drafts/.gitkeep` preserva o diretório vazio necessário em um checkout novo; metodologias de exemplo, ferramenta e testes são versionáveis após revisão.
