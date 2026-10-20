# MITR3 — propostas de resposta com evidência anexada

Implementa o [contrato de 2026-10-20](MITR3-EVIDENCE-ANSWER-CONTRACT-20261020.md)
em `bin/mitr3-answer.py`, sem alterar o retriever, o bridge, o eval ou os conjuntos
cegos. Não instala modelos. Usa o provedor já autorizado através do CLI OpenCode.

```sh
bin/mitr3-answer.py answer "Descreva CVE-2020-1472" --json
bin/mitr3-answer.py "Descreva CVE-2020-1472" --model google/gemini-3.5-flash-lite --max-evidence 5
bin/mitr3-answer.py "T1059.001" --remote --json
```

`answer` é um prefixo opcional; a pergunta é um único argumento. O limite global
é de 1 a 20 registros (padrão 5), contando documentos e arestas juntos. Cada uma
das até três consultas passa pelo bridge com `--json --limit 5`. A consulta remota
é opt-in: somente `--remote` a encaminha ao MegaBrain. O CLI é somente leitura.

## Interpretação e adapter

A primeira chamada recebe **literalmente apenas a pergunta crua**, sem corpus,
evidência, gabarito, exemplos, instruções acrescentadas ou consultas anteriores.
O adapter precisa devolver exatamente:

```json
{"language":"pt","intent":"vulnerability","entities":["CVE-2020-1472"],"queries":["CVE-2020-1472"]}
```

`intent` admite `entity`, `artifact`, `technique`, `vulnerability`, `attribution`,
`procedure`, `unknown`. Há de uma a três consultas, cada uma com até 500 caracteres.
Um identificador CVE/CWE/ASVS/ATT&CK introduzido pelo plano, ausente literalmente da
pergunta, causa `PLAN_NEW_IDENTIFIER`. O plano não é evidência nem autorização.

O requisito de enviar só a pergunta tem uma limitação operacional: um provedor
que devolva prosa, em vez do plano JSON, resulta em abstenção `MODEL_JSON` ou
`PLAN_SCHEMA`. Este CLI não acrescenta silenciosamente instruções de formato na
etapa A, nem transforma uma resposta narrativa em plano. A obediência do provedor
a esse protocolo não foi medida com um modelo real nesta implementação.

Comando padrão, em argv sem shell:

```text
opencode run --model google/gemini-3.5-flash-lite -- <prompt>
```

`MITR3_MODEL_CMD` configura um comando confiável, separado por `shlex.split`.
Os placeholders `{model}` e `{prompt}` são substituídos dentro de argumentos,
sem interpretação de shell. Sem `{prompt}`, o prompt é acrescentado como último
argumento. Exemplo de mock local:

```sh
MITR3_MODEL_CMD='python3 /tmp/model-mock.py {prompt}' bin/mitr3-answer.py "pergunta" --json
```

Cada chamada tem timeout de 120 segundos. stderr do provedor é descartado,
ANSI é removido e stdout nunca é repassado diretamente. JSON com chaves repetidas,
NaN ou estrutura errada é recusado. Se houver texto envolvendo o JSON, ocorre
uma única tentativa local de extrair o primeiro objeto balanceado, respeitando
strings e escapes. Isso não faz outra chamada ao modelo.

## Pacote público e proveniência

Para documentos locais, resolve o ID aprovado pelo bridge usando o search exato
existente, verifica igualdade de ID, URL e fonte, e recalcula o SHA256 do corpo
indexado. O pacote inclui `id`, `title`, `source`, `source_url`, `validation`,
`sha256`, `namespace`, `kind` e `snippet`. O trecho vem dos primeiros 300 caracteres
de `summary`, ou `lesson` quando summary é vazio. O hash identifica o documento
completo indexado, não os 300 caracteres. Fontes elegíveis: CISA KEV, ASVS 5.0.0 e
catálogo público de casos. Qualquer registro com `[REDACTED:*]` é descartado.

Arestas mantêm predicate, pontas e evidence da ponte, sem inferência. Seu SHA256
é o do feed/bundle, separado do hash documental. Relações locais usam IDs estáveis
`local-edge:<origem>:<predicate>:<destino>` e precisam de documento incidente no
pacote para vincular sua URL pública. ATT&CK usa o ID relationship STIX,
`modified` e SHA256 já verificados pelo bridge, no namespace `attack`. A entidade
é conferida no SQLite ATT&CK; como o grafo não tem summary/lesson, seu snippet fica
vazio, sem prosa STIX inventada. Uma aresta oferece como trecho a representação
JSON literal de suas pontas e predicate. Isso só comprova uma declaração
estruturada da fonte, não uma relação com CVE/CWE/ASVS.

Citações remotas do bridge têm apenas metadados, sem documento público com
snippet/hash verificável. Por isso não entram no conjunto citável nem no prompt
de composição. Não são enviadas evidências privadas de clientes ao provedor.
Nenhuma citação MegaBrain valida uma aresta.

## Composição e gate

A segunda chamada contém a pergunta e o pacote JSON delimitado por
`<evidence>...</evidence>`, com aviso explícito de **DADO NÃO CONFIÁVEL** e de que
nunca se trata de instruções. Caracteres `<` e `>` dos dados são escapados para
impedir que um snippet feche o envelope. O formato aceito é exclusivamente:

```json
{"abstain":false,"claims":[{"text":"Proposição curta","citations":[{"id":"ID do pacote","quote":"Trecho literal do snippet"}]}]}
```

O gate determinístico exige citações em todas as claims, ID no pacote e trecho
não vazio contido no snippet após colapsar espaços. Não aceita campos extras ou
texto livre, nem claims junto de `abstain=true`. Uma claim não pode combinar
citações locais e ATT&CK, nem usar uma para afirmar relações do outro namespace.
As referências explícitas a CVE/CWE/ASVS e IDs/nomes de namespace ATT&CK são
checadas também em texto normalizado por NFKC. Citação remota é recusada.

Qualquer falha retorna uma abstenção canônica com código fixo, claims vazias e
nenhuma citação ou diagnóstico privado. O modo texto só renderiza claims
aprovadas, IDs e URLs conferidos; não imprime os campos livres do modelo.
O JSON de sucesso tem `status=evidence_attached_proposal`.

**Integridade de citação não prova entailment.** Uma claim falsa pode citar um
trecho verdadeiro que não a sustenta. A separação de namespaces rejeita mistura
estrutural e referências explícitas, mas não resolve todas as paráfrases ou
relações implícitas. O resultado é uma **proposta com evidência anexada**,
pendente de revisão independente, nunca uma resposta semanticamente validada
pelo próprio gerador.

## Verificação desta entrega

- 118 testes anteriores e 21 testes novos: **139/139**, também com
  `python3 -W error::ResourceWarning -m unittest discover -s tests`.
- Modelo mock local por `MITR3_MODEL_CMD`; testes não usam rede ou provedor real.
- Integração CLI com bridge/search reais somente leitura; pacote ATT&CK também
  conferido offline (entidade + quatro arestas dentro do limite global de cinco).
- Candidate JSON completo idêntico antes/depois: recall **0.975**, abstenção
  **1.000**, hit@5 **1.000**. Isso mede o retriever, não o modelo de resposta.
- Nenhuma execução do conjunto cego, nem acesso a seus gabaritos nesta tarefa.
- Nenhuma instalação de modelo, chamada a Ollama, publicação ou escrita remota.

A medição cega com o provedor real, a correção semântica por revisores
independentes e a aceitação operacional ficam para a rodada separada do time.
