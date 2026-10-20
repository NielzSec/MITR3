# Diagnóstico das abstenções 04, 05 e 06 — Robin v1

Data: 2026-10-20. Base inspecionada: `f8d06ccdfa5ce77574f52b73ea38f096b0105458`.
**Diagnóstico somente. O v1 está queimado para tuning. Qualquer patch futuro:
“medicao somente em v2 cego”.** Nenhum pipeline, prompt de produção, adapter,
retriever, teste ou gabarito foi alterado. Não é uma nova nota do conjunto cego.

## Resultado principal

| Item | Causa localizada na primeira medição | Com evidência forçada, adapter atual/Gemini |
|---|---|---|
| 04 | **Etapa A**: queries sobre Mirai/router entregam outros roteadores, sem `CVE-2023-1389`. A abstenção do compositor decorre de pacote fora do alvo. | Não abstém; cita `CVE-2023-1389` para injeção de comando/RCE. Não comprova vínculo Mirai. |
| 05 | **Compositor com perda de informação na etapa B**: `CVE-2020-1472` chega, mas `summary[:300]` corta o apelido pedido. A saída histórica é JSON válido de abstenção, não erro de parser. | Prefixo de 300 chars mantém `MODEL_JSON`: o agente plan responde em prosa, sem composição válida. |
| 06 | **Compositor/suficiência de contexto**: `CVE-2023-23397` chega com resumo inteiro, e o modelo devolve abstenção. Não é perda do ID na etapa A histórica. | Não abstém; cita o ID e NTLM Relay, sem provar os detalhes UNC/lembrete/zero clique ausentes da fonte entregue. |

O motivo interno exato da decisão do compositor histórico não está no JSON
`{"abstain":true,"claims":[]}`. A posição da falha e o conteúdo recebido são
observáveis; as lacunas semânticas são fatores demonstrados, não uma leitura do
raciocínio privado do modelo. Presença do ID não prova que todo enunciado da
pergunta seja sustentado pelo resumo. Nenhuma proposta abaixo foi promovida a
resposta semanticamente validada.

## Método e rastreabilidade

1. Preservados hashes de `bin/*.py` e arquivos do conjunto v1 antes do diagnóstico.
2. Os três itens foram executados pelo entrypoint de `bin/mitr3-answer.py` com
   `--json --model ...`, via `runpy` e instrumentação externa transparente em
   `/tmp/opencode/abstain-diag`. O observador apenas grava prompt/stdout, argv,
   retorno e tempo de `subprocess.run`; mantém argumentos, timeout e comportamento
   do CLI. Não utiliza `MITR3_MODEL_CMD`, não reescreve consultas nem respostas.
3. O provedor da primeira medição, `opencode/nemotron-3.5-lightning-free`, hoje
   recusa os três casos antes da etapa A: exit 1, stdout vazio, `MODEL_FAILED`.
   Um probe com a mesma configuração retorna recusa dos modelos gratuitos por
   tráfego abusivo detectado na rede/IP. Isso é indisponibilidade atual do
   provedor, não causa retroativa das três abstenções `MODEL_ABSTAIN`.
4. O provedor previamente autorizado `google/gemini-3.5-flash-lite` respondeu
   `ok` ao probe. Os três casos e os controles forçados foram executados com ele,
   mantendo o adapter atual `--agent plan`, sem habilitar tools, remote ou outro
   agente. Esses resultados não são comparáveis como uma nova nota Nemotron.
5. Para localizar as falhas **históricas**, foram recuperadas as sessões da
   primeira medição no SQLite local do OpenCode, somente leitura. Filtro:
   diretório `/home/nielz/MITR3`, janela UTC 04:44–04:47:51 e os trechos públicos
   distintivos das três perguntas. Foram lidos apenas prompts desses itens e
   blocos de resposta `type=text`; não foram exportados reasoning, system,
   credenciais ou outras sessões. O agente histórico era `build`; não foi
   reexecutado esse agente. A mudança para `plan` ocorreu depois, em `f68a42a`.
6. Cada query histórica e atual foi executada diretamente em `search --json
   --limit 5` e no bridge `--json --limit 5`. Os IDs e a ordem coincidiram em
   todos os pares índice/bridge. Não há perda adicional introduzida pelo bridge.
7. Controles por palavra-chave, definidos a partir dos termos dos casos,
   selecionaram o documento do primeiro resultado do índice. A composição
   forçada usa esse ID via `evidence_package`, sem etapa A, sem incluir gabarito
   ou resposta esperada no prompt. Usa o mesmo `composition_prompt`, adapter e
   gate existentes. Apenas fontes públicas locais foram enviadas ao provedor.

A primeira medição está em `reports/blind-answers-robin-v1-run1.json`
(`at_utc=2026-10-20T04:47:51.068437+00:00`). A segunda rodada já mostrava mudança
para `MODEL_JSON` no 05 e `NO_EVIDENCE` no 06: repetir o pipeline estocástico não
reproduz necessariamente as mesmas queries ou o mesmo ponto de falha.

Os pacotes históricos recuperados do 05 e do 06 são iguais, campo a campo,
aos controles forçados prefix300 atuais.

Os prompts históricos registrados tinham aspas escapadas. Na leitura forense,
removeu-se uma camada de escape das aspas **somente para interpretar o pacote
arquivado**; não se alterou o que o modelo recebeu. IDs e trechos foram cruzados
com as buscas atuais. Essa serialização histórica também difere do replay atual;
não há contrafactual com Nemotron disponível para isolar seu efeito.

## Controles locais: três alvos presentes

| Item | Query de controle | Índice e bridge, alvo na posição 1 |
|---|---|---|
| 04 | `TP-Link Archer` | `CVE-2023-1389` |
| 05 | `Netlogon` | `CVE-2020-1472` |
| 06 | `Outlook NTLM` | `CVE-2023-23397` |

São 3/3 controles deste diagnóstico, não uma nova execução dos seis positivos do
cego. A consulta do 04 também devolve outros quatro roteadores; as do 05 e 06
retornam só o documento relevante. Origem dos três: CISA KEV,
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>, confiança
`official_catalog_not_locally_tested`. Catalogação não comprova exposição de alvo
nem todos os vínculos de campanha mencionados nas perguntas.

## Item 04 — falha histórica da etapa A

Etapa A histórica, sessão `ses_ea85f2f26ffeI7cElrpbXKC75G`,
2026-10-20T04:45:19.479Z:

| Query gerada | IDs no índice e no bridge | Alvo presente? |
|---|---|---|
| `Mirai KEV router` | `CVE-2016-10174`, `CVE-2020-10987`, `CVE-2011-4723`, `CVE-2015-2051`, `CVE-2021-35395` | não |
| `TP-Link Botnet Ready setup` | vazio | não |
| `Mirai home router exploitation` | vazio | não |

O pacote de cinco documentos contém NETGEAR, Tenda, D-Link e Realtek, sem o
TP-Link procurado. A etapa A conservou texto de oferta (`Botnet Ready setup`) e
produziu termos genéricos/expandidos (`home router exploitation`) em vez de uma
consulta que recuperasse o componente. O primeiro resultado genérico preenche o
limite global, mas nenhuma das outras queries recupera o alvo sequer isoladamente.

O compositor histórico, sessão `ses_ea85efb35ffeW52pjvDoFhPHGw`, às
04:45:32.777Z, recebeu exatamente esse pacote e respondeu
`{"abstain":true,"claims":[]}`. Portanto não se trata de um compositor recusando
um documento TP-Link que já estivesse no pacote.

No replay Gemini atual:

| Query gerada | Resultado comum índice/bridge |
|---|---|
| `Mirai Botnet Ready setup TP-Link` | vazio |
| `KEV CVE roteador TP-Link Mirai` | alvo em 1º; também `CVE-2015-3035`, `CVE-2023-33538`, `CVE-2025-9377`, `CVE-2023-50224` |
| `Mirai rotas domésticas TP-Link` | vazio |

Esse replay não se absteve e citou três CVEs. O controle com apenas o alvo e sua
aresta declarada também não se absteve e citou `CVE-2023-1389`.
Isso não comprova que a pergunta inteira foi respondida: o resumo tem 102
caracteres, descreve TP-Link Archer AX-21/injeção de comando/RCE e **não menciona
Mirai**. O gate verifica a citação; não verifica essa atribuição por inferência.

## Item 05 — documento certo, apelido cortado e adapter atual em prosa

Etapa A histórica, sessão `ses_ea85eec8affeazMlF8IrtvcDc6`, às 04:45:36.553Z:

| Query gerada | Resultado comum índice/bridge |
|---|---|
| `CVE do Netlogon 2020` | `CVE-2020-1472` |
| `efeito do CVE Netlogon` | vazio |

O pacote histórico contém `CVE-2020-1472` e a aresta `cwe_of → CWE-330`.
O compositor da sessão `ses_ea85eb547ffeK3I1WP8mn7ZxrB`, às 04:45:50.693Z,
retornou JSON válido de abstenção. A etapa A funcionou suficientemente para
recuperar o ID; não é `MODEL_JSON` nessa primeira medição.

A perda de informação é objetiva: summary tem **383 caracteres**; a produção
usa os primeiros **300** e termina em `on a dev`. `Zerologon` começa no offset
**373**, fora do pacote. A frase literal que sustenta o apelido existe no documento:

> The vulnerability is also known under the moniker of Zerologon.

Nenhuma aresta CWE fornece esse apelido. O compositor não dispõe do texto
completo que a busca encontrou. Logo “hit do documento” e “evidência entregue para
o apelido” divergem. Não se deve preencher a lacuna com conhecimento do modelo.

No replay Gemini atual:

| Query gerada | Resultado comum índice/bridge |
|---|---|
| `Netlogon 2020 ransomware` | `CVE-2020-1472` |
| `Netlogon apelido` | vazio |

O pacote volta a conter o alvo e sua aresta, mas o compositor produz prosa de
“Plan Mode”, discute a falta do apelido e pede orientação ao usuário. Não entrega
um objeto de composição válido; a menção ao schema com `boolean`/`string` não é
JSON. O resultado é **`MODEL_JSON`**, uma falha de formato do conjunto agente/modelo
no adapter atual, não uma falha de `search` nem uma claim rejeitada pelo gate.

Controles sem mudar código:

| Evidência forçada | Resultado do adapter/gate Gemini |
|---|---|
| Documento exato, prefixo300 + mesma aresta | `MODEL_JSON`, prosa de Plan Mode; apelido continua ausente |
| Últimos 300 caracteres do mesmo summary + mesma aresta | `MODEL_JSON` novamente |
| Controle preliminar: últimos 300 caracteres, sem aresta | proposta com ID, Zerologon e efeito; citações passam no gate |

O controle preliminar altera duas variáveis (janela e presença da aresta), além
da variabilidade do modelo: **não prova que trocar a janela basta para corrigir**.
O controle mantendo a aresta mostra que o problema de formato do adapter ainda
pode impedir a resposta mesmo com o apelido no pacote. Nenhum desses controles
foi aplicado ao pipeline ou contado como melhora no cego.

## Item 06 — compositor histórico recebeu o alvo

Etapa A histórica, sessão `ses_ea85e70e8ffevqp3ouj3XWHMPC`, às 04:46:08.195Z:

| Query gerada | Resultado comum índice/bridge |
|---|---|
| `NTLM hash Outlook UNC` | vazio |
| `stealers NTLM Outlook` | `CVE-2023-23397` |

A segunda query recupera o documento. O pacote histórico da sessão de composição
`ses_ea85e5436ffeq7qa1fT8qxVmRI`, às 04:46:15.539Z, tem o documento e a aresta
`cwe_of → CWE-294`. A saída é JSON válido de abstenção. **A perda histórica ocorre
no compositor, não por ausência do alvo em A/B, nem por falha de parsing.**

Aqui o summary inteiro tem 159 caracteres, sem truncamento. Declara privilégio e
NTLM Relay em Outlook. Não contém `UNC`, objeto de lembrete, zero clique ou roubo
de hash explícito. A recusa pode refletir essa diferença entre a pergunta e o
texto entregue; o JSON histórico não oferece explicação para prová-lo. Não é
correto equiparar existência da CVE a comprovação de todos esses detalhes.

O replay Gemini atual falha em um ponto diferente:

| Query gerada | Resultado comum índice/bridge |
|---|---|
| `roubo de hash NTLM Outlook caminho UNC` | vazio |
| `lembrete Outlook caminho UNC NTLM` | vazio |

Ambas acrescentam ao corte de cobertura termos ausentes do resumo; pacote vazio,
**`NO_EVIDENCE`**, compositor nem chamado. A mesma pergunta com documento exato
forçado + aresta permite ao compositor Gemini responder com `CVE-2023-23397` e
NTLM Relay, passando o gate. Isso demonstra capacidade de resposta parcial com
fonte presente nesse modelo, não que a recusa histórica tenha sido um erro de
adapter, nem que o vetor completo tenha sido validado.

## Evidência persistida e reprodução

Resultados estruturados, queries, rankings completos, pacotes, saídas finais,
controle de janela e identificadores das sessões estão em
[`reports/abstain-diag-20261020.json`](../reports/abstain-diag-20261020.json).
Os prompts/stdout atuais e o extrator temporário ficam em
`/tmp/opencode/abstain-diag`; o relatório no Git não depende dessa pasta para
consultar as queries e os resultados. Não inclui raciocínio privado dos modelos.

Hashes SHA256 dos documentos-alvo:

| ID | SHA256 do documento indexado |
|---|---|
| CVE-2023-1389 | `f2b8d41cb7a1abb9e02891c427af807e72a4682df5c881c019c8c0145d3be67f` |
| CVE-2020-1472 | `29e5540c90994d1a53399d62161fe6bcf06dfe111727ba2f5e0c4ba1a33b91e0` |
| CVE-2023-23397 | `c0773e2f867a2327a1e309e48236ec8c5f48b20f9a8fda285086ca66934f4831` |

Para repetir somente o controle local, sem modelo:

```sh
python3 bin/mitr3-rag-intel.py search 'stealers NTLM Outlook' --json --limit 5
python3 bin/mitr3-context-bridge.py 'stealers NTLM Outlook' --json --limit 5
```

As demais queries estão nas tabelas acima. Uma nova chamada ao modelo não é
reprodução bit a bit dos textos históricos. O provider gratuito está indisponível
na rede atual e não foi contornado. O adapter atual permanece no agente plan.

## Encaminhamento, sem implementar correções

- Etapa A: medir preservação de entidades úteis e excesso de qualificadores de
  consultas, separadamente de recall do índice.
- Evidência/compositor: medir cobertura dos fatos pedidos no trecho, abstinência
  total versus resposta parcial explícita e ausência de atribuições na fonte.
- Adapter: estudar um contrato JSON em agente realmente restrito a inferência,
  sem reabilitar tools; preservar diagnóstico de falha do provedor sem expor segredo.

Esses pontos são hipóteses de trabalho para patch separado, obrigatoriamente
marcado **“medicao somente em v2 cego”**. Não são ajustes autorizados nesta entrega.
Suite inicial: **160/160**; suite final: **164/164**, com ResourceWarning tratado como erro.
Durante o diagnóstico entraram os commits externos `2d73b75` e `8a5992a`,
sem relação com a resposta, incluindo quatro testes OSINT novos. Os hashes de
answer, bridge, search/eval e do conjunto cego permanecem iguais aos da base. Pipeline e arquivos do
cego preservados byte a byte; apenas documentação e relatório diagnóstico entram
no commit. Nenhuma nova pontuação de resposta foi atribuída ao v1.
