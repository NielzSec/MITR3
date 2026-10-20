# MITR3 — primeira avaliação de respostas (conjunto cego v1)

**Data:** 2026-10-20 · **Conjunto:** `evals/blind/blind-answers-robin-v1.json`
sha256 `61bf0b511faa00d98b89635b2c807dcbe675b6a070cafa5b51eef63bb2a40693` · **Errata:** `ERRATA-robin-v1.md`
**Pipeline:** `bin/mitr3-answer.py` (etapas A–D do contrato de resposta por evidência)
**Modelo:** `opencode/nemotron-3.5-lightning-free`

## Resultado

| métrica | run 1 | run 2 |
|---|---|---|
| respondíveis (após errata) | 6 | 6 |
| respondidos corretamente | **3** | **3** |
| abstenções indevidas | 3 | 3 |
| abstenção correta nos 4 negativos | 3/4 | 3/4 |
| citações proibidas | **1** | **1** |

Estável nas duas passadas. Os mesmos três itens acertam, os mesmos três se recusam, o mesmo item erra.

## Item por item

| item | esperado | run 1 | run 2 |
|---|---|---|---|
| 01 Cobalt Beacon | CVE-2022-39197 | ✔ | ✔ |
| 02 Cobalt UI RCE | CVE-2022-42948 | ✔ | ✔ |
| 03 Deadbolt | CVE-2022-27593 | ✔ | ✔ |
| 04 Mirai / roteador | CVE-2023-1389 | abstém | abstém |
| 05 Zerologon | CVE-2020-1472 | abstém | abstém |
| 06 Outlook NTLM | CVE-2023-23397 | abstém | abstém |
| 07 ESXiArgs | **abster** (errata: CVE real fora do KEV) | responde errado | responde errado |
| 08 AsyncRAT | abster | ✔ | ✔ |
| 09 builder pós-takedown | abster | ✔ | ✔ |
| 10 infostealer no KEV | abster | ✔ | ✔ |

## O item 07, nas duas execuções

> run 1: "CVE-2021-21972 is the cataloged CVE of vCenter that serves as the public anchor of the ESXiArgs ransomware campaign"
>
> run 2: "CVE-2021-21972 is the publicly catalogued vCenter CVE anchored in the ESXiArgs ransomware campaign"

Citação literal, ID existente no pacote, gate aprovando. A afirmação é falsa: o resumo
do CVE-2021-21972 não menciona ESXiArgs. Isto é o caso D12 do QA adversarial
acontecendo espontaneamente — e é exatamente o erro que o `ERRATA-robin-v1.md` previu
que alguém cometeria de memória.

O gate não podia barrar: ele verifica presença de citação, não sustentação semântica.
O sistema entregou "proposta com evidência anexada", como o contrato manda chamar.

## Variância observada

O item 05, reexecutado fora da bateria, **respondeu corretamente** com o mesmo texto e a
mesma configuração. As duas passadas oficiais o viram abster, por três motivos diferentes:
`MODEL_ABSTAIN`, `MODEL_JSON` e `NO_EVIDENCE`.

Consequência metodológica: uma execução é uma amostra. O número estável por item nas duas
passadas não garante estabilidade do motivo nem da taxa em execuções futuras. Medições
futuras devem ou fixar temperatura, ou reportar `k` execuções por item.

## O que este número diz e o que não diz

Diz: com evidência no índice, o sistema acerta três de seis perguntas de analista e não
cita documento proibido nos itens que acerta. Recusa-se corretamente em três dos quatro
negativos.

Não diz: que a resposta está certa por ter citação. O item 07 prova o contrário.

## Consequência para o desenvolvimento

O conjunto v1 está **queimado para tuning** desde a primeira leitura. Qualquer alteração
no pipeline a partir daqui deve ser medida em um **v2 cego**, com perguntas novas e autor
diferente, congelado antes da execução. V1 permanece como regressão.

Correção 0/1/2 de cada resposta continua pendente de revisor humano; as métricas acima
são todas mecânicas.
