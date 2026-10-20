# Blind answers v4 — resultados mecânicos

Data: 2026-10-20 · Conjunto: `blind-answers-gemma4-v4` (commit `d0309d3`,
sha256 `7b99a31bbf49dbd908353b8f91b3ed446234b685179151b0089ec71c7667a652`,
autor Gemma4 — sidecar confere com o arquivo; formato lista direta).
Mede também a correção `bb0b83a` (lookup de id case-insensível). Modelo
`dahl/deepseek-ai/DeepSeek-V4-Flash-0731`, 2 passadas.

## Resultado por item (abstain esperado: 08/09/10 = True)

| item | run1 | run2 | esperado |
|---|---|---|---|
| 01 CISA KEV vs lista CVE (conceitual) | MODEL_ABSTAIN | QUOTE_NOT_LITERAL | responde |
| 02 (conceitual) | MODEL_ABSTAIN | MODEL_ABSTAIN | responde |
| 03 ficha CASE-ps-cache-2024 | **respondeu (2 claims)** | MODEL_TIMEOUT | responde |
| 04 (conceitual) | MODEL_TIMEOUT | MODEL_ABSTAIN | responde |
| 05 (conceitual) | MODEL_ABSTAIN | MODEL_FAILED | responde |
| 06 ficha CASE-ps-practical-cache-poisoning-2018 | **respondeu** | **respondeu** | responde |
| 07 (conceitual) | MODEL_ABSTAIN | MODEL_ABSTAIN | responde |
| 08/09/10 controles negativos | NO_EVIDENCE/NE/MODEL_ABSTAIN | idem | **abstenção correta** |

**DOCUMENT_IDENTITY: 0 em 20** — `bb0b83a` segura; as fichas `CASE-` agora passam o gate de identidade (03/06 responderam com citação literal).

## Leitura: o padrão é o estilo da pergunta, não o pipeline

- v3 (perguntas ancoradas em ID — "qual CVE…", "qual requisito…"): 5/7 responderam.
- v4 (perguntas conceituais — "qual a diferença fundamental…", "qual princípio…"): só as
  duas que apontam ficha específica responderam; as conceituais abstêm (MODEL_ABSTAIN)
  ou morrem no gate (QUOTE_NOT_LITERAL, MODEL_TIMEOUT, MODEL_FAILED).
- Hipótese dominante: o contrato exige citação literal do snippet para toda claim; síntese
  conceitual cruzando documentos não tem substring única para citar → o compositor abstém.
  É o contrato funcionando (nada de inferência não ancorada) sobre um tipo de pergunta que
  ele não desenhou para responder. Qual é a política certa (abstém = certo para conceitual,
  ou contrato precisa de nuance de síntese) é decisão de contrato — do time, com prova.

## Dívida técnica (nova build → Codex)

- Runner serial: cada item espera até 420s quando o modelo pendura (item 04 run1 queimou
  7 min em MODEL_TIMEOUT). Próxima versão: paralelo, timeout curto (~90s), retry, e
  container por item. Command: `bin/mitr3-blind-run.py`.

## Pendente humano (revisor: Kai)

- v3 itens 01–05 (respondidos, IDs corretos) + v4 (03, 06 respondidos; 08-10 abstenção
  correta; conceituais abstiveram — juízo de se a abstenção é mérito ou falha).
