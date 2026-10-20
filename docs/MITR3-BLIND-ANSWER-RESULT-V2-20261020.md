# Blind answers v2 — resultados mecânicos (conjunto queimado)

Data: 2026-10-20 · Conjunto: `blind-answers-antigravity-v2` (commit `33549e7`,
sha256 `3b4ee6c4c079d7312a1344a4baf297a7ddd8d6774e03fcf0a6d07dc974f0f613`,
autor Antigravity — verificado: sha do arquivo = sha declarado).
Autor ≠ tuner: correções implementadas APÓS esta medição; qualquer efeito delas
só é medida em conjunto novo (v3).

## Condições de medição (troca de modelo documentada)

- Runs 1–2 originais: `opencode/nemotron-3.5-lightning-free` — **falharam 20/20** com
  MODEL_FAILED: free tier do OpenCode bloqueado por IP ("abusive traffic from this IP"),
  afetando TODO o free tier (glm/deepseek/nemotron), não quota individual.
- Reposição: `dahl/deepseek-ai/DeepSeek-V4-Flash-0731` (2 passadas). Sem relação com
  autor (Antigravity) nem tuner. Ambas as passadas com o mesmo modelo.

## Resultado mecânico (20 chamadas)

| erro | run1 | run2 |
|---|---|---|
| NO_EVIDENCE | 8 | 7 |
| MODEL_ABSTAIN / MODEL_TIMEOUT | 1 / 0 | 0 / 1 |
| DOCUMENT_IDENTITY | 1 (item 04) | 2 (04, 06) |
| responderam | 0 | 0 |

## Diagnóstico da onda NO_EVIDENCE (15/20)

- Reprodução com item do v1 (`blind-robin-04`, evidência confirmada 6/6 no diag
  dc63c70): NO_EVIDENCE no modelo dahl — a falha é da camada, não do conjunto.
- Causa raiz: **etapa A gera queries longas em português; o corpus KEV/ASVS tem
  títulos em inglês** — o FTS da ponte não casa. O nemotron (v1) acertava com queries
  curtas/produto; o dahl gera frases PT coladas da pergunta.
- Prova manual: ponte bate (3 matches) para "MOVEit SQL injection"; as queries que o
  modelo gera ("falha de injeção de SQL pré-autenticada aplicações de transferência…")
  devolvem zero.

## Correções aplicadas APÓS o v2 (não mensuráveis nele)

- `d46c5b2` — etapa A: queries curtas em vocabulário técnico inglês (2-5 palavras).
- `161bbd3` — compositor: critério objetivo de abstenção (abstém só sem evidência
  útil; não por cautela). Defesa de injeção intacta.
- Medição de ambas: **somente no v3 cego** (autor ≠ tuner). v2 vira regressão.

## Notas

- D08 (gate valida presença, não entailment) permanece por design — correção humana
  0/1/2 é do revisor humano.
- Variância do compositor continua: 1× MODEL_TIMEOUT, 1× MODEL_ABSTAIN entre os erros
  mecânicos. Medições futuras: k execuções por item ou temperatura fixa.
