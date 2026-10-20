# MITR3 — Especificação de congelamento do candidato (comparação no v5)

**Data:** 2026-10-20 · **Maestro:** OpenCode · **Autoridade final:** Kai (assinatura antes da primeira execução)
**Base:** disposição QA `GPT6-QA-D1-D4-DISPOSITION` (sha d914c441) · ordem `GPT6-QA-DECISION-SYNTHESIS` (sha f701a3fa) · v5 congelado `43589b6` (sha 550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84)

## 1. Braços comparados

| Braço | Definição | Código |
|---|---|---|
| **Baseline** | Pipeline de produção atual: plan → retrieve → compose → Gate D inalterado | `bin/mitr3-answer.py` no commit congelado |
| **Candidato** | Mesmo plan e mesma recuperação; **extract-then-synthesize com quotes literais obrigatórias** (modo `required` do experimento `8919d5d`); validação final = **o mesmo Gate D inalterado** | runner candidato em branch isolada, build próprio |

O candidato NÃO altera: Gate D, prompts de produção do baseline, ranking, índices, corpus, modelo, conjuntos.
O candidato NÃO recebe: expected_answer, expected_ids, forbidden_ids, rubrica ou notas humanas.
Extração não é juiz semântico; ela só propõe pares id/quote verificados pelo Gate D.

## 2. Condições de execução (iguais nos dois braços)

- Modelo: `dahl/deepseek-ai/DeepSeek-V4-Flash-0731` (fixo; mesmo transporte, mesma config de temperatura/limites do pipeline).
- Perguntas: `evals/blind/blind-answers-robin-v5.json` — **somente os campos `id` e `question`**; o runner nunca lê campo de gabarito.
- Máquina e janela: mesma sessão, mesmo dia; workers/timeout idênticos (`--workers 4 --timeout 90`, retry apenas para `MODEL_TIMEOUT`/`MODEL_FAILED`, como no runner cego existente).
- Ordem: baseline primeiro, candidato segundo, mesma máquina, sem ajustes entre braços.
- Saídas nunca sobrescritas; artefatos novos, sha256 no relatório.

## 3. Métricas pré-registradas (por item e agregadas)

1. `answered_gate` — resposta com composição aceita pelo Gate D.
2. `abstained` — `MODEL_ABSTAIN` (com pacote vazio ≠ com pacote suficiente).
3. `failed` — timeout/erro de modelo (operacional, ≠ resposta falsa).
4. `blocked` — `DOCUMENT_IDENTITY`, `NO_EVIDENCE`, `QUOTE_NOT_LITERAL`, `INSTRUCTION_*` (tipos separados; nunca somados como erro semântico).
5. `forbidden_ids_hits` — IDs proibidos citados (meta: 0).
6. `negative_controls_abstained` — dos 3 controles negativos do v5, quantos abstiveram (meta: 3/3).
7. `semantic_support` — por claim: supported / partial / unsupported / contradicted / insufficient, via parecer GPT-6 + trilha JEV (mesmo protocolo do v3/v4, com a lição do empacotamento de evidência).
8. `quote_literal_rate` — fração de citações cujo quote é literal no snippet enviado.

## 4. Critérios de aceitação (pre-registrados; nenhum ajuste pós-resultado)

- **C1 — Cobertura útil:** candidato ≥ baseline em `answered_gate` nos itens respondíveis.
- **C2 — Sustentação:** candidato não aumenta claims `unsupported/contradicted` vs baseline.
- **C3 — Integridade:** `forbidden_ids_hits = 0` nos dois braços; controles negativos 3/3 abstêm no candidato.
- **C4 — Estabilidade:** nenhuma falha operacional nova atribuível ao candidato além de transporte.
- **Veredito:** só há promoção com C1–C4 e parecer humano. Qualquer regressão em C2 rejeita, mesmo com ganho em C1.
- **Natureza:** n=10 (10 itens, 3 controles) é **exploratório**. Sem decisão de produção; sem reuso do v5 para ajustar o candidato.

## 5. Artefatos a congelar antes da primeira execução

| Item | Como |
|---|---|
| v5 | sha já congelado `55079341…`; verificar antes do run |
| Baseline | commit sha do repo no momento do congelamento + sha256 de `bin/mitr3-answer.py` |
| Candidato | commit sha da branch + sha256 do runner candidato + hash do prompt de extração e do prompt de síntese |
| Modelo/transporte | id do modelo + config (temperatura/limites) registrados no relatório |
| Critérios | este documento com sha256; nenhuma edição após o primeiro run |

## 6. Sequência

1. Codex constrói o runner candidato em branch isolada e testa **apenas em fixture DEV** (nenhum toque ao v5).
2. Maestro congela hashes, regista a lista em relatório.
3. **Assinatura do operador** nesta spec (e na folha de adjudicação) — sem assinatura, sem run.
4. Baseline e candidato rodam sobre o v5, braços separados, saídas congeladas.
5. Revisão cega (GPT-6 + JEV em trilhas separadas; adjudicação humana das divergências).
6. Veredito C1–C4 registrado; produção continua bloqueada até decisão explícita de Kai.
