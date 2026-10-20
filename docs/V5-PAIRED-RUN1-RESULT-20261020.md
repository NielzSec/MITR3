# MITR3 — Rodada pareada v5 (run 1): resultado bruto congelado

**Data:** 2026-10-20 · **Operador:** Kai (autorização explícita, sem restrições) · **Maestro:** OpenCode
**Conjunto:** `evals/blind/blind-answers-robin-v5.json` · sha `550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84`
**Modelo:** `dahl/deepseek-ai/DeepSeek-V4-Flash-0731` · **Runner:** commit `362fe5d` (sha do arquivo `a49e0c64…`)
**Gate D:** inalterado · **Produção:** intocada

## Comandos executados

```sh
python3 bin/mitr3-candidate-run.py evals/blind/blind-answers-robin-v5.json \
  --arm baseline|candidate --model dahl/deepseek-ai/DeepSeek-V4-Flash-0731 \
  --output reports/v5-<arm>-run1.json \
  --private-dir ~/.local/share/mitr3/v5-review/<arm> \
  --expected-set-sha256 55079341… --operator-approved --workers 4 --timeout 90
```

## Artefatos e hashes

| Artefato | sha256 |
|---|---|
| `reports/v5-baseline-run1.json` | `073cdf609af38c8590f48ba584349cb3bfaa53e041c44b3ea2c2755e84fa3041` |
| `reports/v5-candidate-run1.json` | `55ee6dacddf8b4b9ef9166859afb9929fbab15d0813d78f242f57834bd8d19ba` |
| Escrow baseline (manifesto) | `4ebe2592a3f7f7bb4194dc4cb22b8f5e2bcb1a478ce086040487e281085de31e` |
| Escrow candidato (manifesto) | `30c9a94a5b12849e91b0aff08e01fb2ca3a2ccee02b26f8e0c064bb1d133a41f` |

Escrow verificado nos dois braços: `verified=true`, `review_ready=true`, `redacted=0`.
Baseline: 13 tentativas / 64 arquivos. Candidato: 14 tentativas / 57 arquivos.

## Resultado por braço (metadados públicos)

| Item | Baseline | Candidato |
|---|---|---|
| 41 | abstained (QUOTE_NOT_LITERAL) | abstained (NO_VERIFIED_EXTRACTS) |
| 42 | abstained (MODEL_ABSTAIN) | abstained (NO_VERIFIED_EXTRACTS) |
| 43 | abstained (MODEL_ABSTAIN) | abstained (MODEL_JSON) |
| 44 | abstained (MODEL_ABSTAIN) | abstained (NO_VERIFIED_EXTRACTS) |
| 45 | abstained (PLAN_NEW_IDENTIFIER) | abstained (PLAN_NEW_IDENTIFIER) |
| 46 | **evidence_attached_proposal** (3 claims, gate accepted) | abstained (MODEL_JSON) |
| 47 | **evidence_attached_proposal** (2 claims, gate accepted) | abstained (MODEL_TIMEOUT) |
| 48 (controle) | abstained (PLAN_SCHEMA) | abstained (PLAN_SCHEMA) |
| 49 (controle) | abstained (MODEL_ABSTAIN) | abstained (MODEL_TIMEOUT) |
| 50 (controle) | abstained (MODEL_ABSTAIN) | abstained (NO_VERIFIED_EXTRACTS) |

Contagens: baseline 2 respondidos no gate; candidato 0.
Controles negativos (48–50): 3/3 abstêm em ambos os braços. `forbidden_ids` hits: 0 em ambos.

## Critérios pré-registrados (leitura mecânica)

- **C1 — Cobertura útil:** baseline 2, candidato 0 → **FALHA**.
- **C2 — Sustentação:** candidato não produziu claims; não há aumento mensurável de claims não sustentadas, mas o critério fica **vazio** (não avaliável como ganho).
- **C3 — Integridade:** 3/3 controles abstêm no candidato; `forbidden_ids` = 0 nos dois braços → **PASSA**.
- **C4 — Estabilidade:** candidato introduz classes novas de falha de pipeline (`NO_VERIFIED_EXTRACTS` ×4, `MODEL_JSON` ×2) além de `MODEL_TIMEOUT` ×2 → **FALHA** (não atribuível apenas a transporte).

## Veredito preliminar

**Candidato não supera o baseline.** C1 e C4 falham; C2 é vazio; C3 passa por abstenção total. Nenhuma promoção. A revisão semântica (GPT QA + pesquisa de fonte + JEV) sobre as 5 claims aceitas do baseline fica registrada em documento próprio, sem alterar estes números.
