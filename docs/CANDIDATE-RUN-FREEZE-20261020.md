# MITR3 — Registro de congelamento para a rodada pareada no v5

**Data:** 2026-10-20 · **Maestro:** OpenCode · **Base:** `CANDIDATE-FREEZE-SPEC-20261020.md` (sha ef5ec791)

## Hashes congelados (pré-execução)

| Artefato | SHA256 / referência |
|---|---|
| Conjunto v5 | `550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84` (manifesto `43589b6`) |
| Spec de congelamento | `ef5ec791003abc6f927ca7389fd19f83ccd1efe1269b3bc76af0ceec555fd402` |
| Baseline `bin/mitr3-answer.py` | `4ba78d9a0b57e6bfaad6524e95cd81d266f2ba071eeaba61ad8551ed114c29ab` |
| Runner pareado `bin/mitr3-candidate-run.py` | `fa83aa477ef7ecfa081bb503626e509426242c4777f95e6839c6e09788f117c6` |
| Commit do merge (árvore de execução) | `f1c68e7` |
| Modelo | `dahl/deepseek-ai/DeepSeek-V4-Flash-0731` |
| Suite | 200/200 OK (`ResourceWarning` como erro) |

## Comandos exatos (uma execução por braço, sem retry seletivo)

```sh
python3 bin/mitr3-candidate-run.py evals/blind/blind-answers-robin-v5.json \
  --arm baseline --model dahl/deepseek-ai/DeepSeek-V4-Flash-0731 \
  --output reports/v5-baseline-run1.json \
  --expected-set-sha256 550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84 \
  --operator-approved

python3 bin/mitr3-candidate-run.py evals/blind/blind-answers-robin-v5.json \
  --arm candidate --model dahl/deepseek-ai/DeepSeek-V4-Flash-0731 \
  --output reports/v5-candidate-run1.json \
  --expected-set-sha256 550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84 \
  --operator-approved
```

## Regras da rodada (herdadas da spec, reafirmadas)

- Uma execução por braço; saídas nunca sobrescritas; sem repetição para melhorar número.
- Nenhum ajuste entre braços; nenhum código alterado após o primeiro run.
- O v5 é consumido nesta rodada e não é reutilizado para tuning.
- Avaliação do resultado: GPT-6 + pesquisa de fonte + JEV, com adjudicação do operador apenas em divergência não resolvida pela fonte.
- Critérios C1–C4 da spec; produção continua bloqueada independentemente do resultado.

## Verificação de integridade pré-execução

- Testes do runner: 23/23 offline, incluindo bloqueio de leitura do v5 e não-promoção de extração rejeitada.
- Falhas de suite em worktree isolado diagnosticadas como ambientais (índice RAG ausente), não do runner; árvore principal 200/200.
- O runner exige `--operator-approved` e o sha256 do conjunto; recusa execução sem ambos.
