# MITR3 — Registro de congelamento para a rodada pareada no v5

**Data:** 2026-10-20 · **Maestro:** OpenCode · **Base:** `CANDIDATE-FREEZE-SPEC-20261020.md` (sha ef5ec791)

## Hashes congelados (pré-execução)

| Artefato | SHA256 / referência |
|---|---|
| Conjunto v5 | `550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84` (manifesto `43589b6`) |
| Spec de congelamento | `ef5ec791003abc6f927ca7389fd19f83ccd1efe1269b3bc76af0ceec555fd402` |
| Baseline `bin/mitr3-answer.py` | `4ba78d9a0b57e6bfaad6524e95cd81d266f2ba071eeaba61ad8551ed114c29ab` |
| Runner pareado `bin/mitr3-candidate-run.py` | `cf2578791e2a11e3d4bc0165b72cd29d60dc841da32fc73e89a9ab8f61d4fac3` |
| Escrow `bin/mitr3-review-artifacts.py` | `f62ce0208151869b96355324484811f55a6e942a9dcf70d045d1c33881e18d54` |
| Commit do merge (árvore de execução) | `25be178` (escrow incluído) |
| Modelo | `dahl/deepseek-ai/DeepSeek-V4-Flash-0731` |
| Suite | 218/218 OK (`ResourceWarning` como erro) |

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

## Recongelamento pós-NO-GO (2026-10-20)

Bloqueio do QA (`GPT6-V5-PRE-RUN-NOGO`, sha 28675085) corrigido antes de qualquer execução real:

- Escrow privado de claims/citações/snippets por braço, fora do Git, `0600` + manifesto sha256; campos de gabarito nunca decodificados.
- Prova DEV item 1 do QA: fixture sintética, dois braços; **GPT QA** classificou A=SUSTENTADA / B=NÃO SUSTENTADA; **JEV** 0.59 / 0.07. Ambos leram claim, citação e snippet do escrow.
- Suite 218/218; o runner continua exigindo `--operator-approved` + sha do conjunto.
- v5 permanece `55079341…`; nenhum relatório de execução foi criado.
