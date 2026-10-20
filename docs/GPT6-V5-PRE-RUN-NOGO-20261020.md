# MITR3 — HOLD QA antes da unica rodada cega v5
**Data:** 2026-10-20 · **Revisor:** GPT-6, QA externo · **Destino:** OpenCode (maestro), operador.
**Decisao:** **NO-GO temporario** para executar baseline/candidato sobre o v5. Nenhum runner foi disparado por GPT-6 e o conjunto permanece selado.

## Evidencia independente
- Commit de congelamento: `bc71c59`; merge aditivo `f1c68e7`.
- Hashes conferidos localmente: v5 `550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84`; spec `ef5ec791003abc6f927ca7389fd19f83ccd1efe1269b3bc76af0ceec555fd402`; baseline `4ba78d9a0b57e6bfaad6524e95cd81d266f2ba071eeaba61ad8551ed114c29ab`; runner `fa83aa477ef7ecfa081bb503626e509426242c4777f95e6839c6e09788f117c6`.
- `docs/CANDIDATE-FREEZE-SPEC-20261020.md` preregistra C2: nao aumentar claims unsupported/contradicted, com revisao GPT-6 + JEV.
- `bin/mitr3-candidate-run.py`: `call_arm()` devolve `metadata(value['result'])`, descartando claim.text e cite.quote; baseline delega a `BLIND.call_answer()`, que tambem so devolve `BLIND.metadata(json.loads(stdout))`. `run_item()` grava so `claim_count`, `citation_ids`, tipo de erro, tempos e estatistica de extração. Nao existe sidecar de claims/snippets/citacoes com controle de acesso para avaliadores.
- Assim, **C2 e revisao semantica GPT+JEV nao sao verificaveis a partir dos artefatos congelados**. Um resultado `answered_gate` prova apenas validade estrutural, nao suporte semantico. Como o v5 e one-shot, executar agora queimaria uma oportunidade de avaliar C2.
- A `--operator-approved` e uma flag autoafirmada, nao mecanismo de verificacao da assinatura humana. A spec exige consentimento do operador para a rodada, separadamente do encerramento da folha D1–D4. Nao tratar o OK do QA como assinatura do operador.
- Nota estatistica: com n=10 e 3 controles negativos, resultado apenas exploratorio. Branch candidato faz extracao adicional sob mesmo timeout 90s; considerar custos/falhas por maior numero de chamadas ao avaliar C4. Os dois braços podem recuperar pacotes diferentes por planejamento nao deterministico; documentar como fator de confusao da comparacao.

## Correcao obrigatoria ANTES de executar v5
1. **Codex em DEV somente:** implementar **escrow de evidencias por item e braço**, sem qualquer leitura/serializacao do gabarito: ID, pergunta, exact claim.text, cite.id/quote, evidência/snippet efetivamente transmitido, source_url, namespace, SHA256, status/error, modelo/arm, hash do artefato. Garantir isso em AMBOS braços, inclusive baseline, sem alterar prompts nem Gate D.
2. Escolher diretorio privado `mode 0700`, arquivos novos `0600`, exclusao do Git/logs publicos, política de minimização/redaction, manifest SHA256, validacao de integridade e politica de compartilhamento antes de chamar JEV. **Nunca** enviar segredos, alvos privados, PII ou gabaritos a terceiros. A prova cega nao pode conter expected_answer, rubric, expected_ids ou forbidden_ids.
3. Um teste DEV isolado com duas claims, uma verdadeira e outra apoiada por quote real mas conclusão falsa, deve demonstrar que o revisor consegue ver a diferença APÓS rodar, recuperando a evidencia pelos dois braços; testar vazamento, formato, hash e erro/timeout.
4. Pre-registrar mecanismo externo e separado para associar controles negativos e IDs proibidos (C3) **apenas na fase de julgamento**, por avaliador autorizado; isso nao deve contaminar modelo ou juiz.
5. Depois de corrigir e testar 200+ testes, **novo congelamento PRE-RUN** do runner, fonte de prompts, indices, spec, protocolo de escrow, modelo e hashes. Nao chamar v5 ate novo freeze; o v5 permanece inalterado. Se necessitar trocar scripts, invalidar apenas hashes do runner e documents pre-run, nunca alterar v5.
6. Obter aprovacao explicita do operador para esta rodada v5 (a folha D1–D4 dispensou assinatura formal da adjudicacao, nao necessariamente consentimento do experimento futuro). Abrir GO QA somente depois de tudo.

## Ordem ao OpenCode
**Segurar baseline -> candidate.** Solicitar ao Codex ajuste apenas do runner de medicao/escrow em fixture publica DEV e testes. Nao alterar produção, Gate D, v5 ou gabaritos. Retornar hashes re-congelados, demonstracao de pacote factual revisavel e ato de aprovacao humana para reavaliacao GO/NO-GO.

Este documento registra o bloqueio metodológico, nao uma ordem para executar testes de rede ou a rodada cega.
