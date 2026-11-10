# Hackerbots — contratos de estados e gates

## Persistência, execução e avaliação são dimensões separadas

Contratos ativos: `contracts/mission.schema.json`, `contracts/result.schema.json` e
os formatos estritos de Policy/IPC, trace, manifest e outcome. Não renomear valores
históricos sem versão e migração revisadas.

| Conceito | Valores atuais / significado |
| --- | --- |
| Draft | PENDING no manifesto; auditoria REVIEW/FAILED, nunca promote |
| Sessão persistida nova | SESSION_RECORDED; Broker finalizou, verificação ainda não inferida |
| Manifesto legado | REVIEW aceito como sessão, não resultado autenticado |
| Outcome local | VERIFIED/FAILED/BLOCKED; vinculado ao hash do manifesto |
| Falha de execução | BLOCKED/TIMEOUT em failure store; evidência parcial não vira sucesso |
| Resultado do contrato v0.1 | blocked/review_pending/accepted/rejected; campos de aprovação são declarações |
| Ciclo completo futuro | PENDING → PREPARING → RUNNING → COLLECTING → SESSION_RECORDED → VERIFYING → REVIEW; falhas para FAILED/BLOCKED/TIMEOUT/CANCELLED |

O ciclo completo é PROPOSTO. CANCELLED e as etapas intermediárias não são um state
machine persistente implementado. Não adicionar estes estados aos schemas por semelhança.
Ausência de outcome = consulta RECORDED_SESSION_AWAITING_OUTCOME; nunca inferir VERIFIED.

## Definição objetiva dos gates

| Gate | O que mede | Limite e estado atual |
| --- | --- | --- |
| sandbox_gate | Probes de confinamento observados no host | SELFTEST_OK local; não VM nem proteção de processo externo same-UID |
| trace_gate | Forma/seq/hashes/intervalos consistentes | PASS não prova autoria ou consumo de bytes |
| trace_authenticity | Produção/custódia sob fronteira validada | NOT_VERIFIED; F01 OPEN |
| coverage_gate | União de bytes cobrindo unidades LF recalculadas | PASS/FAIL/NOT_APPLICABLE; não compreensão |
| output_gate | Igualdade de saída com oráculo da suíte fixada | NOT_RUN no runner; Evaluator separado com fixtures |
| behavioral_gate | Execução correta de metodologia/skill monitorada | NOT_RUN |
| independent_review | Revisor distinto examinou evidências e mudança | PENDING; autor não autoaprova |
| human_approved | Aceite real de operador por canal independente | false |
| promotable | Requisitos de promoção satisfeitos e autorizados | false; comando de promoção ausente |

`deterministic_oracle: PASS` no runner só compara hash/tamanho/linhas. `outcome:
VERIFIED` continua decisão local, sem autenticação externa. Não transportar PASS entre
gates, não contar SKIP como PASS e não usar READY como certificação de segurança.

## Autorização

Níveis 0 estudo, 1 offline, 2 laboratório, 3 testes externos autorizados e 4 ações
sensíveis são taxonomia PROPOSTA. Não concedem permissão. Contrato Nexus e regras
concretas do programa continuam superiores. Para este roadmap, só preparação offline
com fixtures sintéticas; F01 não implantado e nenhuma execução externa autorizada.
Router seleciona capacidade; política fora do modelo decide; ferramenta aplica limites;
verificador mede; pessoa aceita. JEV experimental não muda política ou autorização.

## F07 — schema canônico e incompatibilidade conhecida

A [especificação Agent Skills](https://agentskills.io/specification) permite
`compatibility` (1..500 caracteres), além de name/description e opcionais definidos.
O quick_validate.py local do Codex, fora do repositório, exclui esse campo de sua
allowlist. PyYAML no venv resolveu a dependência, mas não essa divergência. Estado:
OPEN / tooling compatibility; não é demonstração de skill inválida.

Não apagar metadata válida ou ampliar campos arbitrariamente. Próxima correção
revisável: selecionar validador aderente à especificação ou adaptar a allowlist no
componente apropriado com testes positivos/negativos, fixando sua versão. Não alterar
ferramenta global silenciosamente. A validação nesta entrega registra ambos os resultados.
