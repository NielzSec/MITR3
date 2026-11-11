# MITR3 Hackbots — fase 0

**Estado:** piloto offline. Esta pasta descreve contratos, exemplos e ferramentas; sua presença não inicia agentes nem autoriza tráfego.

## Limites do piloto

- Análise apenas offline; não iniciar automaticamente LLMs, swarm, containers, servidores ou Ruflo.
- Até 2 workers por missão e aceite humano independente.
- O contrato de escopo em `docs/SCOPE.md`, as políticas do MITR3 e as regras do engajamento prevalecem sobre uma missão ou JSON válido.
- Não tratar hipótese, fixture ou resultado de modelo como finding confirmado.
- Skills novas ou alteradas passam pelo Skill Builder, Evaluator, QA independente e aceite humano; não criar `SKILL.md` manualmente em diretório ativo.

## Como ler o registry

`bots.json` é um catálogo declarativo de papéis, backends e ferramentas pretendidas. `default_state` e `backend` não atestam processos ou conexões reais. Não usar a quantidade de registros como quantidade de agentes operacionais.

| Estado | Evidência mínima |
| --- | --- |
| **Implementado** | Código executável e testes/contrato que cobrem a responsabilidade específica. |
| **Configurado** | Backend e ferramentas configurados no host correto, com permissões e conexão verificadas. |
| **Ativo** | Sessão autorizada identificada no Orca, com proprietário e tarefa conhecidos. |
| **Executando** | Missão com run ID, dispatch, branch/commit, caminho do Runner e log sanitizado de ida e volta. |

Esses estados são independentes. Uma entrada no registry prova apenas que um papel foi declarado.

## Leitura operacional de 11/11/2026

Na fotografia do Orca feita durante a auditoria cruzada, o worktree principal mostrava 19 terminais e dois registros de agentes em estado `working`. Um deles aparecia como `MORFEUS`, mas o tipo de agente da sessão era Antigravity; isso não comprova Morfeus/OpenCode como coordenador lógico. Os dois workers Graph estavam `done`, porém seus worktrees ainda continham alterações locais não integradas. Eles e os demais artefatos devem ser preservados até a reconciliação.

Não foi localizado run ID nem log sanitizado que demonstre um fluxo Morfeus → Runner → agente → retorno. Portanto, a integração permanece **PENDENTE / NÃO DEMONSTRADA**. Não iniciar outra missão apenas para gerar essa prova.

## Referências

- `bots.json`: registro declarativo de papéis e limites.
- `contracts/`: schemas de missão, resultado e steering.
- `examples/`: fixtures offline; exemplos não são dados de alvo.
- `docs/MITR3-CROSS-AUDIT-20261111.md`: fotografia de estado, evidências e pendências.
- `docs/SCOPE.md`: contrato humano de escopo.
- `hackbots/team/SKILL-BUILDER-ONLY-POLICY.md`: política de proveniência e certificação de skills.
