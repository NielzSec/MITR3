# Auditoria cruzada MITR3 — estado e correções

**Data da verificação:** 11/11/2026; primeira fotografia às 18:12 BRT, correções complementares nesta sessão<br>
**Origem:** auditoria read-only publicada em [#all-mitr3 às 17:59:57](https://mitr3.slack.com/archives/C0C9ZLLU094/p1794430797701889).<br>
**Escopo:** GitHub/checkout, host e sessões Orca, Hackbots, pipeline comercial, evidências de QA e MITR3-WEB.

## Resultado executivo

O Graph C1–C4 está integrado nos refs remotos informados pela auditoria e recebeu QA independente para os lotes descritos nos relatórios. A inspeção adicional confirmou que a C4 revalidava os arquivos de evidência, mas não o snapshot C3 a que se aplicavam; a nova implementação vincula evidências ao snapshot e faz registros antigos sem vínculo falharem fechados. A migração operacional não foi executada. A release `main` e `master` operacional estão em commits distintos por política; nenhum ref foi alterado nesta verificação.

As correções locais incluem o vínculo C4→snapshot C3, migração explícita do schema, documentação operacional e materiais comerciais mais fiéis à evidência. A mudança de runtime foi validada somente com os testes C4 afetados; nenhuma outra suíte foi repetida. Não houve alteração do banco operacional, branch, processo ou serviço remoto.

## Achados e estado

| Área | Estado | Evidência e correção |
| --- | --- | --- |
| **Git e preservação** | **PARCIAL — reconciliação pendente** | `git ls-remote` mostrou `origin/main=5c00ff4` e `origin/master=3e07ec2`. O checkout ativo `/home/nielz/MITR3/MITR3` está em `master@3e07ec2`, com alteração local em `wrangler.jsonc` (`name: mitr3-web`) e arquivos não rastreados em `labs/jailbreak-forge/`. O clone externo `/home/nielz/MITR3` está em `dc499e2`; seu `ahead 5 / behind 6` refere-se à ref local em cache (`origin/master=e4ec5c7`), e ele tem 15 arquivos modificados, 3 removidos e 292 não rastreados. Não foi atualizado, limpo ou sobrescrito. Os worktrees Orca Graph em `21213cf` têm mudanças de código e relatórios locais ainda não integrados; foram preservados. Alterações e novos caminhos em `evidence/ctf/` surgiram após a fotografia inicial e continuaram aparecendo em snapshots posteriores; não fazem parte deste lote e não foram lidos nem alterados, com autoria a confirmar. VANTA deve reconciliar cópias por mapa de commits/diffs antes de qualquer integração. |
| **Memória do host** | **CONFIRMADO — redução ainda não executada** | Às 18:12, `free -h` observou 2,8 GiB disponíveis e 17/19 GiB de swap usados; às 18:20, 3,2 GiB disponíveis e 17/19 GiB de swap. A amostra `ps` das 18:12 agrupou 55 `node-MainThread` (~3,2 GiB RSS), 15 `orca-ide` (~1,6 GiB), 9 `agy` (~1,6 GiB), 7 `opencode` (~1,2 GiB), 5 `hermes` (~293 MiB) e 3 `codex` (~420 MiB). A fotografia Orca do worktree principal mostrava 19 terminais, 2 agentes `working` e 17 `done`. Os terminais dos dois workers Graph constam como órfãos/done, mas seus worktrees ainda têm alterações locais. O vínculo PID ↔ terminal/árvore ↔ proprietário não foi fechado para todos os processos; nenhuma sessão foi parada. Não encerrar esses terminais antes de preservar e reconciliar os artefatos. |
| **Morfeus ↔ Orca ↔ Runner** | **PENDENTE / NÃO DEMONSTRADO** | `bots.json` declara Morfeus/OpenCode e limite de dois workers. Na fotografia, o agente chamado `MORFEUS` aparecia como tipo Antigravity. Scripts de Runner existem, mas não foi localizado run ID nem log sanitizado de handoff completo. Não iniciamos missão só para fabricar evidência. |
| **Hackbots** | **PARCIAL — documentação corrigida** | `bots.json` registra 15 papéis; registro e `default_state` não demonstram implementação, configuração no host ou execução. O `hackbots/README.md` ausente foi criado com os limites offline da fase 0 e definições separadas de implementado/configurado/ativo/executando. O status atual de integração continua não demonstrado. |
| **Pipeline comercial** | **PENDENTE — 15 candidatos, 0 leads validados** | O CSV continha duas linhas placeholder sem empresa ou fonte; elas foram removidas. O esquema agora registra fonte, data e validação, e há 15 empresas com páginas oficiais sobre suas plataformas/API. Isso comprova apenas a existência dos produtos, sem sinal de demanda, intenção de compra, ativos elegíveis ou autorização. Todos seguem como `candidato`; contato e teste não ocorreram e não estão autorizados. A proposta Standard e o one-pager continuam como rascunhos não aprovados. |
| **Contagens de QA da release** | **PENDENTE — evidência de execução incompleta** | A publicação de release em 17:39 reporta 111 testes e 128 subtestes em `5c00ff4`; não inclui comando integral, ambiente ou log. R11 em #all-mitr3 reporta 185/185 e commit `a1109d4`; o documento local `docs/agentic-swarm/SLACK-DISPATCH-R11-20261111.md` ainda cita `34a6795`. Não há artefato de log que permita comparar os escopos ou explicar a diferença; os totais foram mantidos como resultados reportados, não reprodução independente. Relatórios Graph específicos documentam comandos e resultados anteriores; esses testes não foram repetidos. |
| **MITR3-WEB e indexação** | **PARCIAL — `noindex` confirmado** | `reports/mitr3-web-frontend-audit.json` registra análise estática aprovada dos bundles e hashes remotos, mas não é prova de 14 rotas E2E. O build local contém 14 páginas HTML, todas com `noindex,nofollow`; uma leitura GET atual da raiz `workers.dev` retornou HTTP 200 e a mesma meta. Mantivemos a indexação bloqueada e não fizemos deploy. O domínio `mitr3.com` e e-mail permanecem pendentes conforme o status publicado no Slack; não houve compra, DNS ou configuração de e-mail. |
| **C4 — escopo da evidência** | **FIX NO CÓDIGO — 46/46 + QA APPROVE; MIGRAÇÃO OPERACIONAL PENDENTE** | Evidências novas recebem `graph_snapshot_sha256`, e `verify`/`list` só contam artefatos íntegros e não revogados vinculados ao snapshot C3 atual. Snapshot divergente aparece como `STALE_GRAPH`; linhas C4 v1 antigas aparecem como `UNBOUND_GRAPH` e não contam. O schema v1 exige `migrate` explícito; preserva as linhas históricas, rebaixa `FEASIBLE_PATH` e mantém `PROVEN`. A suíte C4 afetada passou 46/46 e uma revisão independente read-only aprovou a migração e o rebuild v1/v2. A migração operacional não ocorreu. |

## Ações realizadas neste lote

- Atualizei o `README.md` para separar papéis declarados de estado operacional, substituir “matematicamente comprovado” e “75/75 operacionais” por linguagem verificável e apontar a limitação C4.
- Criei `hackbots/README.md` para registrar o piloto offline, a semântica do registry e os estados operacionais.
- Removi placeholders do CSV, acrescentei campos de proveniência/qualificação e registrei 15 candidatas com fonte oficial, sem contatos pessoais ou estimativas de ativos.
- Reescrevi a proposta Standard e o one-pager como rascunhos internos, com limites, exclusões, critérios de aceite, prazo e preço claramente propostos.
- Vinculei evidências novas da C4 ao snapshot C3, fiz evidências antigas sem vínculo falharem fechadas e adicionei migração v1 explícita que preserva o histórico sem revalidá-lo retroativamente, rebaixa `FEASIBLE_PATH` e mantém `PROVEN`.
- Acrescentei cobertura para invalidação por snapshot, migração C4 v1 com rebaixamento de `FEASIBLE_PATH`/preservação de `PROVEN` e rebuild preservando histórico v1/v2; executei somente a suíte C4 afetada (46/46) e recebi revisão independente read-only APPROVE.
- Preservei mudanças locais, worktrees, processos, releases e configurações remotas. Alterações CTF que surgiram na árvore durante esta auditoria ficaram fora do diff e não foram lidas nem modificadas.

## Próximos passos seguros

1. **VANTA:** produzir mapa de commits/diffs das duas cópias e dos worktrees, sem `reset`, `clean`, checkout destrutivo ou sobrescrita; só então propor reconciliação.
2. **Operação:** relacionar PIDs aos terminais e tarefas antes de reduzir processos. Sessões concluídas só podem ser fechadas depois que seus diffs e relatórios exclusivos estiverem preservados.
3. **Morfeus/Orca:** anexar evidência de um handoff real já existente; se não existir, manter o status como pendente e aguardar decisão para construir/rodar integração.
4. **Hunter/Scribe:** qualificar passivamente os 15 candidatos com evidência específica de aderência e revisar a proposta; primeiro contato continua dependente de aprovação do operador.
5. **QA:** anexar logs originais, ambiente, comando, commit e hashes para as alegações `111/111` e `185/185`; não repetir as suítes enquanto os resultados existentes não forem esclarecidos.
6. **MITR3-WEB:** manter `noindex` até QA de rotas e aprovação explícita; nenhum domínio ou e-mail é anunciado como operacional.
7. **C4:** revisar independentemente e integrar a mudança de código; antes de operar o banco existente, fazer backup e executar a migração explícita. Evidências antigas continuam sem contagem até nova análise no snapshot atual.

## Limites desta verificação

Os estados de memória são uma fotografia pontual e RSS pode incluir páginas compartilhadas; ainda falta atribuição de cada PID ao terminal correspondente. A checagem web confirmou somente a raiz publicada e o conteúdo local das 14 páginas, não repetiu a suíte de rotas. Não foram executados health checks, missões, varreduras, migração do banco operacional ou alterações Cloudflare.
