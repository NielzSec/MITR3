# Orca ↔ MITR3 Hackbots

**Decisão de 10/11/2026:** Orca é o painel, transporte de mensagens, sessões e
worktrees da equipe. Morfeus/OpenCode continua responsável por decompor missões,
atribuir trabalho e integrar resultados. O catálogo `../bots.json` declara papéis,
sem criar terminais ou conceder permissões automaticamente.

Uma missão MITR3 usa os contratos existentes em `../contracts/`, registra escopo e
hashes e tem um único responsável pelo despacho. A tarefa e a tentativa no Orca
devem apontar para a missão e seus artefatos. O dispatcher Cairn não recebe o mesmo
trabalho em paralelo. A revisão independente e o aceite humano continuam etapas
distintas da conclusão declarada pelo worker.

O piloto Hackbots permanece offline, com até dois workers e as capacidades reais
do runner descritas em `../runner/README.md`. Worktrees separam alterações de código;
execução e rede continuam limitadas pelos controles do MITR3 e pelo contrato Nexus.

O operador instalou Orca 1.4.255 e o processo daemon foi observado ativo neste host.
O guia `orca-cli` desta sessão manda usar `orca-ide` no Linux fora de um terminal
gerenciado, mas esse executável não está no PATH. Por isso o vínculo de projeto,
mensagens e lifecycle no Orca ainda não foram verificados por CLI nesta migração.
Não afirmar que os nove papéis do catálogo são sessões em execução.

O documento [MAESTRI.md](MAESTRI.md) e os relatórios anteriores são históricos.
O antigo `team/DISPATCH_GUIDE.md` também é histórico: seu hash é citado em uma
skill candidata e seus exemplos `maestri ask` não devem ser executados.
