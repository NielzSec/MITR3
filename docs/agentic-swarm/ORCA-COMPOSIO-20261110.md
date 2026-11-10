# MITR3 — evolução de equipe e integração Composio

Data: 10/11/2026, America/Sao_Paulo.
Estado: Orca escolhido pelo operador e catálogo MITR3 atualizado; vínculo do projeto ao runtime ainda não verificado.

## Objetivo do operador

Evoluir para uma equipe de agentes que decompõe objetivos, escolhe métodos,
consulta especialistas, discorda com evidências e adapta o plano. Especialistas
são instanciados conforme a necessidade; oito nomes no catálogo não são um teto.
Decisões técnicas de rotina ficam com a equipe. Perguntas ao operador ficam para
informação indispensável, mudança material de escopo ou decisão que só ele pode tomar.
Contexto curto por tarefa; ferramentas e skills carregadas conforme a necessidade.
Verificação proporcional à mudança, reaproveitando evidências anteriores válidas.

## Base conferida nesta etapa

- Slack #all-mitr3 lido antes do trabalho: último fechamento publicado é o R10.
- R10 aprovou um worker Codex para análise offline limitada; isso é a capacidade
  aprovada daquele runner, não a capacidade final desejada para toda a plataforma.
- `hackbots/bots.json`: coordenador Morfeus, oito especialistas e apoios Research/QA.
- Já existem contratos de missão/resultado, Skill Builder, Execution Verifier,
  MegaBrain e grafo Cairn. Reutilizar essas peças antes de criar outra infraestrutura.
- `health-20261110.json` registra falha de conexão MegaBrain e timeout do inventário
  OpenCode. É evidência histórica, sem nova prova de indisponibilidade nesta etapa.
  HTTP 401/403 em uma sondagem sem autenticação não prova credencial inválida.
- Composio não constava nas configurações locais Codex/OpenCode inspecionadas.
  Nenhum plugin Composio foi retornado pela busca no diretório desta sessão.

## Integração realizada

Adicionado `composio` em `the local Codex configuration file`, via comando oficial
`codex mcp add composio --url https://connect.composio.dev/mcp`.
O endpoint respondeu com descoberta OAuth; o login terminou com
`Successfully logged in.` Configuração confirmada por `codex mcp get composio --json`:
habilitado, Streamable HTTP, endpoint oficial, sem headers estáticos de credencial.
Configuração TOML válida e modo 0600; backup anterior privado em `.codex/backups/`.

Isso conecta o cliente Codex ao Composio. Em 10/11/2026, uma captura posterior do
operador mostrou YouTube, Reddit, LinkedIn e Cloudflare API Key com uma conexão ativa
cada. Um cliente Codex efêmero alcançou o catálogo Composio e encontrou esses quatro
toolkits configurados; a listagem detalhada das conexões exigiu aprovação e foi
bloqueada pela política `never`. O catálogo disponível ao modelo desta conversa ainda
não incluiu as ferramentas novas. Nenhum conteúdo ou ação de escrita foi acessado.
OpenCode, runner e configurações dos outros agentes não foram alterados.

Para integração dos workers, preferir sessões Composio por usuário/projeto,
contas explicitamente vinculadas e ferramentas selecionadas para a missão.
Filtrar só o nome de uma meta-ferramenta genérica de execução no cliente não
garante leitura apenas: a seleção precisa alcançar as ações upstream.

## Orca confirmado pelo operador

Produto: https://www.onorca.dev/ ; upstream: https://github.com/stablyai/orca .
A documentação apresenta CLI, agentes supervisionados, mensagens com ACK,
tarefas/dependências e identificadores separados para tarefa e tentativa.
Isso permite delegar e receber resultados sem exigir que o humano retransmita tudo.
Porém, a página de orquestração marca o recurso como experimental e informa que
o painel e seu interruptor estão temporariamente indisponíveis. Nenhuma versão
do Orca foi instalada ou validada aqui; disponibilidade real depende da versão escolhida.

O operador instalou Orca 1.4.255; o daemon foi observado ativo em 10/11/2026.
O guia `orca-cli` desta sessão pede `orca-ide` fora de terminal gerenciado no Linux,
mas esse executável não foi encontrado no PATH. A migração do catálogo e das
instruções do MITR3 foi feita sem assumir vínculo de projeto ou despacho real.
O operador forneceu capturas de um post de OccupytheWeb e do Qwen Code no Orca.
O artigo original do Hackers Arise, publicado em 06/11/2026, descreve um workspace
de reconhecimento e três auditorias paralelas por worktree: entradas,
autenticação/sessão e controle de acesso. Esse fluxo de organização manual de
agentes não depende de demonstrar o painel experimental de orquestração.
O material favorece um piloto concreto Orca com os CLIs existentes. Não representa
uma execução ou reprodução realizada pelo MITR3 nesta etapa.

Worktrees separam alterações Git. Não substituem isolamento de processos,
credenciais ou rede. Receitas de ambiente podem usar contêiner/VM em infraestrutura
do operador; isso é uma integração distinta, ainda não verificada para o MITR3.

## Divisão de responsabilidades proposta

| Camada | Responsabilidade |
|---|---|
| Orca, painel escolhido | Sessões, worktrees, ciclo de vida e transporte de mensagens |
| Morfeus ou coordenador designado | Escolher equipe, negociar subtarefas, resolver dependências e integrar resultados |
| Catálogo MITR3 existente | Descoberta de capacidades; separar especialidade lógica de instância de worker |
| Composio/MCPs existentes | Acesso a fontes e ferramentas de cada missão |
| Grafo Cairn / contratos existentes | Hipóteses, observações, tarefas e relações entre evidências |
| MegaBrain | Memória durável de resultados e métodos com proveniência |
| Runner / Execution Verifier / QA | Execução delimitada, reprodução e revisão independente quando relevante |

Uma missão tem um responsável pelo despacho. Orca e Cairn não devem despachar
independentemente o mesmo trabalho. A integração precisa mapear missão, tarefa,
tentativa e artefatos entre os sistemas antes de liberar trabalho automático.

## Colaboração que queremos observar

Exemplo: Research encontra um advisory no X; consulta a fonte original; registra
hipótese, fonte e incerteza. Infra compara a hipótese ao inventário local.
Se houver correspondência, o coordenador abre uma tarefa de laboratório offline.
Engenharia prepara a alteração; QA verifica o comportamento afetado; a equipe
registra a decisão, inclusive resultados negativos e trabalho inconclusivo.

Cada agente pode propor mudança de plano e pedir ajuda a outro especialista.
O que circula são hipóteses, justificativas verificáveis, evidências e decisões;
copiar históricos completos entre todos desperdiça contexto e propaga erros.
Um resultado assinado como concluído pelo worker continua distinguível de um
resultado revisado. Uma tentativa repetida não pode concluir a tarefa errada.

## Próxima fatia de implementação

1. Disponibilizar ao worker um subconjunto somente de leitura de Reddit, YouTube e
   LinkedIn. Manter Cloudflare fora da lane de pesquisa e registrar proveniência de
   cada coleta. Primeira tarefa: radar local com dados públicos salvos.
2. Confirmar o executável `orca-ide` e vincular o projeto MITR3 ao runtime já ativo;
   depois executar uma missão local pequena com despacho, mensagem, revisão e retomada.
3. Reutilizar o catálogo/contratos MITR3 para conectar esse fluxo à memória e ao
   runner. Expandir concorrência depois de medir recursos e corrigir gargalos.

Não houve alteração de prompts, skills ativas, limites do R10 ou permissões de
missões. Nenhum teste antigo foi repetido. Validações desta etapa: descoberta
OAuth, login real, configuração do servidor e parse/modo do TOML. A migração e
o fluxo multiagente proposto ainda exigem implementação e revisão independente.

## Fontes primárias consultadas

- https://docs.composio.dev/docs/composio-connect
- https://docs.composio.dev/docs/sessions-via-mcp
- https://docs.composio.dev/docs/agent-plugins
- https://developers.openai.com/codex/mcp
- https://www.onorca.dev/docs/cli/orchestration
- https://www.onorca.dev/docs/model/worktrees
- https://www.onorca.dev/docs/ways-to-run
- https://hackers-arise.com/artificial-intelligence-ai-in-cybersecurity-part-31-orchestrating-autonomous-multi-agent-exploitation-swarms-with-orca/
