# MITR3 — decisão Rust + Python e produto Intelligence Radar

**Data:** 10/11/2026  
**Estado:** decisão arquitetural; nenhuma reescrita de runtime executada  
**Objetivo:** converter pesquisa contínua em um produto recorrente e evoluir o
núcleo de execução somente onde Rust traz ganho mensurável.

## Decisão

O MITR3 adota Rust + Python como arquitetura padrão para novos componentes, sem
reescrever projetos por linguagem. Rust será a primeira opção para supervisão de
processos, concorrência CPU-bound, limites de recursos, protocolos, parsers de
entrada não confiável e caminhos em que latência ou memória precisem de previsibilidade.
Python permanece como primeira opção para políticas, conectores MCP/Composio,
pesquisa, modelos, análise, relatórios e composição rápida de ferramentas.

Cada migração exige um perfil ou benchmark do caminho afetado, um contrato de
compatibilidade e uma revisão independente. A fronteira inicial será processo +
JSON/JSONL ou IPC local. PyO3 fica reservado a hotspots medidos que realmente
precisem de chamada no mesmo processo; isso evita acoplar empacotamento e falhas
nativas ao orquestrador antes da necessidade.

Esta decisão vale como direção para os projetos MITR3. Código existente continua
na linguagem atual enquanto cumprir orçamento, confiabilidade e segurança.

## Evidência técnica local

- O host tem `rustc` e `cargo` 1.99.1.
- O Python é 3.14.8, porém `sys._is_gil_enabled()` retornou `True` e
  `Py_GIL_DISABLED` retornou `0`.
- O runner canônico tem aproximadamente 2.037 linhas Python em
  `hackbots/runner/`. Ele supervisiona subprocessos, sessões, deadlines, cgroups,
  encerramento de descendentes, quotas, protocolo e hashes de evidência. É o
  primeiro candidato natural a um núcleo Rust.
- O MITR3 canônico ainda não possui crate Rust próprio. Os arquivos Rust
  encontrados pertencem principalmente a dependências de laboratório de firmware,
  como binwalk e unblob, e não contam como migração do núcleo.
- O grafo de ataque usa SQLite e hashing em um fluxo local delimitado. Sem perfil
  que demonstre gargalo, ele permanece em Python.

O Codex oficial usa um workspace `codex-rs` e seu núcleo atende interfaces Rust.
Isso comprova o uso de Rust no Codex, não uma substituição geral de C++ em todos os
produtos. O CPython 3.14 também oferece build free-threaded oficialmente suportada,
mas ela não é padrão, extensões incompatíveis podem reativar o GIL e há custo de
execução. Portanto, o GIL é um dado de projeto, não uma razão suficiente para
reescrever todo o sistema.

## Primeiro produto fixo: MITR3 Intelligence Radar

O primeiro produto recorrente será um radar de inteligência técnica para equipes
pequenas de software e segurança. Ele transforma sinais dispersos em decisões:

1. coleta autorizada em Reddit, YouTube, LinkedIn, advisories de fornecedores,
   CVEs e fontes primárias;
2. normalização, deduplicação e preservação de URL, data e proveniência;
3. verificação do sinal na fonte primária;
4. correlação com a stack e o inventário informado pelo cliente;
5. priorização por exposição, explorabilidade, impacto e confiança;
6. entrega em painel e relatório periódico, com alertas somente quando houver
   mudança relevante.

Posts sociais são leads, nunca achados ou fatos finais. Um alerta pago deve mostrar
o que mudou, por que pode afetar o cliente, a fonte primária, a confiança e a ação
recomendada. Essa proposta aproveita MegaBrain, Cairn, contratos, grafo e QA já
existentes, em vez de vender quantidade de agentes.

### Oferta inicial

| Plano | Entrega | Hipótese a validar |
|---|---|---|
| Radar semanal | resumo priorizado, fontes e ações | aquisição de primeiros usuários |
| Radar por stack | correlação com tecnologias do cliente e alertas de mudança | receita recorrente principal |
| Radar + análise | triagem humana e sessão mensal de remediação | plano de maior valor |

Preço será definido depois de cinco entrevistas e dois pilotos locais com dados
públicos. Não há promessa de receita, cobertura total ou detecção em tempo real.

## Integrações Composio

A captura fornecida pelo operador mostra YouTube, Reddit, LinkedIn e Cloudflare API
Key com uma conexão ativa cada. Um cliente Codex efêmero alcançou o catálogo do
Composio e encontrou os quatro toolkits configurados; a consulta detalhada do estado
foi bloqueada pela política de aprovação do cliente. Nenhuma postagem, perfil,
mensagem, vídeo, arquivo, segredo ou ação de escrita foi acessada.

O worker de pesquisa receberá apenas ferramentas de leitura de Reddit, YouTube e
LinkedIn. Cloudflare pertence à lane operacional de publicação e não entra no
contexto de pesquisa. Essa separação será feita no roteamento das ferramentas, sem
depender de prompts longos.

## Fronteira de implementação

| Componente | Linguagem | Motivo |
|---|---|---|
| `mitr3-runner-core` | Rust | processos, cgroups, deadlines, IPC, quotas e encerramento de árvore |
| broker/protocolo de eventos | Rust, contrato JSON/JSONL versionado | validação de entrada e comportamento previsível |
| evidência e hashes | Rust no runner; Python nos consumidores | custódia no limite de execução, análise flexível acima |
| orquestração e políticas | Python | iteração rápida e ecossistema de agentes/MCP |
| conectores sociais e de pesquisa | Python | APIs e schemas mudam com frequência |
| correlação, relatórios e MegaBrain | Python inicialmente | não há gargalo medido |
| parser CPU-bound futuro | Rust/PyO3 após perfil | extensão pequena, interface estreita |

O Rust não recebe credenciais de provedores no primeiro corte. O runner recebe um
contrato de tarefa já autorizado, executa o processo delimitado e devolve eventos e
evidências. Decisão de missão, autorização e promoção de achados continuam fora do
núcleo nativo.

## Plano de entrega

1. **Radar local:** ingerir um conjunto salvo de fontes públicas, deduplicar,
   exigir fonte primária e produzir um relatório de exemplo sem acessar contas.
2. **Leitura Composio:** expor ao worker somente operações de leitura das três
   fontes sociais e registrar origem, timestamp e identificador da chamada.
3. **Piloto do produto:** executar duas edições semanais para uma stack fictícia e
   medir relevância, falsos positivos, tempo de triagem e custo por alerta útil.
4. **Contrato do runner:** congelar fixtures JSON/JSONL e resultados atuais; medir
   throughput, RSS, tempo de encerramento e contenção de descendentes.
5. **Slice Rust:** portar supervisão e protocolo, mantendo a CLI Python compatível;
   comparar com a baseline e submeter a QA independente.
6. **Expansão:** migrar somente o próximo hotspot comprovado. Outros projetos adotam
   a mesma regra quando forem alterados, sem conversão em massa.

## Critérios de sucesso

- um alerta leva a uma decisão concreta e cita fonte primária;
- nenhuma conclusão nasce apenas de postagem social;
- custo e tempo de triagem por alerta são conhecidos;
- o slice Rust mantém os contratos e controles atuais;
- a migração melhora uma métrica definida sem reduzir cobertura ou QA;
- nenhuma integração de escrita fica disponível ao worker de pesquisa.

## Fontes primárias

- Python free threading: https://docs.python.org/3/howto/free-threading-python.html
- Python library/extension FAQ: https://docs.python.org/3/faq/library.html
- Codex build oficial: https://github.com/openai/codex/blob/main/docs/install.md
- Codex Cargo workspace: https://github.com/openai/codex/blob/main/codex-rs/Cargo.toml
- PyO3: https://pyo3.rs/main/

## Riscos e lacunas

- O catálogo Composio desta conversa não expõe diretamente as ferramentas recém-
  conectadas; o roteamento por worker ainda precisa ser implementado.
- A captura prova o estado exibido no painel, não a capacidade de cada operação.
- A baseline de desempenho do runner ainda não foi medida; iniciar a porta antes
  dela impediria atribuir qualquer melhora ao Rust.
- Licenças e termos de cada fonte precisam ser conferidos antes de oferecer coleta
  comercial contínua.
