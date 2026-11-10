# Hackerbots — roadmap de capacidades

Estado: FOUNDATION_PREPARATION; nenhuma habilitação operacional. Este documento
substitui a ordem histórica de pilotos, não as regras de escopo. Índice técnico em
[arquitetura](HACKERBOTS-ARCHITECTURE.md), [papéis](HACKERBOTS-ROLES.md) e
[gates](HACKERBOTS-SECURITY-GATES.md).

| Fase / prioridade | Entrega | Dependência e critério de saída | Estado |
| --- | --- | --- | --- |
| A / P0 | Identidades, instalação/custódia confiável | Operador aprova pacote deploy; negação real entre UIDs e revisão independente | PROPOSTO / F01 OPEN |
| A / P0 | Consulta restrita | Launcher/units revisados, quotas e SO_PEERCRED testados no host | PREPARADO; NÃO IMPLANTADO |
| A / P1 | Contratos/autorização | Política fora do modelo; nenhum gate derivado de outro | PARCIAL: contratos e runner sintético existentes |
| A / P1 | Revisão de mudanças | Revisor diferente de autor, sem autoaprovação | PENDENTE |
| A / P3 | Validador de skills F07 | Resolver divergência de schema sem aceitar campos arbitrários | PENDENTE; fonte canônica identificada |
| B / P1 | Research + QA, coordenação Morfeus | Primeiro benchmark offline e oráculos revisados, F01 aceito antes de integração | ESPECIFICADO; NÃO HABILITADO |
| C / P2 | JS, Web e API Analysts | Benchmark separado por domínio; escopo, parser/ferramentas e falsos positivos medidos | PLANEJADO |
| D / P2 | Reverse Engineering | REA Guarded por operação, contrato por artefato, fixtures de laboratório | PLANEJADO |
| E / P3 | Fuzzing/Binary + Vulnerability Intelligence | Laboratório, harness/oráculos, limites/triagem, pesquisa rastreável | PLANEJADO |
| F / P3 | Missões com dependências e concorrência | Especialistas isolados medidos, recuperação/custo e revisão cruzada | BLOQUEADO pelas fases anteriores |

Regra de crescimento: um worker sintético por execução; não lançar os oito perfis.
O catálogo bots.json é inventário de papéis, não disponibilidade ou permissão. Seu teto
histórico de dois workers não habilita execução paralela. Antes de ampliar, medir CPU,
memória, tempo, custo e benefício no mesmo benchmark; comparar taxas de acerto com
contraexemplos e falsos positivos. Não selecionar modelo por reputação/preço presumido.

Próxima entrega habilitável: teste controlado de consulta com UID dedicado, aprovado
pelo operador; o pacote está em [deploy](../deploy/README.md). Preparação de benchmark
Research em [FIRST-RESEARCH-HACKERBOT.md](FIRST-RESEARCH-HACKERBOT.md) não executa agente.


## Atualização 2026-10-24 — Web evidence QA / PHP2Shell

Piloto Web: hackbots/tools/web_evidence.py valida offline a coerência
de metadados do laboratório SQLi da PortSwigger concluído pelo operador.
10 testes positivos/negativos, nenhum agente, HTTP ou execução de payload.
Sem atestar autoria de respostas HTTP ou comportamento do modelo.
Ver WEB-HACKERBOT-PILOT.md.

Pesquisa para futuro laboratório PHP2Shell: CVE-2026-109618/109619,
releases corrigidas, e terceiro aviso CVE-2026-115560. Nenhum container
foi puxado ou iniciado; plano de VM descartável + Docker isolado em
PHP2SHELL-LAB-PLAN.md. F01 e revisão independente continuam OPEN.
