# MITR3 — Pipeline de Prospecção & Dealflow

**Estado em 11/11/2026:** há **15 empresas candidatas com fonte oficial registrada, 0 leads validados e 0 contatos autorizados**. As fontes confirmam a existência de produtos/plataformas digitais; não confirmam demanda por serviço, intenção de compra, elegibilidade de ativos ou autorização. Não usar os registros antigos `LEAD-001` e `LEAD-002`: eram placeholders sem empresa, contato ou fonte e foram removidos.

O tracker `dealflow-leads.csv` é a fonte de verdade. Um registro só entra como lead validado quando contém fonte pública verificável, data de coleta e critério objetivo de qualificação. Nome de empresa sem sinal de necessidade é apenas candidato e não deve ser contabilizado como lead qualificado.

## Lanes

| Lane | Entrada | Conversão | Limite |
| --- | --- | --- | --- |
| **A — Serviços** | Inbound, indicação ou pesquisa pública de empresas | Qualificação → proposta → aceite → execução | Nenhum contato até aprovação do operador; nenhum teste ativo antes de autorização e escopo assinados. |
| **B — Bug bounty** | Programa público com política e escopo publicados | Triagem → análise dentro do escopo → revisão humana → submissão | O programa autoriza apenas o escopo e as técnicas que declara; política MITR3 mais restritiva prevalece. |

## Status verificáveis

| Estado | Critério |
| --- | --- |
| `candidato` | Empresa e produto/plataforma confirmados em fonte pública; sinal comercial ainda não qualificado. |
| `validado` | Empresa, fonte, data e critério registrados; encaixe com o serviço confirmado por evidência pública. |
| `não_verificado` | Informação insuficiente ou fonte indisponível; não contar como lead. |
| `descartado` | Fora do perfil, fonte fraca, duplicado ou sem autorização para prosseguir. |

Campos pessoais (nome, e-mail e telefone) ficam vazios até existir fonte pública adequada e necessidade operacional. Não coletar dados sensíveis nem registrar detalhes de vulnerabilidade de terceiros no CSV. Usar apenas metadados e links públicos.

## Qualificação de serviços

Sinal mínimo para qualificar: serviço/produto público compatível com a oferta, evidência pública datada e próximo passo permitido. Não inferir exposição vulnerável a partir do setor, do domínio ou de uma notícia genérica. Não classificar uma empresa como afetada sem prova específica.

O pacote Standard de R$ 3.490 está **proposto, não aprovado**. O rascunho atual limita-se a até 5 URLs web e 5 grupos de rotas de uma API, com prazo proposto de 3 dias úteis após escopo, autorização e pré-requisitos completos. A proposta precisa de aceite comercial e revisão jurídica antes de ser enviada.

## Regras de operação

- A pesquisa comercial é passiva e usa fontes públicas. Não enumerar, varrer ou testar ativos de prospect.
- Não enviar e-mails, mensagens ou propostas sem autorização explícita do operador.
- Não alegar casos de sucesso, estatísticas de mercado, disponibilidade de atendimento ou canais de contato sem evidência e aprovação.
- No mínimo, cada registro deve ter `empresa`, `origem`, `fonte_url`, `data_coleta`, `lane`, `status_verificacao`, `criterio_qualificacao` e `proxima_acao`.
- Uma proposta enviada exige ativos nominados, autorização expressa, janela de teste e regras de engajamento assinadas em `docs/SCOPE.md`.

## Próximas ações

1. Hunter: qualificar passivamente os 15 candidatos por segmento e sinal público de necessidade; documentar evidência específica antes de mudar qualquer status. Sem contato, enumeração ou teste.
2. Scribe: revisar a proposta Standard como documento de trabalho, mantendo preço e SLA identificados como proposta.
3. Operador: aprovar qualquer primeiro contato, preço, escopo, canais e termos finais.

Até que a qualificação seja sustentada por evidência, o pipeline tem **15 candidatos, 0 leads validados e 0 contatos autorizados**.
