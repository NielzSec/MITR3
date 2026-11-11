# MITR3 — Pipeline de Prospecção & Dealflow (2026-11-11)

Alinhado à landing page e ao one-pager (`ONE-PAGER-ATTACK-SURFACE-EXPRESS.md`).
Esteira: `docs/commercial/dealflow-leads.csv` (fonte única de verdade; mover lead = editar linha).

## Duas lanes de dealflow

| Lane | Entrada | Conversão | Métrica-chave |
| :--- | :--- | :--- | :--- |
| **A — Clientes (serviços)** | Landing page, outbound, indicação | Proposta → aceite → execução → upsell | Taxa de fechamento por pacote |
| **B — Bug bounty** | Programas públicos (HackerOne, Bugcrowd, Intigriti, VDP) | Caça → report aceito → bounty → reputação → referência para Lane A | Bounty médio, aceitação de reports |

Lane B alimenta a Lane A: reputação em plataformas + casos de sucesso (como Cimapi e Costa Lavos no one-pager) viram prova social.

## Lane A — Estágios (0 a 5)

| # | Estágio | Critério de saída |
| :--- | :--- | :--- |
| 0 | **Lead** | Contato identificado (landing, LinkedIn, WhatsApp, indicação, scrub de superfície exposta com LGPD ok) |
| 1 | **Qualificado** | ICP match + decisor mapeado + dor declarada (ver qualificação abaixo) |
| 2 | **Diagnóstico/Prova** | Oferta de mini-diagnóstico passivo ou demo de achado público (sem teste ativo sem autorização) |
| 3 | **Proposta enviada** | `EXECUTIVE-PROPOSAL-TEMPLATE.md` preenchida com pacote e escopo |
| 4 | **Aceite** | Termo assinado + 50% + escopo formal (`docs/SCOPE.md`) |
| 5 | **Entrega/Upsell** | Relatório entregue + debriefing feito + follow-up (reteste, plano anual, indicação) |

### Qualificação (ICP por pacote)

| Sinal | → Pacote |
| :--- | :--- |
| 1–3 domínios, PME, sem time de SEC dedicado | **Express Starter R$ 1.850 / 24h** |
| 4–10 domínios + APIs, time de TI interno, compliance (LGPD) | **Business Standard R$ 3.490 / 48h** |
| Escopo em nuvem, reteste, multiente, recorrência | **Enterprise (sob consulta)** |

Perguntas de qualificação mínima: quantos domínios/app expostos? Já sofreu incidente ou acha? Quem decide e quando? Orçamento aprovado?

### Regras de front-end comercial

- Prospecção passiva apenas (OSINT público); **nenhum teste ativo sem contrato e escopo assinado** — usar achado passivo como gancho de demo.
- Dados de lead: nome, empresa, contato, origem. Sem evidências de vulnerabilidade de terceiros dentro do tracker (link para evidência no MegaBrain/hash, nunca colar payload).
- SLA de resposta a inbound: 24h (coerente com promessa de entrega de 24h).

## Lane B — Bug bounty

| # | Estágio | Critério de saída |
| :--- | :--- | :--- |
| 0 | **Programa triado** | Programa ativo, escopo web/API, recompensa ≥ alvo do squad |
| 1 | **Recon & inventário** | Superfície mapeada (skills `mitr3-hb-js-inventory`, scope gate) |
| 2 | **Caça** | Duplicatas filtradas; candidatos com evidência + hash |
| 3 | **Report submetido** | Report dentro do escopo do programa, revisão humana antes do submit |
| 4 | **Resolvido** | Bounty pago / duplicata / informative — registrar valor e lição |
| 5 | **Alavanca** | CVE/write-up (com aprovação do operador) → conteúdo para landing e outbound |

Lanchar Stage 0 só com o gate de escopo (programa define autorização; MITR3 RoE superior).

## Cadência operacional

- **Semanal**: revisar CSV — tudo em Stage ≥2 há >14 dias precisa de ação ou descarte.
- **Mensal**: 1 case de sucesso → atualizar one-pager/landing; reconciliar bounties Lane B.
- Origem de leads nova só entra no CSV se tiver um canal repetível (landing, indicação, plataforma).

## Status inicial

- [x] Documento-mestre + tracker criados
- [ ] Primeiras 10 leads Lane A carregadas (outbound/indicações Cimapi, Costa Lavos)
- [ ] Lane B: consolidar lista de programas alvo (ex.: MELI #33462 em andamento) no CSV
- [ ] Formulário/CTA da landing gravando direto no CSV (integração futura)
