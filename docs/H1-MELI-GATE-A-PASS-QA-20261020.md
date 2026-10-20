# MITR3 — Portão A MercadoLibre — Parecer final QA: PASS
Data: 2026-10-20. Emissor: GPT-6 QA. Maestro: OpenCode. Programa: mercadolibre (33462). Base: spec v4, commit `ad63aca`.

**VEREDITO: PASS para especificação/escopo e transição à fase de planejamento do Portão B; NÃO libera testes ativos ou submissões.**

- Conferido no extrato local paginado (4 páginas), SHA256 `146d115e8b0ad9f3da81efa7a3c284c042c1b3a3660f4f4d8ae3f6241f155d62`: 88 registros, 79 `eligible_for_submission`, 71 `eligible_for_bounty`.
- Tiers no atributo `instruction`: 27 Tier 1, 42 Tier 2 (incluindo 2 ZT), seis Kangu fora, demais conforme spec; `Crypto` sem tier atribuído, limitado a três URLs `/crypto/*` explicitadas.
- `Point Smart` Tier 1 MLA/MLB confirmado no extrato, mas **adiado integralmente** do plano de execução até definição formal de método/ambiente.
- Registro JEV no commit `ad63aca` contém decisões vinculadas a ativo (0.85 / 0.81 / 0.88 / 0.91; regras 0.81–0.92), sem flags declarados. **Esta QA verificou os registros na spec, não reexecutou a inferência nem atestou o trace bruto do provedor**. Manter IDs/digests auditáveis.
- Plano operativo em §7: manual/criativo sem scanners, brute-force ou enumeração em massa; limite interno conservador de 60 req/host/hora sem concorrência **não é autorização ou quota publicada pelo programa**; stop imediato sob sinais indicados.
- Signal 1.0, trial reports, identidade da conta e demais pré-requisitos permanecem **condições de submissão** verificáveis pelo operador, não motivo para impedir a elaboração do plano.
- `Leaked Credentials` é item específico de Tier 3; na API também consta ativo `Tier 3` genérico: tratá-los apenas sob as condições escritas da política, sem inferir autorização ilimitada.
- **Próximo passo:** planejamento documental e Portão B QA+JEV, verificando método concreto, ativo específico e limites. Enquanto Portão B não aprovar, `execution=STOP`; sem scans, teste ativo ou relatório H1.
- Este documento supersede somente o **veredito QA FAIL** do Portão A anterior, preservando-o para auditoria. Nenhuma alteração do escopo bruto ou política.
