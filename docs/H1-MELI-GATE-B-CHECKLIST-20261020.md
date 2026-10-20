# H1 — Checklist do Portão B (análise do plano)

**Data:** 2026-10-20 · **Maestro:** OpenCode · **Base:** spec v4 `ad63aca`, Portão A `PASS` (`534d5e1`)

## Entrada exigida

- `docs/H1-MELI-TESTPLAN.md` (deepseek) — plano de teste web/API.
- `docs/H1-MELI-MOBILE-PLAN.md` (Antigravity) — estático mobile.
- `docs/H1-MELI-TIER3-PLAN.md` (Robin) — leaks, passivo.
- `docs/H1-MELI-RECON-PASSIVE.md` (Gemma4) — reconhecimento passivo.
- `bin/mitr3-h1.py` (Codex) — cliente read-only e validador.

## Critérios de PASS (QA)

1. **Cobertura:** cada hipótese referencia ativo com `eligible_for_submission=true` dos 88; nenhum ativo fora, nenhum Kangu, nenhum `wow-int`.
2. **Método:** manual/criativo; ausência de scanner, fuzzer, brute force, enumeração em massa, DoS, GraphQL DoS, engenharia social, criação massiva de contas.
3. **Limites:** taxa e concorrência coerentes com §7 da spec; critérios de parada presentes e acionáveis.
4. **Contas:** test users quando aplicável; `PR:High` no CVSS; nenhuma credencial real; cartões de teste oficiais.
5. **Exclusões:** mobile exclusions, SDK MercadoPago/secure inputs, KYC, Melidolar, Collaborators, Point Smart adiado.
6. **Evidência:** request/response redigidos, passos numerados, impacto, CVSS 3.1, hash + UTC.
7. **Tier 3:** uma bounty por origem; confirmação com uma chamada não destrutiva; sem exfiltração; vínculo comprovado.
8. **Rastreabilidade:** cada tarefa tem dono, entrada, saída e limite; mudança de requisito volta à spec.

## Critérios de FAIL imediato

- Qualquer técnica proibida pelo programa.
- Qualquer ativo fora do escopo ou sem elegibilidade de submissão.
- Plano que dependa de acesso a dados de terceiros, credenciais reais ou persistência.
- Ausência de critérios de parada ou de formato de evidência.

## JEV no Portão B

Claims a medir com evidência vinculada (ativo/trecho da política):
1. "O plano usa apenas teste manual/criativo, sem varredura massiva." Evidência: trecho do plano + política.
2. "Todo ativo citado no plano está no extrato de 88 com submission=true." Evidência: lista de ativos do plano + extrato.
3. "Test users são usados com PR:High e sem credenciais reais." Evidência: trecho do plano.
4. "Critérios de parada cobrem 429/403, 5xx, WAF, PII e degradação." Evidência: trecho do plano.
5. "Point Smart está fora do plano ativo e Crypto limitado aos três caminhos." Evidência: trecho do plano.

`PASS` só com QA `PASS` **e** JEV sem flag não resolvido. `FAIL` devolve à fase 3.
