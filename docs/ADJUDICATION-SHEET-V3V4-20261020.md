# MITR3 — Folha de adjudicação v3/v4 (QA × JEV)

**Data:** 2026-10-20 · **Preparação:** OpenCode (maestro) · **Decisão:** Kai (operador humano)
**Base:** laudo `GPT6-EVIDENCE-QA-V3V4` (sha a34ff665) + trilha JEV (`reports/jev-v3v4-review-20261020.json`, sha be496a1d) + reconciliação `GPT6-JEV-QA-RECONCILIATION` (sha 72b07c8c).

## 1. Divergências que exigem tua assinatura

| # | Claim | QA | JEV | Sonda independente (maestro) | Leitura |
|---|---|---:|---|---|---|
| D1 | `v4p2-06c2` — distinção poisoning/deception | 2 | 0.32 unsupported | Mesma claim com evidência enriquecida (vínculo unkeyed↔distinção): **0.73**, sem revisão. Com a âncora do packet: 0.32/0.34, estável em 2 chamadas | **Divergência de empacotamento, não de juízo.** O JEV avaliou o snippet resumido; a claim carrega um vínculo que a âncora não carrega. QA certo sobre a fonte; JEV certo sobre a evidência entregue |
| D2 | `v3p2-03c1` — Barracuda CVE-2023-2868 | 2 | 0.79 partial | 0.79 é 1 ponto abaixo do limiar; banda de corte | Falso alarme de limiar, não de conteúdo. Conferível na fonte do fabricante |
| D3 | `v4p1-03c1` — normalização de URLs no cache | 2 | 0.63 partial | Âncora do v4 é paráfrase ("diferenças de interpretação de caminhos e regras de cache…") — mesmo padrão do D1 | Probable false negative por âncora resumida. Verificar se a claim é absoluta ou condicionada à configuração |
| D4 | `v4p1-06c2` — mecanismo de unkeyed inputs | 2 | 0.63 partial | Âncora de uma linha; artigo original tem o mecanismo completo | Mesmo padrão D1/D3: evidência empacotada abaixo do que a claim afirma |

**Padrão que atravessa D1/D3/D4:** as âncoras do v4 são resumos, não citações literais — o JEV é consistente e conservador sobre o que recebe; o QA é correto sobre a fonte original. Nenhuma das quatro divergências demonstra erro do juiz; três demonstram falha de empacotamento de evidência no conjunto v4.

## 2. Concordâncias que a reconciliação não destacou

- **V6.2.4 × V6.2.12:** o QA encontrou salto inferencial (3.000 comuns ≠ senhas vazadas, que é V6.2.12). O JEV já havia sinalizado as duas ocorrências (0.57 e 0.50, `needs_review=true`) — **concordância independente**, com o JEV chegando primeiro.
- **RSA/relay:** o QA mostrou que a pergunta histórica do v3/v4 presume dois módulos RSA, quando o write-up usa `gcd(n, relay_fingerprint)`. O modelo absteve. A pergunta era ambígua — **achado sobre o conjunto, não sobre a resposta**. Congelar o histórico, sinalizar em fixtures futuras.

## 3. Limitações registradas

- GPT-6 teve contato com scores do JEV antes de congelar o laudo (declarado por ele). Cegamento perfeito entre as trilhas não existe — a adjudicação humana cobre exatamente isso.
- JEV não recebe a pergunta no `jev_evidence` (claim+evidência apenas). O adaptador `jev-judge-v1` deve carregar a pergunta no envelope para o contrato completo.
- Variância entre chamadas idênticas observada: ±0.02 a ±0.07. Um juiz com ruído não decide sozinho.

## 4. Decisão solicitada a Kai

Para cada linha D1–D4: **manter nota do QA**, **manter classificação do JEV**, ou **nota intermediária** com justificativa.

Assinatura do operador: ______________________ Data: __________

Consequência da adjudicação: fecha a revisão semântica dos v3/v4 (item 1 da ordem do QA) e libera o caminho para congelamento do candidato e a rodada pareada no v5 — com protocolo métrico definido ANTES da primeira execução.

## 5. Apêndice — isolamento experimental D3/D4 (Perplexity, 2026-10-20)

Evidência obtida por pesquisa assistida (portal Perplexity, sessão corrigida pelo operador). Citações verbatim conferidas contra os artigos originais.

**D4 — PortSwigger 2018, `practical-web-cache-poisoning`:**
- "Please note that web caches also enable a different type of attack called Web Cache Deception which should not be confused with cache poisoning." — a distinção existe literalmente no paper.
- "any difference in the response triggered by an unkeyed input may be stored and served to other users." — vínculo unkeyed→resposta compartilhada.
- URL: https://portswigger.net/research/practical-web-cache-poisoning

**D3 — PortSwigger 2024, `gotta-cache-em-all` (M. Doyhenard):**
- "Many HTTP servers and proxies including Nginx, Node, CloudFlare, CloudFront and Google Cloud decode certain delimiter characters before interpreting the pathname. To make things worse, this process is inconsistent."
- "This means that the same URL will have a different meaning in the most popular CDNs and origin servers even without any custom configuration."
- "It's possible to exploit dot-segment normalization by leveraging the discrepancies between parsers to modify the behavior of the cache rules and obtain crafted keys."
- URL: https://portswigger.net/research/gotta-cache-em-all

**Conclusão do isolamento:** D3 e D4 têm sustentação literal nas fontes originais → nota 2 factual do QA confirmada. Os flags do JEV permanecem válidos como sinal de empacotamento da evidência entregue ao juiz (âncoras-resumo no v4), não como erro factual.

Arquivo de conferência desta consulta: portal Perplexity, threads `71323410-db19-4d92-b9e4-6c3a45eda1b5` e follow-up, 2026-10-20 15:25-15:26.

## 6. Fecho da folha

Disposição final registrada: D1 = 2 · D2 = 2 · D3 = 2 · D4 = 2 (factual), com flags do JEV preservados como sinal de empacotamento de evidência. Base de revisão confirmada pelo operador: **GPT + pesquisa + JEV** (adendo da emenda, 2026-10-20). Assinatura formal dispensada por instrução do operador.
