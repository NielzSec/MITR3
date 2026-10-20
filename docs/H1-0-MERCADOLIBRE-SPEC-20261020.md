# H1-0 — Especificação v2: MercadoLibre (bug bounty)

**Data:** 2026-10-20 · **Operador:** Kai (`nielzsec`) · **Maestro:** OpenCode
**Programa:** `mercadolibre` (ID 33462) · `open` · triage ativo · bounty ativo
**Fonte do escopo:** API HackerOne `/v1/hackers/programs/mercadolibre/structured_scopes` — **4 páginas**, 88 registros (sha `146d115e8b0ad9f3da81efa7a3c284c042c1b3a3660f4f4d8ae3f6241f155d62`). Política oficial sha `74df70a9d27ffc20f5bd450365a9f2a07d6ac50c17e15f48f9b3bdcc3cc1c007`. Cópias privadas em `~/.local/share/mitr3/h1/mercadolibre/` (0600).
**Correção da v1:** a v1 leu apenas a página 1 (25 ativos) e tratou o extrato como completo. A paginação foi descoberta ao reconciliar com o export de escopo do Burp (`mercadolibre-2026-10-20T20_21_29Z.json`): 66 hosts no Burp, **100% cobertos** pela lista completa da API. A v2 substitui a v1; nenhum teste foi executado sob a v1.

## 1. Escopo — 88 ativos (79 com submissão, 71 com bounty)

### Aplicativos Android (Google Play)

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `com.mercadopago.wallet` | sim | sim | critical |
| `com.mercadolibre` | sim | sim | critical |
| `com.mercadoenvios.driver` | sim | sim | critical |
| `com.mercadoenvios.crowdsourcing` | sim | sim | critical |
| `com.mercadoenvios.logistics` | sim | sim | critical |
| `com.mercadolibre.android.mplay_tv` | sim | sim | critical |

### Aplicativos iOS (App Store)

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `com.mercadopago.MercadoPago` | sim | sim | critical |
| `com.3mosquitos.MercadoLibre` | sim | sim | critical |

### URLs e APIs

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `api.mercadopago.com` | sim | sim | critical |
| `api.mercadolibre.com` | sim | sim | critical |
| `logistica.redelcom.cl` | sim | sim | critical |
| `www.mercadolibre.co.cr` | sim | sim | critical |
| `www.mercadolibre.com.bo` | sim | sim | critical |
| `www.mercadolibre.com.do` | sim | sim | critical |
| `www.mercadolibre.com.ec` | sim | sim | critical |
| `www.mercadolibre.com.gt` | sim | sim | critical |
| `www.mercadolibre.com.hn` | sim | sim | critical |
| `www.mercadolibre.com.ni` | sim | sim | critical |
| `www.mercadolibre.com.pa` | sim | sim | critical |
| `www.mercadolibre.com.py` | sim | sim | critical |
| `www.mercadolibre.com.sv` | sim | sim | critical |
| `www.mercadolivre.com` | sim | sim | critical |
| `www.mercadopago.com.ec` | sim | sim | critical |
| `wow-int.mercadolibre.com` | NÃO | não | none |
| `biolibre.ar` | sim | sim | critical |
| `biolibre.cl` | sim | sim | critical |
| `biolibre.co` | sim | sim | critical |
| `biolibre.mx` | sim | sim | critical |
| `biolivre.com.br` | sim | sim | critical |
| `meliplay.com.ar` | sim | sim | critical |
| `meliplay.com.pe` | sim | sim | critical |
| `meliplay.com.uy` | sim | sim | critical |
| `mercadoplay.co` | sim | sim | critical |
| `mercadoplay.com.pe` | sim | sim | critical |
| `mercadoplay.com.uy` | sim | sim | critical |
| `mercadoplay.pe` | sim | sim | critical |
| `mercadoplay.uy` | sim | sim | critical |
| `portalinmobiliario.cl` | sim | sim | critical |
| `portalinmobiliario.com` | sim | sim | critical |
| `tucarro.com` | sim | sim | critical |
| `tucarro.com.co` | sim | sim | critical |
| `tumoto.com` | sim | sim | critical |
| `furycloud.io` | sim | sim | critical |
| `furydocs.io` | sim | sim | critical |
| `sustentabilidadmercadolibre.com` | sim | sim | critical |
| `mercadoenvios.com.ve` | sim | não | critical |
| `mercadopago.com.ve` | sim | sim | critical |
| `mpago.li` | sim | sim | critical |
| `mpago.la` | sim | sim | critical |
| `mercadobackoffice.com` | sim | sim | critical |
| `www.ipbooster.com` | sim | não | critical |
| `mercadolivreexperience.mercadolivre.com.br` | sim | não | critical |
| `*.modoblack.mercadolivre.com.br` | sim | não | critical |
| `fullbarhomologa.modoblackfullbar.com.br` | sim | não | critical |

### Wildcards

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `*.kangu.com.br` | NÃO | não | none |
| `*.adminml.com` | sim | sim | critical |
| `*.mercadolibre.cl` | sim | sim | critical |
| `*.mercadolibre.com` | sim | sim | critical |
| `*.mercadolibre.com.ar` | sim | sim | critical |
| `*.mercadolibre.com.co` | sim | sim | critical |
| `*.mercadolibre.com.mx` | sim | sim | critical |
| `*.mercadolibre.com.pe` | sim | sim | critical |
| `*.mercadolibre.com.uy` | sim | sim | critical |
| `*.mercadolivre.com.br` | sim | sim | critical |
| `*.mercadopago.cl` | sim | sim | critical |
| `*.mercadopago.com` | sim | sim | critical |
| `*.mercadopago.com.ar` | sim | sim | critical |
| `*.mercadopago.com.br` | sim | sim | critical |
| `*.mercadopago.com.co` | sim | sim | critical |
| `*.mercadopago.com.mx` | sim | sim | critical |
| `*.mercadopago.com.pe` | sim | sim | critical |
| `*.mercadopago.com.uy` | sim | sim | critical |
| `*.gokangu.cl` | NÃO | não | none |
| `*.gokangu.co` | NÃO | não | none |
| `*.gokangu.mx` | NÃO | não | none |
| `*.gokangu.uy` | NÃO | não | none |
| `*.kangu.tech` | NÃO | não | none |
| `*.mlstatic.com` | sim | sim | critical |
| `*.tucarro.com.ve` | sim | não | critical |
| `*.mercadolibre.com.ve` | sim | não | critical |
| `mercadolibreexperience.com.*` | sim | não | critical |

### Hardware

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `Point Smart` | sim | sim | critical |

### Outros

| Ativo | Submission | Bounty | Severidade máx. |
|---|---|---|---|
| `developersforum` | NÃO | não | none |
| `Redelcom` | NÃO | não | none |
| `Crypto` | sim | sim | critical |
| `Leaked Credentials` | sim | sim | high |
| `Tier 3` | sim | sim | critical |
| `Wonder` | sim | sim | critical |

### Fora de escopo (submission=false)
`*.kangu.com.br`, `*.gokangu.cl`, `*.gokangu.co`, `*.gokangu.mx`, `*.gokangu.uy`, `*.kangu.tech`, `developersforum`, `Redelcom`, `wow-int.mercadolibre.com`.

### Submissão sim, bounty não
`mercadoenvios.com.ve`, `www.ipbooster.com`, `*.tucarro.com.ve`, `*.mercadolibre.com.ve`, `mercadolibreexperience.com.*`, `mercadolivreexperience.mercadolivre.com.br`, `*.modoblack.mercadolivre.com.br`, `fullbarhomologa.modoblackfullbar.com.br` — elegíveis para relato/reputação, sem pagamento.

## 2. Regras do programa que vinculam toda a operação

- **Sem varredura automatizada massiva.** Teste criativo e manual é o esperado.
- Proibidos: DoS/DDoS, força bruta, spam, engenharia social/phishing, malware, criação massiva de contas, comprometer conta/dados de terceiros, degradar serviço, ataques físicos.
- **Test users** permitidos; `PR` no CVSS é **High** para findings com essas contas; cartões de teste oficiais permitidos.
- CVE/0-day só 30 dias após publicação e com PoC demonstrável pela internet; sem dump de SAST; dependency confusion fora; supply-chain com pacote público e PoC válido dentro.
- **Mobile:** fora — certificate pinning/SSL, ofuscação, SafetyNet/anti-instrumentação, componentes exportados sem impacto real, deeplinks `mercadopago://in-app-browser` e `meli://in-app-browser`.
- **Subdomain takeover:** prova de inserção de conteúdo + DNS/HTTP; sem cookies/phishing.
- **XSS sem bypass de CSP** tem severidade reduzida/zero.
- **Tier 3 (não-aplicativo):** credenciais/documentos expostos ligados à MercadoLibre; uma bounty por local de origem; validade confirmada com **uma** chamada não destrutiva; proibido acessar/exfiltrar além da confirmação; exige evidência de vínculo.
- Exclusões: `Melidolar`, KYC (ações não monetárias sem validação), GraphQL com impacto DoS, `Collaborators`; SDK MercadoPago/secure inputs sem bounty; `.cn` fora.
- Piso de CVSS 2.0 para low; high/critical: `((CVSS × Tier) × 10) + bônus`.
- **Signal 1.0** no último ano é requisito; contas abaixo usam trial reports — confirmar elegibilidade de `nielzsec` no Portão A.

## 3. Padrão de evidência (obrigatório)

1. Ativo exato + URL/endpoint + método.
2. Passos numerados, conta/test user por rótulo (nunca credencial real).
3. Request/response redigidos (sem cookies, tokens, PII de terceiros).
4. Impacto concreto + CVSS 3.1 justificado.
5. Prova mínima — nada além do necessário.
6. Hash do artefato + timestamp UTC.

## 4. Fluxo de seis fases (emenda QA+JEV)

1. Especificação (este documento) → 2. **Portão A (QA + JEV)** → 3. Plano → 4. Tarefa → 5. **Portão B (QA + JEV)** → 6. Implementação.

Mudança de requisito volta para a especificação; nunca direto para execução.

## 5. Perguntas abertas para o Portão A

1. `Crypto`, `Wonder`, `Point Smart` e `Tier 3`/`Leaked Credentials`: qual a superfície testável e a prova mínima aceitável?
2. Tiers 1/2/3 por ativo não vêm no extrato; como classificar sem arbitrar?
3. Elegibilidade de `nielzsec` frente ao requisito de Signal 1.0 / trial reports.
4. `*.adminml.com` tem restrição adicional de método?
5. Limite operacional entre "teste criativo" e "varredura massiva".
