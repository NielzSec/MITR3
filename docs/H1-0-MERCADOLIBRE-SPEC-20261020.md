# H1-0 — Especificação v3: MercadoLibre (bug bounty)

**Data:** 2026-10-20 · **Operador:** Kai (`nielzsec`) · **Maestro:** OpenCode
**Programa:** `mercadolibre` (33462) · `open` · triage ativo · bounty ativo
**Escopo:** API HackerOne, 4 páginas, **88 ativos** (sha `146d115e8b0ad9f3da81efa7a3c284c042c1b3a3660f4f4d8ae3f6241f155d62`); política sha `74df70a9d27ffc20f5bd450365a9f2a07d6ac50c17e15f48f9b3bdcc3cc1c007`. Cópias privadas 0600 em `~/.local/share/mitr3/h1/mercadolibre/`.
**Histórico:** v1 leu só a página 1 (25 ativos, incompleta); v2 corrigiu para 88 e reconciliou 100% com o export Burp; **v3 adiciona o tier do campo `instruction`**, que a v2 não extraía. Nenhum teste ativo foi executado em nenhuma versão.
**Regra de gates:** Portão A (QA+JEV) em `FAIL` conforme `docs/H1-MELI-GATE-A-QA-20261020.md`; execução ativa = STOP até novo parecer.

## 1. Distribuição de tiers (campo `instruction`)

- **Tier 2**: 40
- **Tier 1**: 27
- **n/d**: 9
- **Kangu (fora)**: 6
- **fora**: 2
- **Tier 2 ZT**: 2
- **sem tier (Crypto)**: 1
- **Tier 3 (leaks)**: 1

> Nota: o parecer QA citou "21 de 22 ativos Tier 1" com base na lista v1 (25 registros, sem paginação). O extrato completo mostra 27 Tier 1 e 40 Tier 2 — números que substituem aquela leitura. `Crypto` não informa tier (apenas os caminhos `/crypto/*` em mercadopago.com.mx, .cl e .com.br). `Leaked Credentials` é o ativo de Tier 3. `Wonder` não informa tier.

## 2. Escopo — 88 ativos

### Aplicativos Android

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `com.mercadopago.wallet` | Tier 1 | sim | sim | critical |
| `com.mercadolibre` | Tier 1 | sim | sim | critical |
| `com.mercadoenvios.driver` | Tier 1 | sim | sim | critical |
| `com.mercadoenvios.crowdsourcing` | Tier 1 | sim | sim | critical |
| `com.mercadoenvios.logistics` | Tier 1 | sim | sim | critical |
| `com.mercadolibre.android.mplay_tv` | Tier 2 | sim | sim | critical |

### Aplicativos iOS

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `com.mercadopago.MercadoPago` | Tier 1 | sim | sim | critical |
| `com.3mosquitos.MercadoLibre` | Tier 1 | sim | sim | critical |

### URLs e APIs

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `api.mercadopago.com` | Tier 1 | sim | sim | critical |
| `api.mercadolibre.com` | Tier 1 | sim | sim | critical |
| `logistica.redelcom.cl` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.co.cr` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.bo` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.do` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.ec` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.gt` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.hn` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.ni` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.pa` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.py` | Tier 2 | sim | sim | critical |
| `www.mercadolibre.com.sv` | Tier 2 | sim | sim | critical |
| `www.mercadolivre.com` | Tier 2 | sim | sim | critical |
| `www.mercadopago.com.ec` | Tier 2 | sim | sim | critical |
| `wow-int.mercadolibre.com` | n/d | NÃO | não | none |
| `biolibre.ar` | Tier 2 | sim | sim | critical |
| `biolibre.cl` | Tier 2 | sim | sim | critical |
| `biolibre.co` | Tier 2 | sim | sim | critical |
| `biolibre.mx` | Tier 2 | sim | sim | critical |
| `biolivre.com.br` | Tier 2 | sim | sim | critical |
| `meliplay.com.ar` | Tier 2 | sim | sim | critical |
| `meliplay.com.pe` | Tier 2 | sim | sim | critical |
| `meliplay.com.uy` | Tier 2 | sim | sim | critical |
| `mercadoplay.co` | Tier 2 | sim | sim | critical |
| `mercadoplay.com.pe` | Tier 2 | sim | sim | critical |
| `mercadoplay.com.uy` | Tier 2 | sim | sim | critical |
| `mercadoplay.pe` | Tier 2 | sim | sim | critical |
| `mercadoplay.uy` | Tier 2 | sim | sim | critical |
| `portalinmobiliario.cl` | Tier 2 | sim | sim | critical |
| `portalinmobiliario.com` | Tier 2 | sim | sim | critical |
| `tucarro.com` | Tier 2 | sim | sim | critical |
| `tucarro.com.co` | Tier 2 | sim | sim | critical |
| `tumoto.com` | Tier 2 | sim | sim | critical |
| `furycloud.io` | Tier 2 ZT | sim | sim | critical |
| `furydocs.io` | Tier 2 ZT | sim | sim | critical |
| `sustentabilidadmercadolibre.com` | Tier 2 | sim | sim | critical |
| `mercadoenvios.com.ve` | Tier 2 | sim | não | critical |
| `mercadopago.com.ve` | Tier 2 | sim | sim | critical |
| `mpago.li` | Tier 2 | sim | sim | critical |
| `mpago.la` | Tier 2 | sim | sim | critical |
| `mercadobackoffice.com` | Tier 2 | sim | sim | critical |
| `www.ipbooster.com` | n/d | sim | não | critical |
| `mercadolivreexperience.mercadolivre.com.br` | n/d | sim | não | critical |
| `*.modoblack.mercadolivre.com.br` | n/d | sim | não | critical |
| `fullbarhomologa.modoblackfullbar.com.br` | n/d | sim | não | critical |

### Wildcards

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `*.kangu.com.br` | Kangu (fora) | NÃO | não | none |
| `*.adminml.com` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.cl` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com.ar` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com.co` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com.mx` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com.pe` | Tier 1 | sim | sim | critical |
| `*.mercadolibre.com.uy` | Tier 1 | sim | sim | critical |
| `*.mercadolivre.com.br` | Tier 1 | sim | sim | critical |
| `*.mercadopago.cl` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.ar` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.br` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.co` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.mx` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.pe` | Tier 1 | sim | sim | critical |
| `*.mercadopago.com.uy` | Tier 1 | sim | sim | critical |
| `*.gokangu.cl` | Kangu (fora) | NÃO | não | none |
| `*.gokangu.co` | Kangu (fora) | NÃO | não | none |
| `*.gokangu.mx` | Kangu (fora) | NÃO | não | none |
| `*.gokangu.uy` | Kangu (fora) | NÃO | não | none |
| `*.kangu.tech` | Kangu (fora) | NÃO | não | none |
| `*.mlstatic.com` | Tier 2 | sim | sim | critical |
| `*.tucarro.com.ve` | n/d | sim | não | critical |
| `*.mercadolibre.com.ve` | n/d | sim | não | critical |
| `mercadolibreexperience.com.*` | Tier 2 | sim | não | critical |

### Hardware

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `Point Smart` | Tier 1 | sim | sim | critical |

### Outros

| Ativo | Tier | Sub | Bounty | Máx. |
|---|---|---|---|---|
| `developersforum` | fora | NÃO | não | none |
| `Redelcom` | fora | NÃO | não | none |
| `Crypto` | sem tier (Crypto) | sim | sim | critical |
| `Leaked Credentials` | Tier 3 (leaks) | sim | sim | high |
| `Tier 3` | n/d | sim | sim | critical |
| `Wonder` | n/d | sim | sim | critical |

### Fora de escopo (submission=false)
`*.kangu.com.br`, `*.gokangu.cl`, `*.gokangu.co`, `*.gokangu.mx`, `*.gokangu.uy`, `*.kangu.tech`, `developersforum`, `Redelcom`, `wow-int.mercadolibre.com`.

### Submissão sim, bounty não
`mercadoenvios.com.ve`, `www.ipbooster.com`, `*.tucarro.com.ve`, `*.mercadolibre.com.ve`, `mercadolibreexperience.com.*`, `mercadolivreexperience.mercadolivre.com.br`, `*.modoblack.mercadolivre.com.br`, `fullbarhomologa.modoblackfullbar.com.br`.

## 3. Regras que vinculam a operação

- **Sem varredura automatizada massiva**; teste criativo e manual.
- Proibidos: DoS, força bruta, spam, engenharia social/phishing, malware, criação massiva de contas, comprometer conta/dados de terceiros, degradar serviço, ataques físicos.
- Test users: `PR=High` no CVSS; cartões de teste oficiais.
- CVE/0-day: 30 dias após publicação + PoC pela internet; sem dump de SAST; dependency confusion fora.
- Mobile: não reportar pinning/ofuscação/SafetyNet/componentes exportados sem impacto/deeplinks in-app-browser.
- Subdomain takeover: prova de conteúdo + DNS/HTTP.
- XSS sem bypass de CSP: severidade reduzida/zero.
- Tier 3: uma bounty por origem; confirmação com uma chamada não destrutiva; sem exfiltração; exigir vínculo.
- Exclusões: Melidolar, KYC não-monetário, GraphQL DoS, Collaborators; SDK MercadoPago/secure inputs sem bounty; `.cn` fora.
- CVSS mínimo 2.0 (low); high/critical `((CVSS × Tier) × 10) + bônus`.
- Signal 1.0 / trial reports: pendência de conta (`nielzsec`).

## 4. Padrão de evidência

Ativo exato + endpoint/método; passos numerados com conta rótulo; request/response redigidos; impacto + CVSS 3.1; prova mínima; hash + timestamp UTC.

## 5. Fluxo de seis fases (emenda QA+JEV)

Especificação → **Portão A (QA+JEV)** → Plano → Tarefa → **Portão B (QA+JEV)** → Implementação. Mudança de requisito volta à especificação.

## 6. Pendências do Portão A

1. `Crypto` sem tier e caminhos `/crypto/*`; `Point Smart` Tier 1 (AR/BR) — método físico a esclarecer.
2. `Wonder` sem tier e sem instrução.
3. Elegibilidade de `nielzsec`: Signal 1.0 / trial reports / verificação de identidade.
4. Limite qualitativo entre teste criativo e varredura massiva.
