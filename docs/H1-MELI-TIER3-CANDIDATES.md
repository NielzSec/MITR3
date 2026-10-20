# H1-MELI-TIER3-CANDIDATES — MercadoLibre credential/document exposure

**Data coleta:** 2026-10-20 · **Operador:** Robin · **Fase:** 3/6 (Tier 3 passivo)
**Regra:** passivo puro · sem acesso · sem valor de segredo impresso · bounty por local de origem

---

## Candidatos confirmados (requerem Portão B antes de qualquer contacto)

| # | Localização | Tipo | Evidência de vínculo | Nota |
|---|---|---|---|---|
| **C1** | `github.com/trufflesecurity/trufflehog/issues/4620` (Issue pública, dez/2025) | Tokens de produção MercadoPago expostos em endpoint kubelet não protegido (porta 10255) | Variáveis de ambiente com prefixos `MERCADO_PAGO_ACCESS_TOKEN`, `MERCADOPAGO_ACCESS_TOKEN`, `MP_ACCESS_TOKEN`, `MERCADOPAGO_CLIENT_SECRET`; aplicação de produção e-commerce/travel booking | **Prioridade alta** — relato público de credenciais expostas em produção; o issue cita "Kubernetes kubelet endpoint" como origem. Reportável como credencial exposta de sistema que utiliza MercadoPago. Exposição via infraestrutura do alvo, não do próprio MercadoLibre — verificar elegibilidade no escopo H1 antes de reportar. |
| **C2** | `github.com/alexandregama/mercado-pago-java-sdk` (repo ativo, forked do oficial) | Access token com formato de produção no exemplo de uso do SDK (`APP_USR-<redacted>`) | Token com prefixo `APP_USR-` e sufixo `__LA_LC__` — formato de produção real; diff contra SDK oficial mostra valores de exemplo no `curl` do README; contributor `alexandregama` publicou em contexto de tutorial | **Verificação necessária**: confirmar se o token ainda está ativo (1 chamada não-destrutiva GET `/users/me` após Portão B). **Valor redigido nesta versão; não testado.** |

---

## Candidatos marginais (vínculo direto fraco ou infraestrutura própria)

| # | Localização | Tipo | Evidência de vínculo | Limite |
|---|---|---|---|---|
| **C3** | `github.com/theYahia/WWmcp` | `MERCADOPAGO_ACCESS_TOKEN` em config MCP com placeholder `APP_USR-XXXXXXXX-XXXXXX-X-XXXXXXXX` | Configuração production-ready com instruções de uso de token `APP_USR-` (produção) vs `TEST-` (sandbox) | Placeholder com `X` — não confirmado se o autor substituiu ou se há valor real no histórico do repo |
| **C4** | `internal-api.mercadopago.com` + IP `10.54.29.54` | Subdomínio interno + IP RFC-1918 privado | Enumerado via hackertarget.com; IP `10.x.x.x` indica infraestrutura de rede interna (VPN/bastion); domínio não exposto em CRL/TLS pública | IP privado `10.54.29.54` inacessível de internet; subdomain takeover? Não expõe credenciais diretamente; candidato apenas paraenumeração de superfície |
| **C5** | `gtwy-aza.mercadopago.com` e `gtwy-azb.mercadopago.com` | Aponte para `8.8.8.8` (Google DNS) | IPs legítimos; gateway com config apontando para 8.8.8.8 — pode indicar DNS hardcoded ou redirect mal configurado | Sem credencial; apenas enumeração |

---

## Subdomínios internos enumerados (hackertarget.com, passivo, sem acesso)

| Subdomínio | IP | Observação |
|---|---|---|
| `internal-api.mercadopago.com` | `10.54.29.54` | IP privado — infraestrutura interna |
| `mail.mercadopago.com` | `91.194.249.21` | Servidor de e-mail — não expõe credenciais |
| `mcp.mercadopago.com` | `52.85.31.59` | MCP server oficial; não expõe credenciais |
| `api.mercadopago.com` / `api.mercadolibre.com` | pública | APIs legítimas |
| `analytics.*`, `auth.*`, `developers.*`, `applications.*` | AWS CloudFront | Infraestrutura pública normal |
| `o*.sg.a.mercadolibre.com` (o18–o5, 3 IPs) | `149.72.129/205/241–245` | Balanceadores de carga; IPs públicos |
| `dnsps*.mercadolibre.com` (28 IPs) | `205.251.192–195` | Servidores DNS privado (Amazon DNS) |

---

## Nenhum candidato encontrado

- **CRT.sh** (certificados TLS): indisponível (502) em toda a rodada
- **Pastebin / 0x0 / dpaste**: search indexado não retornou artefatos com credenciais reais vinculadas ao escopo
- **SDKs oficiais** (`mercadopago/sdk-*`, `mercadolibre/*`): todos com placeholders (`YOUR_ACCESS_TOKEN`, `client_secret_example`, `<ACCESS_TOKEN>`)
- **Documentação oficial**: apenas best practices de rotação de credenciais — não exposição

---

## Finding fuera de Tier 3 (reporte separadamente se elegível)

| # | Localização | Tipo | Justificação |
|---|---|---|---|
| **N1** | `app.opencve.io/cve?product=mercadopago` — **CVE-2026-76842** | Path traversal no MercadoPago Node.js SDK (CVE-2026-76842, 8.2 High) | Injeção de path em `/v1/payments/${id}`, `/paymentRefund`, `/advancedPayment`, `/disbursementRefund` — token do merchant渗出 para query strings arbitrárias; helper `encodePathParam` existe mas não foi aplicado a estes endpoints; PR #451 aplicou a outros clientes. **Não é Tier 3** (é vulnerability in product MercadoPago); elegível como finding separado após Gate B |

---

## Ação requerida antes de qualquer contacto

1. **C1**: Verificar se a aplicação e-commerce/travel booking citada no Trufflehog issue está em qualquer wildcard do escopo H1 (`*.mercadopago.com` etc.) — se sim, reportar como credencial exposta em infraestrutura própria
2. **C2**: Confirmar se o token do Java SDK continua ativo com 1 chamada `GET https://api.mercadopago.com/users/me` (não-destrutiva); se 401 → inválido, descartado; se 200 → confirmar se pertence a entorno de produção
3. **N1**: Avaliar elegibilidade CVE-2026-76842 como vulnerability in product (não Tier 3) — fora do scope credential leak, mas dentro do escopo H1 como vulnerability

**Regra: nenhum valor de segredo impresso, nenhuma exfiltração, nenhum acesso além de reprodução documentada.**

*Coleta passiva · artefatos não indexados em RAG · 2026-10-20 UTC*
