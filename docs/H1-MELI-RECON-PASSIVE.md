# H1-0 — Passive Reconnaissance: MercadoLibre
Date: 2026-10-20
Status: Passive (No traffic sent to hosts)

## 1. Prioritized Surface & Assets
| Asset | Priority | Hypothesis | Source |
|---|---|---|---|
| `*.adminml.com` | P0 | Administrative tools, internal dashboards, higher chance of broken access control (BOLA/BFLA). | CT Logs/Spec |
| `api.mercadopago.com` | P0 | Core financial transactions, payment processing; high impact for logic flaws. | Dev Docs/Spec |
| `api.mercadolibre.com` | P1 | Main marketplace logic, user profiles, inventory; large surface area. | Dev Docs/Spec |
| `*.mercadopago.*` | P1 | Regional payment gateways; potential discrepancies in regional implementations. | CT Logs |
| `*.mercadolibre.*` | P2 | Regional marketplace sites; primarily XSS/CSP bypasses and request smuggling. | CT Logs |
| Mobile Apps | P2 | Hidden endpoints in binary, hardcoded keys, improper deep-link validation. | App Stores |

## 2. Intelligence Sources (Dated)
- **HackerOne Hacktivity (2026-10-20):** Analysis of disclosed reports indicates a pattern of IDORs in regional subdomains and logic flaws in payment flows.
- **Certificate Transparency (2026-10-20):** Identification of `adminml.com` subdomains suggests a separation of administrative and consumer traffic.
- **Developer Portals (2026-10-20):** MercadoPago API docs reveal a complex OAuth2 flow and a wide array of endpoints for merchant management.
- **Public CVEs/Advisories (2026-10-20):** No critical 0-days in the last 30 days, but general stack (Java/Spring) suggests focus on deserialization and SSRF.

## 3. Initial Hypotheses
1. **Administrative Isolation:** `*.adminml.com` may be less hardened than consumer-facing sites, potentially allowing unauthorized access to internal tools.
2. **Regional Drift:** Differences in how `*.cl`, `*.mx`, and `*.br` handle sessions could lead to cross-region account takeover or data leakage.
3. **API Shadowing:** Mobile apps may call endpoints on `api.mercadolibre.com` that are not documented in the developer portal, bypassing certain frontend checks.
4. **Payment Logic Flaws:** The transition between `mercadolibre` (marketplace) and `mercadopago` (wallet) likely contains edge cases in state synchronization (Race Conditions).
