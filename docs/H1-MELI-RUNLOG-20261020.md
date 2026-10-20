# H1 — Runlog MercadoLibre (manual)

**Data:** 2026-10-20 · **Operador:** nielzsec · **Autorização:** Portão A PASS `534d5e1`, Portão B PASS `db803b2`
**Método:** curl manual, single-threaded, 2s entre requisições, UA identificado, sem autenticação. Total: 5 requisições.

| UTC | URL | HTTP | Observação | Evidência (sha256) |
|---|---|---|---|---|
| 2026-10-20T20:47:08Z | `https://api.mercadolibre.com/sites` | 403 | PA_UNAUTHORIZED_RESULT_FROM_POLICIES | `8dba48cc2bbe45b5…` |
| 2026-10-20T20:47:10Z | `https://api.mercadolibre.com/items/MLB000000000` | 403 | PA_UNAUTHORIZED_RESULT_FROM_POLICIES | `874e76b33b0f3f64…` |
| 2026-10-20T20:47:12Z | `https://api.mercadopago.com/v1/payments/1` | 401 | unauthorized (access_token ausente) | `a47139ad22361e59…` |
| 2026-10-20T20:47:14Z | `https://api.mercadopago.com/v1/payment_methods` | 401 | unauthorized_scopes (public key/caller id ausente) | `ac84c07bb5ba7628…` |
| 2026-10-20T20:47:36Z | `https://www.mercadolivre.com.br` | 200 | HTML 543081 bytes | `92aad6427ce9fab3…` |

## Leitura

- `api.mercadolibre.com` devolve **403 PolicyAgent** para chamadas não autenticadas a partir do nosso egress: bloqueio de borda, não vulnerabilidade. Headers internos vazam nomes de política (`x-policy-agent-block-code`), sem impacto demonstrável.
- `api.mercadopago.com` devolve 401 padrão; `cause.data` traz timestamp e request-id — comportamento esperado, sem dado sensível.
- `www.mercadolivre.com.br` serve a home normalmente; scripts públicos listados (security.js, widgets em `http2.mlstatic.com`), insumo para H9.
- **Nenhum achado.** P0 de API exige credencial de aplicação/test user para avançar.

## Próximo bloqueio

Teste autenticado depende de app de desenvolvedor MercadoLibre (client_id/secret) ou test user oficial — recurso de conta do operador, não gate de QA.
