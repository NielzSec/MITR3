# H1-MELI — Leads de autorização a partir do capture (offline)

**Fonte:** `apisec-capture-2026-10-20T20-54-29.json` (168 req, sessão única do operador) · **Nenhum tráfego novo.**
**Limite estrutural:** todos os objetos pertencem à mesma identidade (`user_id 398309969`). Sem segunda sessão, BOLA/IDOR não se prova — só se formula.

## Candidatos (ordem de valor)

| # | Endpoint | Objeto | Por que é candidato | Prova mínima com 2 identidades |
|---|---|---|---|---|
| L1 | `POST /checkout/review/api/update/session/{session_id}/update_selection` | `session_id` | Sessão de checkout no path, mutação de seleção; se a sessão não for validada contra o cookie, altera carrinho alheio | Sessão B envia `session_id` de A; sucesso = 200 + seleção alterada em A; falha esperada = 403/404 |
| L2 | `POST /gz/cart/v3/api/add-to-cart?element_id={n}&client.id={cart_id}` | `client.id` | `client.id` no query; se aceitar carrinho de terceiro, adiciona item à conta alheia | Carrinho B adiciona com `client.id` de A; verificar item em A (leitura) |
| L3 | `GET /gz/checkout/cart/v2/buy?cho_id={cho_id}` | `cho_id` | `cho_id` opaco ligado à sessão; replay cross-session pode iniciar compra alheia | Sessão B abre `cho_id` de A; esperado 403/redirect, não 200 com dados |
| L4 | `POST /checkout/review/api/update/session/{session_id}/update_selection` (variação de método) | `session_id` | Mesma rota aceita POST; testar troca de método/CSRF | Mesma prova de L1 |
| L5 | `GET /notifications/center/api/badge` | conta | Sem ID no path; baixo valor, só confirma escopo de sessão | Não priorizar |

## O que NÃO fazer

- Não testar IDs de terceiros “no escuro”: colisão acidental altera conta real e viola a spec.
- Não usar `cho_id`/`session_id` de capturas de outros usuários.
- Não disparar o mesmo teste em paralelo (spec v4 §7: uma sessão, sem concorrência).

## Pré-requisito

Duas identidades de teste oficiais (app de desenvolvedor → test users). O app está em criação no devcenter; falta apenas o reCAPTCHA. Com dois test users, L1–L3 são testáveis em ~6 requisições read-only/uma mutação controlada.

*Análise offline · sem valores de cookie/PII · 2026-10-20 UTC*
