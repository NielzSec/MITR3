# H1-MELI — SUBRESOURCE-SURFACE-INTEL (Onda 10 · H-ORDER10.1)

**Data:** 2026-10-21 · **Autor:** DeepSeek (intel tática) · **Revisado:** VANTA
**Fontes:** ORDERS-INTEL + CODEX-WEB-SUBRESOURCES (parecer GPT-6 Astra) — nenhum tráfego.

---

## Ranking de probabilidade de desvio de autorização

| # | Sub-recurso de `/orders/{id}/...` | Porquê | Principais headers |
|---|---|---|---|
| 1 | `/notes` | Fronteira **só-vendedor** limpa: anotação interna sem ruído fiscal. Se B ler nota de C = desvio inequívoco (contraste C1/C2). Sem header extra → mais fácil normalizar | `Authorization` apenas |
| 2 | `/shipments` | **Cross-object ownership** (sender/receiver ≠ buyer/seller) + histórico de BOLA em shipment/pack. Risco alto e baixa demanda de contraste. Cuidado: 204 assíncrono e formato novos (grave se mal normalizado) | `x-format-new: true` (usual · obrigatório 12/10/2025) · `X-New-Domain: true`; `X-Api-Version:2` ≠ `x-version:2` |
| 3 | `/billing_info` | Autorização **fiscal específica** ≠ participação na compra; rota legada depreciada. Valor alto; ruído alto (x-version: 2 vs `quantity/billing-info/{site_id}/{bid}` atual) | `x-version: 2` (legado) · ver rep. atual; NÃO usar `x-format-new` aqui |
| 4 | `search?buyer=` / `q=` | Filtro ≠ autorização; superfície informativa mas sem sub-recurso próprio | `Authorization` |
| 5 | `/feedback` + `/claims` | Papéis processuais (`players[].role`) ≠ buyer/seller; leitura | `Authorization` |

## Discriminantes de headers — não confundir identidade com formato

- **`X-Caller-Id` = risco de identidade** (declarada pelo cliente); usado em outras APIs MP,
  **não obrigatório nos 3 alvos**. Se o servidor derivar o principal desse header (sem token),
  é vetor de spoofing → nunca usá-lo para declarar outra identidade.
- **`x-format-new` / `X-New-Domain` = seletores de representação** (formato/shards), não
  identidade; ausência → falso 404/204, contamina o julgamento. `x-format-new: true` exige
  contrato de Shipments pós 12/10/2025.
- **`X-Api-Version: 2` ≠ `x-version: 2`**; cada rota valida seu próprio contrato — não
  transportar headers entre APIs (não assumir `X-Caller-Id` Global).
- Erros mistos: `400`=schema, `401`=authn, `403`=authz/ACL (candidato de BOLA em 403? NÃO —
  403 é enforcement), `404`=ambiguo (ACL ou rota), `204`=sem envio associado.

## Assimetria de máxima (ordem de sondagem, dado o C2)

- **1ª sonda:** `/orders/{ORDER_ID}/notes` com token de B (fronteira limpa; se 200 com nota
  de C → desvio forte, sem ruído cron)
- **2ª sonda:** `/orders/{ORDER_ID}/shipments` com token de B + `x-format-new:true` +
  `X-New-Domain:true`; se 204/400 → normalizar contrato; se 200 com payload de envio de C
  (sender_id do anúncio de C) → candidato
- **3ª sonda:** `/orders/{id}/billing_info` legado com `x-version:2` só se a rota atual
  `billing-info/{site_id}/{bid}` não diferenciar; tratar 400/404 como AMBIGUOUS_404 (contaminação)

## Critério de aceite (JEV — H-ORDER10.1)

`CONTRACT_VALID ∧ OWNER_BASELINE_VALID (C1/C2 200) ∧ SUBJECT_VERIFIED (B) ∧ OBJECT_RELATION_VERIFIED`
Falsos positivos: routing que ecoa `/orders/search?buyer=` como prová de leitura; 404 genérico
como enforcement comprovada; `x-format-new` faltando → 400/204 sem sentido de autorização.

## Conclusão (1 linha)

Maior assimetria = **`/orders/{id}/notes`** (fronteira limpa só-vendedor) e **`/shipments`**
(cross-object); **billing_info legado** é o de maior valor porém maior ruído — priorizar notes
e shipments na sequência controlada, com headers de formato **por rota** e nunca `X-Caller-Id`
como identidade.
