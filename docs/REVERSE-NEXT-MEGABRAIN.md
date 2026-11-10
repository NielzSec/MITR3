# REVERSE-NEXT-MEGABRAIN — integração MegaBrain (G4) — lane Knowledge (Hermes)

**Data:** 2026-10-21 · **Execução real via MCP MegaBrain (local), zero tráfego a terceiros; nenhum serviço/MELI tocado.**
**Receios e operações reais** (health, health v2, store x3, ingest_file, 10 knowledge_search + read por id), recibos em `~/MITR3/labs/reverse-next/knowledge/` e JEV shadow.

## 1. Health (medido)
- `megabrain_health`: status ok; root `/opt/megabrain/MegaBrain`; JEV shadow (typesafe, `jev-latest`, shadow mode).
- `megabrain_v2_health`: db ok (pgvector 0.8.7; documents=1085, claims=24417, evidence=10004),
  worker alive, network_isolated=true. **Nota:** corpus `reverse` do servidor aponta REA remota
  em `1417bf943bf49e49b414e8a508bf28a31304be83` (indexado 2026-10-20) — NOSSO pin é
  `01788bac…`, distinguível pelo origin. Não confundir.

## 2. Recibos de ingestão (fallback knowledge_store)
`knowledge_ingest_file` → `import_path_not_authorized` (documentado; fallback).
| role | document_id | version | content_hash | origin (commit) |
|---|---|---|---|---|
| rea | `32e6e8a1-c5e0-47fb-ae84-f544d1be976f` | 1 | `1476fd33…` | `mitr3.reverse-next.v1:…/rea.md (rea-src@01788bac…)` |
| reverse-skill-method | `9832c38d-e2f8-4791-b2a9-e830f3460b8e` | 1 | `3acb8eea…` | `mitr3.reverse-next.v1:…/reverse-skill-method.md (reverse-skill@cab634bd…)` |
| manifest | `16c8f936-9e83-45db-bdc9-9257ad47923f` | 1 | `7f452714…` | `mitr3.reverse-next.v1:manifest` |

## 3. Readback 6-10 (determinístico por document_id/origin/commit — NÃO pela semelhança de frase)
| Query | Hits no namespace | Confirmação |
|---|---|---|
| `01788bac863ac786bfbb648cad69b11e23b40a89` | 3 docs (manifest, rea, reverse-skill-method) | lexical, origin com commit |
| `cab634bd855fc287f6e420c1f36fd1a6b9245960` | 2 docs (manifest, reverse-skill-method) | lexical, origin com commit |
| `mitr3.reverse-next.v1` | 3 docs | lexical no namespace |
| commit (source_type=manual) | rea + manifest | origin intacta |
| `knowledge_read` 32e6e8a1 | found v1, conteúdo com citação literal `## Bring your own engine` | readback por id |
| `knowledge_read` 9832c38d | found v1, conteúdo com `## ACTIVATION AND CONSENT GATE` + commit | readback por id |
| `knowledge_read` 16c8f936 | found v1, manifest completo | readback por id |
| seed pré-ingest | zero hits do namespace | estado inicial vazio comprovado |

**PASS G4 (parte MegaBrain)** — sujeito à revisão humana: fontes/commits corretos nos
recibos, sem segredo, sem instrução externa executada. Queries de frase isolada sem commit
podem ser enterradas no ranking — NÃO são evidência de falha de ingestão.

## 4. JEV shadow (advisory)
- `jev_preflight` (op ingest): risk **low** 1.04, allow, shadow, `observe_only` — `jev_dec_1142c8c38cbf4b0b`.
- `jev_evidence` (readback suporta claim): **0.82** sufficient, needs_review false — `jev_dec_63866e7d1b264ba0`.
- `jev_postcheck` (ao fim): **verify_more** (quality 3.49 strong) — `jev_dec_07f5c261259a4283`;
  não é `complete` — sinal honesto de que skill/MEGABRAIN.md ainda faltavam (agora entregues).

## 5. Schema p/ teste determinístico do QA (sem calls a serviços)
Caminho: `labs/reverse-next/knowledge/upstream-manifest.json` (→ copia ingerida em `16c8f936…`).
Teste sugerido: para cada selector, verificar existência+seção literal+SHA256 no clone local,
e nos recibos verificar origem == prefixo do namespace + commit cravado; parse do JSON sem
executar nada. Os hashes de `binary-diagnostics.md`, `android-analysis.md`,
`firmware-analysis.md`, `ghidra-provider.md`, `routing.json`, `MASTER-ROUTING.md` e
`RULES.md` estão no manifest (upstream) e nas fichas curadas (nomes destes arquivos).

## 6. Não-tocados (verificado)
scripts/, tests/, fixtures/, config/, cases/, reports/ de outras lanes; produção e
clientes; nenhum binário/payload/PII ingerido; clones em ~/Tools read-only.
Alterações desta lane — apenas adições:
- `labs/reverse-next/knowledge/{README,rea,reverse-skill-method,upstream-manifest.json,ingest-receipts.json}`
- `skills/mitr3-reverse-next/SKILL.md`
- este documento.

## 7. Estado final (honesto)
- Ingerir/lerback: **feito** (3 docs, 7+ readback determinístico, JEV shadow).
- skill própria: **feita** — `~/MITR3/skills/mitr3-reverse-next/SKILL.md`.
- Manifest/schema para teste do QA: **entregue** no knowledge dir + cópia ingerida.
- Uso de REA/Ghidra sobre fixtures, execução de script de lab, e integração de clientes:
  **fora da lane** (Build/QA) — não medir, não alegar sucesso que não executei.
