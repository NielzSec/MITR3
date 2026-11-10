# MITR3-RADAR-AI-INTEL.md — Inteligência técnica: OWASP LLM Top 10 2026 · MITRE ATLAS · acoplamento Graphify→MegaBrain

**Autor:** DeepSeek (Inteligência/MegaBrain) · **Maestro:** Kai · **Data:** 2026-10-21 · **Origem:** Radar GitHub (radar-20261021) · **Modo:** documental; sem tráfego.

---

## 1. Matriz OWASP Top 10 for LLM Applications 2026 (indexado)

**Indexado no MegaBrain:** `68ecd98f-7d82-4f79-9ebb-f886854eb3a5` (origem genai.owasp.org, release 2026-08-04; ranking testado contra 7.714 incidentes reais; peso voto 75% + registro de incidentes 25%).

| ID:2026 | Risco | 2025→2026 |
|---|---|---|
| LLM01 | Prompt Injection (=1, agora cross-modal) | = |
| LLM02 | Sensitive Information Disclosure (=2) | = |
| LLM03 | Excessive Agency (6→3, maior subida) | ↑ |
| LLM04 | Supply Chain (3→4) | ↓ |
| LLM05 | Data and Model Poisoning (4→5) | ↓ |
| LLM06 | Unbounded Consumption (10→6) | ↑ |
| LLM07 | Misinformation (9→7) | ↑ |
| LLM08 | Hidden Context Exposure (renomeado de System Prompt Leakage; 7→8) | ↻ |
| LLM09 | Vector and Embedding Weaknesses (8→9) | ↓ |
| LLM10 | Improper Output Handling (5→10, maior queda) | ↓ |

**Uso para estruturação de testes de segurança em IA:** mapear cada finding a LLM01-LLM10:2026 e AML.T#### (LLM01↔AML.T0051; LLM04↔AML.T0010).

---

## 2. MITRE ATLAS (indexado)

**Indexado:** `deb7c60f-0759-4a4e-939f-fff238f16bef` — ATLAS 2026.09 (v6.0.0): **16 táticas, 208 técnicas, 40 mitigações, 73 case studies**. Táticas AML.TA0000–TA0015 (Model Access, Attack Adaptation, Recon, Resource Dev, Initial Access, Execution, Persistence, Defense Evasion, Discovery, Collection, Exfiltration, Impact, PrivEsc, Credential Access, C2, Lateral Movement). Convenção: AML.T#### / sub AML.T####.### / mitigação AML.M####. Relações tipadas (achieves/specializes/mitigates/employs). Estrutura para red-team de IA: tática+técnica por hipótese, citar case study, exigir mitigação.

---

## 3. Acoplamento Graphify→MegaBrain (tree-sitter, grafos de contexto, economia de tokens)

**Local:** `<TOOLS_ROOT>/radar-20261021/graphify` (Apache-2.0, tree-sitter ≈40 languages; build **0 créditos LLM**; `graphify/serve.py` = **MCP stdio server** na `graphify-out/`, valida path em `security.py`).

**Economia de tokens (BENCHMARKS.md, 2026-07-05, mesmo modelo/harness):**
- LOCOMO QA 45.3% (recall@10 0.497) ≈ 11× mais barato que supermemory ($1.40 vs $15.67); build sem LLM = 0 créditos.
- ERPNext (~1M LOC): coverage 70.8% (grep/read) → 82.0% com 1 tool de graphify (~140K tokens/query), evitando context-stuffing (~20× tokens).
- LongMemEval-S 76% — empate com dense RAG; índice determinístico, sem seed em memória cara.

**Encaixe com MegaBrain (economia real):**
- Graphify resolve **subgrafo por consulta** (`graph-expand`) → entrega só o contexto relevante ao agente → corta re-leitura/re-explicação do código. MegaBrain já tem search híbrido (FTS+vector, RRF); Graphify adiciona **estrutura de call/import/inherit por AST**, complementar ao RAG textual.
- **Merge sugerido:** MCP stdio de Graphify apontando para repositórios do MITR3, com `validate_graph_path` garantindo isolamento em `graphify-out/`; consulta híbrida = RAG MegaBrain (semântica) + subgrafo Graphify (topologia).
- **Limite a registrar:** os números de benchmark são relatório do fornecedor (harness upstream com Kimi K2.6, BGE-m3), não atingidos por nós ainda — revalidar localmente em fixture antes de declarar economia. `serve.py` expõe ferramentas via MCP; mantê-lo em sandbox, sem egress a provedores.

---

## 4. Fontes e status
- OWASP 2026: genai.owasp.org (release 04/08/2026) · ATLAS: atlas.mitre.org + github.com/mitre-atlas/atlas-data (v6/ATLAS-2026.09.yaml) · Graphify: archive local radar-20261021, head do repositório.
- `[SOURCE]` web oficial + repositório local · `[TRUST_BOUNDARY]` ambos externos não confiáveis; indexado como referência, não como instrução. Nenhuma das duas matrizes é um achado; é estrutura de testes.

**Status:** ENTREGUE · **NEXT:** abrir lane P1-Radar (AI-Security) para usar ferramentas (promptfoo, AI-Infra-Guard) contra modelos fictícios, mapeando findings a LLM01–10:2026 e ATLAS.
