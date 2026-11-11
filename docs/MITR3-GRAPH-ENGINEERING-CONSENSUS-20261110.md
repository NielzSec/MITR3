# MITR3 — Graph Engineering Architecture Consensus & Technical Specification
**Date:** 2026-11-10 | **Status:** APPROVED BY MULTI-AGENT CONSENSUS | **Branch:** `master` (Staging)

---

## 1. Executive Summary & Vision

Operator **dj** and **GPT** formulated the foundational blueprint for connecting the **AI Vulnerability Harness** to the **MITR3 Attack Graph**:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Vulnerability Harness                                    │
│    AST · IaC · Ensemble · SARIF · Semgrep                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Graph Ingestion / Normalizer                             │
│    Normaliza nós, arestas, identificadores, evidências e   │
│    proveniência (SHA256).                                   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. MITR3 Attack Graph                                       │
│    Source ──► Finding ──► Sink                              │
│                   │                                         │
│                   ▼ (inhibited by)                          │
│               Mitigation                                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Evidence & Verification                                  │
│    Caminhos, alcançabilidade, controles e confiança da       │
│    conclusão.                                               │
└─────────────────────────────────────────────────────────────┘
```

The multi-agent operational team (**VANTA**, **OpenCode**, **Hermes**, **Codex Astra**) convened and performed an autonomous architectural review of this model. The consensus verdict is **UNANIMOUS APPROVAL with 3 Hardening Constraints**.

---

## 2. Multi-Agent Team Evaluation & Perspectives

### 2.1 VANTA (Lead Architect / Systems Engine)
* **Verdict:** Validates the pipeline as the missing topological link in MITR3.
* **Analysis:** Current static scanners output isolated finding records (e.g. "SQL injection at line 42"). By mapping findings into a directed property graph, we transform flat detection into verifiable attack paths:
  $$\text{Path} = \text{Entrypoint} \xrightarrow{TAINT} \text{Parameter} \xrightarrow{AST_{reach}} \text{Vulnerability} \xrightarrow{CALLS} \text{Sink}$$
* **Constraint:** The graph must remain fully queryable offline via SQLite (`state/mitr3-attack.sqlite3`) and support streaming JSONL graph exports for high-performance visualizers.

### 2.2 OpenCode (Operational Tooling / Local LLM - GLM 5.3 Flash / DeepSeek V4)
* **Verdict:** Approved. Emphasizes token and inference frugality.
* **Analysis:** Layer 2 (*Normalizer*) must be 100% deterministic Python (`bin/mitr3-graph-normalizer.py`), never reliant on external LLM calls for parsing. Ingesting SARIF, Semgrep, CodeQL, and AST outputs must be an algorithmic O(N) process with zero token cost.
* **Evidence Rule:** Every node and edge must carry an immutable `evidence_sha256` pointing to physical disk artifacts.

### 2.3 Hermes (Autonomous Explorer - DeepSeek V4.1 Flash)
* **Verdict:** Approved. Highlights execution and path reachability.
* **Analysis:** In Layer 4 (*Evidence & Verification*), an attack path cannot merely be theoretical. It must be computed using reachability mathematics:
  $$\text{Exploitability} = P(\text{Source} \to \text{Sink}) \times (1 - \text{MitigationStrength})$$
* If an IaC rule (e.g., AWS Security Group blocking ingress port 8080, or IAM policy denying `s3:GetObject`) is verified on disk, the mitigation edge acts as a physical circuit breaker, pruning the attack edge from the active exploitation graph.

### 2.4 Codex Astra (Spec Enforcer / Formal Gatekeeper - Invariant Watchdog)
* **Verdict:** Approved pending database schema constraints.
* **Analysis:** The SQLite graph schema must enforce foreign key integrity and prevent orphan edges using triggers, exactly like `bin/mitr3-attack-graph.py`:
  ```sql
  CREATE TRIGGER check_edge_endpoints BEFORE INSERT ON attack_edges
  WHEN NOT EXISTS (SELECT 1 FROM attack_nodes WHERE node_id = NEW.source_id)
    OR NOT EXISTS (SELECT 1 FROM attack_nodes WHERE node_id = NEW.target_id)
  BEGIN SELECT RAISE(ABORT, 'Missing graph node endpoint'); END;
  ```

---

## 3. Concrete Schema & Entity Model

### 3.1 Node Types (`attack_nodes`)
| Type | Example ID | Description |
|---|---|---|
| `SOURCE` | `src:fastapi:/api/v1/user/search` | HTTP endpoint, CLI parameter, RPC route, or public event |
| `FINDING` | `fnd:sqli:users.py:L42` | Output of `mitr3-vuln-harness.py` with multi-scanner agreement |
| `SINK` | `snk:db:sqlite3:execute` | Dangerous sink (SQL exec, shell spawn, SSRF request, eval) |
| `MITIGATION` | `mit:iac:sg-09a1c807:ingress_deny` | Terraform/CloudFormation/K8s network or IAM security boundary |
| `ATTACK_TECHNIQUE`| `T1190` | MITRE ATT&CK technique reference |

### 3.2 Edge Types (`attack_edges`)
| Edge | Source -> Target | Semantic Meaning |
|---|---|---|
| `FLOWS_TO` | `SOURCE -> FINDING` | Data flow / taint reachability from entrypoint to vulnerable site |
| `CALLS` | `FINDING -> SINK` | Syntactic AST branch leading into the execution sink |
| `MITIGATED_BY` | `FINDING -> MITIGATION` | Infrastructure or code guardrail inhibiting exploitation |
| `MAPS_TO` | `FINDING -> ATTACK_TECHNIQUE`| Alignment with STIX ATT&CK enterprise catalog |

---

## 4. Implementation Roadmap

1. **Phase 1: Ingestion Engine (`bin/mitr3-graph-normalizer.py`)**
   - Parses SARIF v2.1, Semgrep JSON, CodeQL CSV, and `mitr3-vuln-harness.py` outputs.
   - Emits canonical nodes and edges with deterministic SHA256 hashes.
2. **Phase 2: Graph Database Layer (`bin/mitr3-attack-graph.py` extension)**
   - Unified schema in `state/mitr3-attack.sqlite3` storing both STIX enterprise techniques and live codebase attack chains.
3. **Phase 3: Verification & Path Pruner (`bin/mitr3-graph-verify.py`)**
   - Queries paths from unauthenticated Sources to Sinks.
   - Flags unreachable paths as `SUPPRESSED_BY_IAC` or `AST_UNREACHABLE`.
   - Generates confidence score (0.0 to 1.0) and high-fidelity SARIF / Mermaid reports.
