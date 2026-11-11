# MITR3 — Codex Task Brief: Finish Layer 4 (Evidence & Verification)
**Date:** 2026-11-10 | **Target:** `bin/mitr3-graph-verify.py` & `tests/test_graph_verify.py`
**Working Directory:** `/home/nielz/MITR3/MITR3` (and sync to `/home/nielz/MITR3`)

---

## 1. Context & What Claude Left Off
Claude began implementing Layer 4 (`bin/mitr3-graph-verify.py`) based on the Graph Engineering architecture consensus, but was cut off mid-session due to token exhaustion.

### What Claude Implemented:
* Database schema for `verification_evidence`, `evidence_revocations`, `path_verdicts` with strict triggers.
* Functions: `record_evidence()`, `revoke_evidence()`, `load_evidence()`, `confidence()`, `evaluate()`, `persist()`, `verify()`, `list_evidence()`.
* Handling of `ast_gate` as both integer `(0, 1)` and string `("PASS", "FAIL")`.
* Invariant: `PROVEN` is NEVER set automatically by this layer (maximum state is `FEASIBLE_PATH`).

### What Remained Incomplete:
1. **Missing CLI in `bin/mitr3-graph-verify.py`:**
   The file ends at line 421 without `main()` or CLI argument parsing.
   Needs CLI support for:
   - `record <evidence.json>`
   - `revoke <evidence_id> --reason <text> --by <who>`
   - `list`
   - `verify [--exposure <exp>] [--write] [--json]`
2. **Missing Unit Test Suite:**
   Create `/home/nielz/MITR3/tests/test_graph_verify.py` (and copy to nested repo) covering:
   - Schema creation and append-only trigger enforcement.
   - Recording valid evidence and rejection of invalid evidence.
   - Live artifact verification and hash mismatch detection.
   - Revocation workflow.
   - Path evaluation (`ACTIVE`, `SUPPRESSED_BY_IAC`, `AST_UNREACHABLE`, `CONFLICT`).
   - Confidence scoring and `FEASIBLE_PATH` promotion.
3. **Documentation:**
   Document Layer 4 in `docs/MITR3-VERIFICATION-LAYER4-20261110.md`.

---

## 2. Hardening Constraints (Codex Doctrine)
* Standard library only (`sqlite3`, `json`, `pathlib`, `hashlib`, `unittest`).
* Do NOT rerun passed tests from C1/C2/C3 unnecessarily.
* Always check `#all-mitr3` on Slack before posting.
* Maintain Git custody: VANTA commits to `master`.
