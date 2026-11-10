---
name: mitr3-codeql
description: CodeQL security-extended scans with repeatable SARIF, severity summaries, immutable runs and SHA256 evidence for authorized MITR3 source audits.
user-invocable: true
---

# MITR3 CodeQL — shared agent skill

Use for **authorized source-code audits and controlled labs**. The active CLI is
`~/.local/bin/codeql` (2.27.2) and the driver is
`~/MITR3/bin/mitr3-codeql.sh`.

## Quick workflow

1. Confirm you are analyzing a local codebase you are allowed to inspect.
2. Choose the language; default is Python:
   ```bash
   ~/MITR3/bin/mitr3-codeql.sh /absolute/path/to/repo python
   ~/MITR3/bin/mitr3-codeql.sh /absolute/path/to/js-repo javascript
   ```
3. Read the path printed by the runner. Every invocation gets its own
   `~/MITR3/engagements/codeql_<repo>_<hash>/runs/<timestamp>_<lang>/` folder.
4. Review `codeql-findings.md` for CRITICAL/HIGH/MEDIUM/LOW/INFO counts
   and top query IDs with file:line; verify `evidence/codeql-<lang>.sarif`
   for complete detail.
5. In the run directory, check `sha256sum -c evidence/SHA256SUMS`.
   Inspect `logs/database-analyze.log` for `CodeQL scanned X out of Y`.
6. Confirm suspected issues by manual code review and test appropriate to
   the authorized scope before reporting. 0 findings is not proof of safety.

## Go — important upstream build limitation

The CodeQL CLI does **not** support `--build-mode=none` for Go.
The driver refuses Go by default, preventing implicit execution of arbitrary
repository build instructions. On a trusted and authorized repository only:

```bash
MITR3_CODEQL_ALLOW_GO_BUILD=1 ~/MITR3/bin/mitr3-codeql.sh /path/to/go-repo go
```

This opts into `autobuild`. Consider a sandbox/container with restricted
network and resources if the repository is untrusted.

## Privacy and coordination

- Databases are in `/tmp/opencode/codeql-db-*`; do not delete them from
  another agent's session or treat them as permanent storage.
- Results are versioned, SARIF and reports are protected with umask 077.
- Do not publish raw SARIF or sensitive snippets into MegaBrain/RAG without
  redaction and independent QA.
- If a scan fails, preserve the run folder/logs and report failure accurately.
- Do not modify source files, credentials, another agent's work or the Maestri
  board merely to make a finding pass.
- Coordinate findings with the OpenCode maestro and Codex QA.
- Canonical documentation: `~/MITR3/docs/TOOLCHAIN.md`,
  `~/MITR3/docs/RUNBOOK.md`.
