# MITR3 — Operational Environment

Arch Linux host `nielz-aspire-a315-53` · squad wired through Maestri · last audit 2026-10-19.

## Layout

```
~/MITR3/
  README.md              this file
  bin/mitr3-health.sh    one-shot health + toolchain sweep
  bin/mcp-smoke.py       launch an MCP server over stdio and call one tool
  docs/SCOPE.md          Nexus human-contract procedure
  docs/TOOLCHAIN.md      installed / missing matrix, owners
  docs/RE-VALIDATION.md  Ghidra / r2 / jadx / rizin / frida proofs
  docs/WEBAPI-VALIDATION.md  nmap / ffuf / nuclei / sqlmap / trivy proofs
  docs/OSINT-PLAYBOOK.md MegaBrain-backed research workflow
```

## Squad

| Seat | Agent | Engine | Lane |
|---|---|---|---|
| Maestro | OpenCode | DeepSeek V4.1 Flash | orchestration, active testing, installs |
| Research | Gemma4 / Hermes | gemma4:31b-cloud | MegaBrain, OSINT, documentation |
| Build | Codex | GPT-6-Sol | QA, reproducibility, code review |
| Reverse | Antigravity / VANTA | Gemini 3.8 Flash | RE, low-level, tooling |
| Exploit | deepseek | DeepSeek-V4-Flash-0731 | pentest, web/API |

Comms: `maestri list` · `maestri ask "Agent" "prompt"` · `maestri ask --batch '{...}'`.
Handoffs use the ask-back pattern: the worker calls `maestri ask "OpenCode" "<result>"` when done.

## MCP plane

| Server | Transport | State |
|---|---|---|
| megabrain | HTTP `nielz-aspire-a315-53.tailb82a64.ts.net/mcp` | ok, 1018 docs / 23186 claims / 9438 evidence |
| mitr3-nexus | stdio | ok, 10 tools, scope-gated |
| rea | stdio | ok, 209 tools, Ghidra 12.1.2 backend |
| context7 | HTTP | ok |
| chrome-devtools | stdio → Brave | fixed 2026-10-19 (`--executablePath /usr/bin/brave`) |
| playwright | stdio | chromium installed |
| apisec-ng | stdio → REST | fixed 2026-10-19 (`secbolt:` prefix strip in launcher) |

Config lives in `~/.config/opencode/opencode.json` and `~/.hermes/config.yaml`. Both must agree when a server is fixed.

## Root policy

`sudo` is available to the squad (`wheel`). Use it for package installs, service changes and toolchain repairs — not for destructive operations on user data or history. Reversible changes: just do them. Anything that deletes, overwrites or pushes: state it first.

## Scope policy

Nexus refuses routed work without a human contract (`no_human_contract`). The contract is per artifact and per purpose, signed interactively with the artifact SHA256. Procedure in `docs/SCOPE.md`. Agents never mint their own approval; the operator does.

## Health

```bash
~/MITR3/bin/mitr3-health.sh            # environment
~/MITR3/bin/mitr3-health.sh --json     # machine readable
maestri list                           # squad presence
```

## Toolchain source of truth

`~/.local/bin` (go + pipx) is prepended to PATH by the shell profile. If a tool exists but is not found, check that first.
