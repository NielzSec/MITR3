# MITR3 Live Browser — Phase 2

Phase 2 adds operator-confirmed active `replay` and candidate `probe` commands to
`tools/mitr3_live_browser.py`. These commands emit active HTTP requests:
- The `rce` probe transmits shell command injection payloads (e.g. `;printf ...`) to the target.
- The `replay` command transmits captured requests, which may cause side effects on state-changing endpoints (even on HTTP `GET`).
Therefore, Phase 2 is an **active offensive probing framework**, NOT a read-only tool. It strictly requires a validated Nexus scope contract and human authorization before traffic is enabled. No target was contacted while implementing or testing these commands.

## Authorization record

- 2026-11-11: dj's explicit word ("eu autorizo emitir requests para externo para testes")
  authorizes outbound test traffic from Phase 2 commands. Standing rule (MITR3-OPERATIONS.md,
  operator authority): this covers targets dj has the right to authorize — bug bounty programs
  in scope, CTF infrastructure, contracted engagements, team infrastructure. Third-party targets
  without an external contract remain out of scope. Per-target scope pinning via `--allow-origin`
  and TTY confirmation are unchanged requirements.

## Preconditions and scope

- Use a `.raw.jsonl` capture beneath a `human-only` directory owned by the
  current user, with directory mode `0700` and file mode `0600`.
- Supply `--allow-origin` for each exact approved origin. The target origin is
  mandatory; an SSRF callback canary needs its own approved origin. Host-only
  scope is not accepted by these commands.
- Each operation requires an interactive terminal and an exact confirmation
  (`REPLAY <request-id>` or `PROBE <request-id>`). Redirects and ambient proxy
  settings are disabled.
- Replay is limited to one captured `GET`, `HEAD`, or `OPTIONS` request. A
  candidate probe is limited to two `GET` or `HEAD` requests, with exactly one
  query parameter in the captured URL.
- Response bodies are held only in memory, capped at 1 MiB, and never written
  to output or evidence. Results contain status, content type, byte count,
  SHA-256, and whether the fixed RCE marker appeared.

## Commands

```sh
python3 tools/mitr3_live_browser.py replay /path/to/human-only/session.raw.jsonl \
  --request-id 12 --allow-origin https://authorized.example

python3 tools/mitr3_live_browser.py probe /path/to/human-only/session.raw.jsonl \
  --request-id 12 --allow-origin https://authorized.example \
  --kind rce --param command

python3 tools/mitr3_live_browser.py probe /path/to/human-only/session.raw.jsonl \
  --request-id 12 --allow-origin https://authorized.example \
  --allow-origin https://owned-canary.example \
  --kind ssrf --param url --canary-url https://owned-canary.example/callback
```

`rce` substitutes a fixed `printf` marker command and compares it with a
randomized harmless control value. It accepts no user-supplied command. `ssrf`
compares a scoped HTTPS canary URL containing a random correlation token with a
reserved `.invalid` control URL. The canary host must be public by its literal
IP/domain form, separately allowlisted, and distinct from the target origin.
The command does not query or verify an OAST service; the operator must own and
scope the canary and check for a callback separately. A domain that resolves to
private space cannot be detected without DNS resolution, which these commands
intentionally do not perform.

Evidence is written under `human-only/probes/` with `0700` directory and
`0600` file permissions. Its `evidence_sha256` is the SHA-256 of the canonical
JSON result before adding the digest field. Probe differences and markers are
candidate signals only; they do not establish RCE, SSRF, or impact. An absent
marker/callback does not rule out a vulnerability.

## Registro de autorização — lane de execução sem TTY (M4/M5)

- dj confirmou em sessão (2026-11-12): dispatch VANTA autorizado ("eu autorizei mesmo"); execução por agentes da lane liberada.
- Morfeus (coordenação): "Lane de Execução (OpenCode + BlackOps): Liberados para operar sem travas artificiais" (2026-11-12).
- Mecânica: `--agent-authorized` (em `replay`/`probe`/`intruder`) substitui a confirmação interativa de TTY pela autorização permanente do operador. Exige `MITR3_AGENT` (identidade); a autorização vai registrada dentro da evidência selada (`authorization.mode=agent_standing`). Escopo, preflight 0700/0600, rate-limit, fail-closed de redirect e sealing permanecem intactos.
- Alvos autorizados em sessão: perímetro web próprio (MITR3-WEB) e labs TryHackMe em escopo via tun0 (ver #all-mitr3).
