# Nexus scope contract

Nexus routes reverse/offensive work only when a human contract exists for the artifact.
Without one: `human_scope_valid=false`, `route_locked=false`, `target_execution=disabled`.

## What a contract pins

- workspace (name only, `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
- absolute, non-symlink target file and its SHA256
- purpose: `ctf`, `bug_bounty`, `authorized_pentest`, `internal_audit`, `reverse_research`, `appsec`
- operator name, `authorized_at`, `expires_at` (1–720 h), `allow_dynamic_debugging=false`

Stored at `~/.local/share/mitr3-nexus/scopes/<workspace>.json`, mode 0600.

## Creating one (operator, interactive TTY)

```bash
cd ~/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re
python authorize_scope.py \
  --workspace <case_name> \
  --target /absolute/path/to/artifact \
  --purpose reverse_research \
  --operator nielz \
  --hours 72
# prints the SHA256, then asks you to type: AUTORIZO <first 12 hex of sha256>
```

It refuses when stdin is not a TTY. That is the point: the approval is typed by the
operator, not minted by a tool call. Agents prepare the exact line; they do not run it.

## Per-artifact, not per-machine

One contract = one file digest. A second sample needs a second contract. Binaries that
change (rebuild, different build id) invalidate the digest and need re-approval.

## Checking state

```bash
~/MITR3/bin/mitr3-health.sh        # host
# MCP: mitr3_scope_status -> approved, purpose, expires_at
```

## When a target arrives

Send the path to the squad. The reply is the filled-in command above; the operator runs it
and types the phrase. Nexus then unlocks routing for that digest only.
