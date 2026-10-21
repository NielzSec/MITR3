# Method — reconstruct the flow, then prove the crossing

Derived from the public Team82 work on Danfoss AK-SM 800A controllers
(CVE-2025-41450 auth bypass, CVE-2025-41451 command injection,
CVE-2025-41452 configuration manipulation/DoS). The point of that research was
not a suspicious function: it was a reconstructed chain of trust across four
components —

```
external nginx -> CGI component -> internal nginx -> application -> auth + privileged ops
```

That chain is the template. Every OT web surface tends to have the same shape
with different names, and the bug usually sits where one hop trusts a value the
previous hop let a client control.

## Phases

### 1. Acquisition and identity

- Obtain the package from the vendor's official distribution page, under a
  license or authorization that permits analysis.
- Record: URL, version, release date, download time, **sha256 of the package**.
- Store it read-only. Never analyze a package you cannot re-download and match.

### 2. Container identification

`fwlab inspect` reports magic, size, entropy and confidence. Unknown is a valid
answer; guessing is not.

- zip/tar/gz/xz -> `fwlab extract` handles it recursively.
- squashfs/cramfs/ubi/ubifs/jffs2 -> hand off to Unblob (REA `extract_firmware`)
  or `binwalk -e` in an isolated directory.
- vendor `.spk` -> header heuristic only. Locate the payload boundary, carve it,
  then re-run identification on the carved blob. Document the offset you carved
  at; that offset is evidence.

### 3. Inventory

`fwlab inventory` produces per-file sha256, ELF class/arch/endianness/stripped
state, setuid bits, scripts, and strings that matter (auth, session, admin,
system, popen, execve, /bin/sh, upgrade).

Read it like a map, not a list:

- init scripts and service configs show what starts and with which privileges
- CGI binaries and web roots show the exposed surface
- setuid binaries and anything that spawns a shell show the blast radius
- `upgrade`/`firmware` strings show a second trust boundary (package verify)

### 4. Trust-boundary reconstruction

This is the phase that separates a finding from a guess. For each exposed entry
point, answer:

1. What bytes does the client control? (headers, query, body, filename, cookie)
2. Where does each value enter the process? (parse function, offset)
3. What check stands between it and the privileged operation?
4. Is the check on the same value that reaches the operation, or on a copy that
   was normalized differently?

The classic crossings:

- header treated as identity (`X-User`, `X-Admin`, `X-Forwarded-*`)
- path normalized after authorization but before use (`/admin/../public`)
- token compared with a non-constant-time or prefix-only function
- internal hop trusts anything arriving from `127.0.0.1`
- config write accepts a path the read path would reject

### 5. Hypothesis, then static confirmation

Write the hypothesis as a sentence with two addresses:

> `strstr` at 0x… compares the client header `X-Lab-Admin: 1` against the raw
> request buffer, and jumps past the session check at 0x… when it matches.

If you cannot name both addresses, you have a suspicion, not a finding.

### 6. Validation on owned ground

- Run the extracted binary in an emulated or local harness you own.
- No network egress. No real controller. No vendor infrastructure.
- Capture the request that crosses the boundary and the response that proves
  the privileged operation happened.
- If the binary cannot be run safely, static proof stands alone — label it as
  static and say what would confirm it dynamically.

### 7. Evidence and delta

- Bundle: package sha256, `inspect.json`, `inv.json`, `q.jsonl`, `report.md`,
  decompiled excerpt with addresses.
- If a fixed version exists, `fwlab diff` and decompile the same function in
  both. A one-function delta at the trust boundary is the strongest possible
  evidence that the vendor agreed with your read.
- Report the crossing, the precondition, the impact, and the fix. Never inflate
  reachability: an auth bypass that needs a local port is not the same finding
  as one that needs the internet.

## Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| "found `system()` in a binary" | every embedded web stack has one; the finding is what reaches it |
| strings-only report | strings prove presence, never control flow |
| decompiling one function in isolation | the bug is usually in the caller's contract |
| testing on a live device "just to confirm" | scope, safety, and reproducibility all degrade |
| claiming CVE equivalence | your target is not the CVE's target until you prove the same path |

## Mapping to the Danfoss case

| Public finding | General shape | What to look for locally |
|---|---|---|
| CVE-2025-41450 auth bypass | a component accepts a request without validating the session the next hop assumes | CGI entry that never calls the session check, or calls it after dispatch |
| CVE-2025-41451 command injection | client string reaches a shell through a config or diagnostic path | `popen`/`system` with a buffer filled from HTTP |
| CVE-2025-41452 config manipulation / DoS | privileged write path accepts unvalidated content | upload/restore handlers, config parsers, watchdog resets |

These are patterns, not claims. A local match is a lead; only your own evidence
turns it into a finding.
