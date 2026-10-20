# MITR3 — Codex Arsenal independent QA

Source snapshot timestamp: 2026-10-19T18:49:54.507595+00:00
Age (minutes): 5.6
Snapshot action: install
Total tools: 12
Status summary: missing=11, validated=1

| Tool | Phase | Status | Version | Blocker |
|---|---:|---|---|---|
| impacket | 2 | validated | 0.13.1 | none |
| bloodhound-python | 2 | missing | — | package_resolution |
| kerbrute | 2 | missing | — | network |
| responder | 2 | missing | — | network |
| aws | 3 | missing | — | permissions |
| gcloud | 3 | missing | — | network |
| az | 3 | missing | — | permissions |
| prowler | 3 | missing | — | package_resolution |
| scoutsuite | 3 | missing | — | package_resolution |
| cloudfox | 3 | missing | — | network |
| pacu | 3 | missing | — | package_resolution |
| trufflehog | 3 | missing | — | network |

## Caveats
- Privilege errors may reflect execution sandbox and not the actual Arch host; do not modify system ownership or sudo rules blindly.
- Network/package failures need DNS and upstream package verification before diagnosing compatibility.
- A recorded installation attempt is not proof of successful installation; use validated/smoke_ok status only.

## Actionable QA checklist
1. Distinguish installed, CLI-smoke-verified and real protocol/network-functional.
2. Preserve install logs only in private directories; sanitize error messages before adding to shared docs/RAG.
3. Retry network/privilege installation solely from approved host session; never run installers against live targets.
4. Check native pacman package availability and exact upstream package path; pin versions or record hashes.
5. Check wrapper idempotence and do not overwrite unrelated executables.

Security: this report only reproduces allowlisted status metadata, not raw stdout, commands or secrets.
