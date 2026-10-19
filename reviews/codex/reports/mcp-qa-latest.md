# MITR3 — independent QA for Codex MCP check

Original timestamp: 2026-10-19T18:23:53.471245+00:00
Age in minutes: 3.8
Configured servers: 7
OpenCode client-confirmed connections: 0
This QA tool performs zero process launches and zero network requests.

| Server | QA grade | Limited transport evidence |
|---|---|---|
| megabrain | unverified_http_reachable | HTTP 406 |
| rea | launch_failure_review | local launch failure |
| chrome-devtools | launch_failure_review | local launch failure |
| apisec-ng | unverified_process_stable | local process survived smoke window |
| playwright | launch_failure_review | local launch failure |
| context7 | unverified_http_reachable | HTTP 405 |
| mitr3-nexus | unverified_process_stable | local process survived smoke window |

## Caveats
- OpenCode status unavailable; zero connections confirmed via its CLI
- Separate smoke launch failures do not prove that live client MCP sessions are down
- HTTP GET 405 or 406 is not an MCP initialize/tools/list success

## Recommendations to Codex and OpenCode
1. Separate process health, HTTP reachability, protocol handshake and client-connected state.
2. To verify an MCP server, use JSON-RPC initialize and tools/list over stdio or Streamable HTTP.
3. GET HTTP 405/406 does not prove MCP works and is not necessarily a server failure.
4. A 5-second subprocess test may fail while the real persistent client works.
5. Diagnose OpenCode HTTP 500 without restarting active agent sessions.
6. Never persist raw stderr, credentials, Authorization headers or private tool responses.

MCP specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
