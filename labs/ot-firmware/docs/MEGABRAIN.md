# MegaBrain integration

Two different paths, with different constraints. Do not confuse them.

## 1. Evidence notes — works from any machine

`megabrain.knowledge_store` accepts text and returns a document/version id plus
a content hash. The lab's `report.md` is text, so the bundle pointer can live in
MegaBrain without shipping binaries.

```
knowledge_store(
  title  = "ACME gateway 4.2.1 — static evidence bundle",
  origin = "mitr3://labs/ot-firmware/ACME-4.2.1",
  text   = <report.md contents + package sha256 + date + authorization note>
)
```

Rules:

- one document per package version, origin names the package
- include the package sha256 and the analysis date in the text
- never paste secrets, keys, credentials or client PII into `text`
- the returned `content_hash` is what you cite, not the title

Demo record stored during the lab build:

```
document_id  539c0e6c-c05b-4994-a7bd-8377bfbdee38
version_id   0f366b04-e4d9-4082-bedf-eb5008e02042
content_hash ece0723b8ab997269a5cc342afc29280c8fd2a5974b124ca36dfcc2a41782f5b
```

## 2. Artifact analysis — server-side roots only

`megabrain.reverse_analyze(artifact)` inspects a local artifact **on the
MegaBrain host**, under its authorized roots. From this workstation the call
returns:

```json
{"status": "degraded", "error": "artifact_outside_authorized_roots"}
```

That is expected: the MCP server runs on a separate host and its roots do not
include `/home/nielz/MITR3`. Two valid ways to use it:

1. copy the extracted binary to a path inside the server's authorized root and
   pass that path (recommended for shared evidence)
2. keep analysis local with REA + Ghidra and store only the text bundle in
   MegaBrain (recommended for client work)

Never widen the server's authorized roots to a whole home directory to make a
single call work.

## 3. What the lab does not send

- No package, binary or firmware image is uploaded to MegaBrain by `fwlab`.
- No secrets are read from the environment by `fwlab`.
- `knowledge_store` is called by the operator, not by the CLI, so the decision
  to publish a text bundle stays human.

## Suggested cadence

| Moment | Call |
|---|---|
| package acquired | `knowledge_search` for prior analysis of the same vendor/version |
| bundle ready | `knowledge_store` one document per version |
| claim about a CVE class | `security_query` / `reverse_query`, then cite the evidence id |
| before publishing | `jev_evidence` on the claim, keep the verdict with the bundle |
