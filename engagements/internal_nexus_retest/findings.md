# Findings — internal_nexus_retest (nexus-restest)

Target: `/home/nielz/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re`  ·  2026-10-19T11:26:11-03:00  ·  scan `20261019T112552`

| scanner | signal |
|---|---|
| semgrep | 2 resultados |
| trivy vuln | 0 |
| trivy misconfig (FAIL) | 0 |
| trivy secret | 0 |
| osv-scanner | 28 |
| secrets-audit | 0 |

## Trivy misconfigurations


## Trivy vulnerabilities by severity

{}

## Semgrep (top rules)

- `python.lang.security.audit.insecure-file-permissions.insecure-file-permissions` ×2

## osv-scanner packages

Aviso: para requirements sem pin, o osv-scanner resolve a **versao minima** da faixa;
versões antigas e seus advisories podem ser artefato. Confirme contra o ambiente instalado.

| pacote | versao resolvida | vulns |
|---|---|---|
| pip | 9.0.3 | 18 |
| requests | 2.9.2 | 10 |

## Secrets audit (paths only, values never stored)


## Artifacts

```
evidence/osv.json
evidence/secrets.json
evidence/semgrep.json
evidence/SHA256SUMS.20261019T112520
evidence/SHA256SUMS.20261019T112552
evidence/trivy.json
```
