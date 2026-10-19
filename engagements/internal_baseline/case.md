# Case — internal_baseline

- id: internal_baseline
- type: internal_audit
- scope: `mitr3-nexus-re` e `apisec-ng-mcp-server`
- authorization: interna — host do squad, autorizada por Kai em 2026-10-19
- operator: nielz / squad MITR3
- opened: 2026-10-19
- state: remediated (F-01..F-03), F-04 FP, F-05 accepted

## Objective

Provar a bancada em um alvo real e autorizado: os próprios componentes que o time opera.
Nenhum alvo externo. Saída esperada: cadeia de evidência reproduzível, achados classificados,
e confirmação de que semgrep / trivy / osv-scanner rodam de ponta a ponta.

## Assets in scope

| asset | type | authorization |
|---|---|---|
| `~/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re` | Python source | interna, operador |
| `~/Documents/MegaBrain-OSINT4ALL/repositories/apisec-ng-mcp-server` | Python source | interna, operador |

## Out of scope

Nada fora do host. Nenhum scan de rede, nenhum alvo externo.

## Rules of engagement

- rate / intensity: estático apenas
- window: 2026-10-19 11:05–11:10
- test accounts: n/a
- emergency contact: n/a

## Hypotheses

| # | hypothesis | method | result |
|---|---|---|---|
| 1 | código dos MCPs tem padrões inseguros | semgrep p/python + p/secrets | 2 warnings, ambos revisados como FP |
| 2 | imagens/containers mal configurados | trivy fs misconfig | 2 achados no Dockerfile do apisec |
| 3 | dependências pinadas com CVE | osv-scanner source | 40 advisories em 4 pacotes |

## Evidence index

| id | file | sha256 | note |
|---|---|---|---|
| E1 | evidence/semgrep.json | c215b9c3… | 2 WARNING |
| E2 | evidence/trivy_apisec-ng-mcp-server.json | 1cb21142… | 2 misconfigs |
| E3 | evidence/trivy_mitr3-nexus-re.json | 42ec4eac… | limpo |
| E4 | evidence/osv_mitr3-nexus-re.json | 0e2043fe… | pip 18, requests 10 |
| E5 | evidence/osv_apisec-ng-mcp-server.json | 292764f1… | httpx2 10, httpcore2 2 |

## Findings

| severity | title | asset | status |
|---|---|---|---|
| HIGH | container roda como root | apisec Dockerfile | aberto |
| MEDIUM | dependências com advisories conhecidos | ambos | aberto |
| LOW | Dockerfile sem HEALTHCHECK | apisec | aberto |
| INFO | chmod 0o700 sinalizado pelo semgrep | nexus | falso positivo |

## Timeline

- 2026-10-19 11:05 case aberto, semgrep executado
- 2026-10-19 11:07 trivy por alvo, osv-scanner por alvo
- 2026-10-19 11:10 evidência selada com sha256
- 2026-10-19 11:20 Dockerfile corrigido (USER 10001 + HEALTHCHECK), imagem reconstruída
- 2026-10-19 11:26 mínimos de dependência, rebuild, reteste com trivy fs na árvore extraída
