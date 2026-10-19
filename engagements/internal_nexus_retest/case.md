# Case — internal_nexus_retest

- id: internal_nexus_retest
- type: internal_retest
- scope: `mitr3-nexus-re` — regressão do pipeline estático
- authorization: interna — mesma base do internal_baseline
- operator: OpenCode (maestro)
- opened: 2026-10-19 11:25
- state: closed (pipeline validado; achados reproduzidos)

## Objective

Provar `bin/mitr3-scan.sh` ponta a ponta e comparar com a rodada manual do
`internal_baseline`: os mesmos misconfigs e advisories devem reaparecer.

## Result

- semgrep 2 resultados, trivy 0 vuln / 0 misconfig / 0 secret, osv 28 (artefato de
  resolução mínima: pip 9.0.3 e requests 2.9.2), secrets-audit 0.
- duração 19 s; evidência selada em `evidence/SHA256SUMS.<timestamp>`.
- resumo em `findings.md`.

## Notes

O `rc=1` do osv-scanner é por desenho: encontrou advisories e o script continua para
produzir o relatório. O que importa é o JSON, não o código de saída.
