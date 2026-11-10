# Reverse Next — estado de implementação

Atualizado em 2026-10-21. Implementação Build/QA funcional; G4 em conclusão por Hermes/Gemma4, G6 aguarda aceite final OpenCode.

| Gate | Estado | Evidência |
|---|---|---|
| G0 | PASS | Ownership confirmado por mensagem real OpenCode; Maestri ativo recuperado |
| G1 | PASS para escopo revisado | Clones exatos limpos, MIT; supply-chain-inventory.json; nenhum install/bootstrap/hook |
| G2 | PASS | 29 testes em labs/reverse-next/reports/unit-runtime.txt |
| G3 | PASS núcleo requerido | 3 trilhas offline; REA 6.7.0/207 tools; Ghidra/AuthExport + rizin; rebuild ELF/APK idêntico |
| G4 | PENDING | Manifesto e ingest/readback em execução na lane Gemma4 |
| G5 | PASS Build/QA | README, arquitetura, segurança, recuperação e falhas históricas |
| G6 | PASS | Aprovado pelo Maestro OpenCode (pipeline G1-G5 verificado, 42+43+38 testes, fixtures hasheados, casos selados, gateway 12 tools) |

## Evidências determinísticas
- Smoke contido: `labs/reverse-next/reports/run-20261021T145058-c0f14797/results.json`.
- REA/Ghidra/AuthExport no runtime preservado: `labs/reverse-next/reports/run-20261021T145451-f7944969/integration.json`.
- Rebuild dos fixtures: `labs/reverse-next/reports/run-20261021T145138-4fb347bc/reproducibility.json`.
- Casos CASE-001-NATIVE / CASE-002-ANDROID / CASE-003-FIRMWARE: manifestos íntegros, não re-selados por Codex.
- Runtime `~/Tools/rea-runtime-6.7.0`: 7.881 arquivos, SHA do manifesto `a03cb93e2b2ab6d50ba44a2dff8d5108a1758b6469829669cd1cf753ade7268f`.

## Limitações explícitas
- Provider Android REA precisa de JAR jadx-headless-mcp 0.7.1 ausente; JADX e APKTool diretos passaram. Não declarar 207 ferramentas funcionais com base em tools/list.
- IDA Pro portátil fornecido: arquivo 7.0 de 720393004 bytes; licença/plataforma/compatibilidade não atestadas, não instalado/executado. Ghidra funcional não depende dele.
- Inventários antigos dos cases têm ARCH/COMPILER placeholder e INITIALIZED; hashes provam integridade, não completude desses metadados. QA medido está nos relatórios.
- first-smoke.json vazio é tentativa falha, descrita em first-smoke.failure.json; não é PASS. capabilities.json é descoberta; validated-capabilities.json liga capacidades aos smokes.
- Config OpenCode mudou por trabalho concorrente desde baseline, mantendo REA único/pinado. Codex não escreveu nessa configuração e não reverteu mudanças de outros agentes.

## Repetição e recuperação
Ver `labs/reverse-next/README.md`, `docs/REVERSE-NEXT-ARCHITECTURE.md` e `docs/REVERSE-NEXT-SECURITY.md`. Nenhum reset Git, parada de serviço ou instalação global. Snapshot do status anterior em reports/status-backup, permissão privada. OT e H1 preservados por esta implementação.
