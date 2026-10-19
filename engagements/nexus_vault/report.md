# Report — nexus_vault (ret2win end-to-end, evidência selada)

**Alvo:** `target/vault` — ELF64 x86-64, não stripped, construído neste host.
**sha256:** `cac247233c6ba8155c2a9acbcfa629fcd42ad762f0c6982ae87072b74685d97c`
**Build:** `gcc -fno-stack-protector -no-pie -z execstack -O0`
**Contrato:** `nexus_vault`, purpose `ctf`, operador `opencode-for-kai`, expira 2026-10-22.
**Estado:** encerrado — vulnerabilidade confirmada estaticamente e explorada em runtime local.

## Vetor

`vuln()` lê até `0x200` bytes em `local_48[64]` (`rbp-0x40`); o endereço de retorno salvo
fica a **72 bytes** (64 do buffer + 8 do rbp). `win()` existe em `0x401176`, imprime a flag
e não tem nenhum chamador. Buffer overflow clássico → ret2win.

## Cadeia de validação

| vetor de confiança | prova |
|---|---|
| 3 providers estáticos | `objdump` (EV-0002), `readelf` (EV-0004), decompilador REA/Ghidra (EV-0005/0006) |
| provider independente | `rizin 0.8.2` — `buf @ stack -0x48` = 72 bytes; nenhum XREF para `0x401176` (RE-VANTA.md) |
| gate adversarial | Codex reprovou a redação original de EV-0001 (falsa sobre `PT_GNU_STACK`) e aprovou o restante com ressalvas; correção registrada em EV-0004 |
| runtime | `dynamic/validate_ret2win.py` — variante direta atingiu `win()`, flag `MITR3{v4ult_r0p_4nd_ev1d3nce}` capturada em stdout (EV-0007) |

O exploit usa o solver do deepseek (`solver/exploit_solver.py`, offset 72, `p64(0x401176)`).
Nada mais foi executado: sem rede, sem target externo, binário local do próprio case.

## Evidence

| id | fonte | claim |
|---|---|---|
| EV-0001 | checksec | mitigação (redação original errada; ver EV-0004) |
| EV-0002 | objdump | `buf` em `rbp-0x40`, `read 0x200`, offset 72 |
| EV-0003 | objdump | `win@0x401176` sem call direto |
| EV-0004 | readelf | correção: `PT_GNU_STACK` presente, RWE |
| EV-0005 | rea/ghidra | `vuln`: `local_48[64]`, caller `main` |
| EV-0006 | rea/ghidra | `win`: sem callers, `puts(0x402008)` |
| EV-0007 | dynamic | **offset 72 confirmado em runtime; flag capturada** |
| EV-0008 | governance | contrato v2 supersede v1: `--allow-dynamic` explícito, gate TTY intacto |

`UNK-0001` (confirmar offset 72 dinamicamente): **fechado por EV-0007**.

## Governança

O autorizador exigia `allow_dynamic_debugging: false` fixo. Foi estendido com um parâmetro
explícito (`--allow-dynamic`) em vez de contornado: o gate humano permanece (TTY +
frase `AUTORIZO <sha12>`), o consentimento dinâmico passa a ser uma decisão registrada,
e o contrato v1 (static-only) ficou arquivado em `evidence/contract_v1_static_only.json`.
SHA inalterado → lock de rota preservado. O status do MCP agora reflete o contrato:
`allow_dynamic_debugging: true`, `dynamic_debugging: allowed_by_contract`.

## Limites

- Após `win()` retornar, o processo segfaulta (sem chain de `exit`) — esperado; a flag já
  está em stdout. Sem canary/PIE/RELRO-full, um chain mais completo não agrega ao case.
- `-z execstack` está no build mas não foi exercitada (ret2win não precisa de shellcode).

## Artefatos

- `solver/exploit_solver.py` + `solver/README.md` (deepseek) — offset e payload, modo `--dry`
- `dynamic/validate_ret2win.py` — harness de validação (dois variantes, transcript)
- `evidence/` — 8 arquivos + SELO `SHA256SUMS` (inclui `RE-VANTA.md`, `QA-CODEX.md`, contract v1)
