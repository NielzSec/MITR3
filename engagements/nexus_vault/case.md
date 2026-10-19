# Case — nexus_vault

- id: nexus_vault
- type: internal_ctf (treino do pipeline Nexus)
- scope: `target/vault` — binário construído por nós para exercitar o fluxo constitucional
- authorization: contrato Nexus `nexus_vault` v2 (purpose `ctf`, operator `opencode-for-kai`, expira 2026-10-22T15:09:13Z, `allow_dynamic_debugging: true`)
- operator: OpenCode (maestro) + squad
- opened: 2026-10-19 11:53
- state: **encerrado** — estático + gate + runtime (flag capturada); ver `report.md`

## Objective

Provar o fluxo completo do MITR3-NEXUS em alvo real e pequeno: contrato assinado por hash,
roteador 3-eixos, lock de rota, análise estática, evidência registrada, gate de QA e solver
sem execução. O alvo é nosso: menu com `read(0, buf, 0x200)` em buffer de 64 bytes e uma
função `win` não referenciada.

## Alvo

| campo | valor |
|---|---|
| arquivo | `target/vault` (ELF64 x86-64, não stripped) |
| sha256 | `cac247233c6ba8155c2a9acbcfa629fcd42ad762f0c6982ae87072b74685d97c` |
| build | `gcc -fno-stack-protector -no-pie -z execstack -O0` |
| mitigação | sem canary, sem PIE, Partial RELRO, `PT_GNU_STACK` RWE |
| fonte | `target/vault.c` |

## Fluxo executado

1. Contrato: `authorize_scope.py` sob PTY, frase `AUTORIZO cac247233c6b` — `mitr3_scope_status` devolveu `approved`, `human_scope_valid=true`, workspace `nexus_vault`.
2. Roteador: `cli.py route` → `ROUTE_DEFCON_PWN`, perfil `deep_vuln_audit`, skill `skills/native-pwn-defcon/SKILL.md`.
3. Lock: `mitr3_route_and_lock_scope` → `locked`, sha prefix `cac247233c6b`.
4. Análise estática pelo servidor: provider `readelf` ok; `checksec` e `ropper` não estão habilitados no runtime recuperado.
5. Evidência: EV-0001..EV-0006 (checksec, objdump, readelf, REA/Ghidra).
6. Gate 2 por Codex: **BLOQUEADO** com correção de EV-0001; corrigido em EV-0004.
7. Fase 6 (solver + runtime): `solver/exploit_solver.py` escrito; contrato v2 com
   `allow_dynamic_debugging=true` assinado; `dynamic/validate_ret2win.py` explora o binário
   local e captura a flag. **Case fechado.**

## Evidence

| id | fonte | claim |
|---|---|---|
| EV-0001 | checksec | mitigação (redação original errada sobre GNU_STACK) |
| EV-0002 | objdump | buf em rbp-0x40, read 0x200, offset 72 |
| EV-0003 | objdump | `win@0x401176` sem call direto |
| EV-0004 | readelf | **correção**: `PT_GNU_STACK` presente, RWE; sem PT_LOAD RWX |
| EV-0005 | rea/ghidra | dossier `vuln`: `local_48[64]`, caller `main` |
| EV-0006 | rea/ghidra | dossier `win`: sem callers, `puts(0x402008)` |
| EV-0007 | dynamic | offset 72 em runtime; flag `MITR3{v4ult_r0p_4nd_ev1d3nce}` capturada |
| EV-0008 | governance | contrato v2 (`--allow-dynamic` explícito); v1 arquivado |

`UNK-0001` (offset 72 em runtime): **fechado por EV-0007** — o autorizador ganhou o
parâmetro explícito `--allow-dynamic` (gate humano TTY intacto) e o contrato v2 foi
assinado com dinâmico permitido; variante direta e ret-sled atingiram `win()`.

## Gate 2 — resultado

Codex reprovou EV-0001 e aprovou EV-0002/EV-0003 como verificações estáticas qualificadas.
Correção aplicada por evidência nova (EV-0004), sem reescrever histórico. QA completa em
`QA-CODEX.md`.

## Artefatos

- `evidence/` — dossiers, logs de Ghidra, QA
- `solver/exploit_solver.py` + `solver/README.md` (deepseek)
- `FIELD-NOTES.md` (Gemma4/Hermes) + documento no MegaBrain `d4ee8007-dcda-4242-9f1c-379ea56496cc`

## Limitações e gaps

- `scripts/ghidra_headless_dumper.py` não roda: o headless atual exige PyGhidra
  (`Ghidra was not started with PyGhidra. Python is not available`). O dossier de Ghidra
  deste case veio pelo provider REA, não pelo dumper. Gap registrado no TOOLCHAIN.md.
- Binários nativos do Ghidra estavam sem bit de execução (`os/linux_x86_64/*` em 0600);
  corrigido com `chmod +x` — vale checar após cada atualização do Ghidra.
- Após `win()` o processo segfaulta (sem chain de `exit`); a flag já está em stdout.
  `-z execstack` presente no build mas não exercitada (ret2win não usa shellcode).

## Timeline

- 11:53 alvo compilado e contrato assinado sob PTY
- 11:55 rota DEFCON_PWN travada
- 11:56 EV-0001..0003; UNK-0001 registrado
- 11:57 Gate 2 Codex: bloqueado
- 11:58 EV-0004 (correção) e solver do deepseek
- 11:59 EV-0005/0006 via REA; dossiers Ghidra falham por PyGhidra
- 12:00 conhecimento capturado no MegaBrain
- 12:05 rizin cobre VANTA (3º provider); EV-0002/0003 confirmados
- 15:05 autorizador estendido (`--allow-dynamic`); contrato v2 assinado (EV-0008)
- 15:07 `dynamic/validate_ret2win.py`: variantes direta e ret-sled atingem `win()`;
  flag capturada (EV-0007); UNK-0001 fechado
