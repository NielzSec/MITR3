# Gate 2 — QA independente de `nexus_vault`

Data: 2026-10-19 14:57 UTC. Alvo: `target/vault` (ELF64 x86-64, não stripped, build ID `241ec7ac83880cfdf38438858dd902dc23f8a319`). Contrato: `~/.local/share/mitr3-nexus/scopes/nexus_vault.json`, purpose `ctf`, operator `opencode-for-kai`, expiração `2026-10-22T14:53:27.024299+00:00`, `allow_dynamic_debugging=false`. Fiz somente leitura estática; **não executei o binário**.

| Claim | Veredito | Evidência independente e limite |
|---|---|---|
| SHA256 do alvo = contrato | **Aprovado** | `sha256sum target/vault` produziu `cac247233c6ba8155c2a9acbcfa629fcd42ad762f0c6982ae87072b74685d97c`, idêntico ao campo `sha256` do contrato. O vínculo é com estes bytes locais, não com uma eventual cópia remota. |
| EV-0001: sem canary, sem PIE, Partial RELRO, pilha executável | **Parcial; corrigir antes de aprovar** | `checksec --file=target/vault` reproduz esses quatro resultados. `readelf -W -h -l -s` mostra `ET_EXEC`, base `0x400000`, `GNU_RELRO`, `GNU_STACK` **presente com flags RWE**, e a função `vuln` sem sequência de canary; `readelf -d` não mostra `BIND_NOW`. A frase registrada **“GNU_STACK ausente” é falsa**. Não há `PT_LOAD` RWX; o `RWE` é do `PT_GNU_STACK`. A opção de link `-z execstack` é plausível, mas não demonstrável apenas pelo ELF. |
| EV-0002: buffer de 64 bytes, leitura de até 512, retorno salvo em offset 72 | **Aprovado como derivação estática** | `objdump -d -M intel target/vault`: `vuln@0x40118c` faz `push rbp; mov rbp,rsp; sub rsp,0x40`; `0x4011b2` passa `[rbp-0x40]` a `read@plt`, com `rdx=0x200`, `rdi=0`. Do início do buffer ao RIP salvo há `0x40 + 8 = 72` bytes. Isso não comprova que uma carga útil controla o fluxo em execução. |
| EV-0003: `win@0x401176`, sem `call` de entrada, imprime a string da flag | **Aprovado no escopo estático; ret2win não demonstrado** | `readelf -Ws` mostra símbolo local `win` em `0x401176` (22 bytes). O disassembly mostra referência a `.rodata` em `0x402008` e `call puts@plt` em `0x401184`; `readelf -p .rodata` confirma a string. A varredura de `call` no `.text` não encontrou chamada direta a `win`; `main` chama `vuln@0x40118c` em `0x401217`. A ausência de chamada direta não exclui entrada indireta e não prova sucesso de um retorno forjado. |
| UNK-0001: confirmação dinâmica do offset pendente | **Aberto, corretamente** | O contrato proíbe depuração dinâmica. Nenhum GDB, execução, payload ou teste de exploit foi feito. O offset 72 é sólido para o frame no ELF atual, mas o comportamento em runtime permanece não verificado. |

## Riscos de método e claims não verificáveis

- Após `read`, `vuln` chama `printf("...%s", buf)` antes de `leave; ret`; a leitura não adiciona terminador NUL. Uma entrada longa pode causar leitura além do buffer, vazamento ou falha antes do retorno. Uma leitura curta também não garante sobrescrita do RIP: são necessários ao menos 73 bytes para atingir seu primeiro byte e 80 para controlar os oito bytes completos.
- A entrada em `win` por `ret`, em vez de `call`, muda o alinhamento de `rsp` esperado pela ABI x86-64 na chamada interna a `puts`. A necessidade de ajuste de alinhamento e o êxito do ret2win não foram verificados sob o contrato atual.
- O binário comprova a flag como string embutida e seu uso por `puts`, mas não comprova que a execução alcance `win` nem que a flag seja observada em runtime. A opção exata usada no link também não é verificável apenas com `checksec`/`readelf`.

## Reprodução estática

Comandos usados: `sha256sum target/vault`; `file target/vault`; `checksec --file=target/vault`; `readelf -W -h -l -s target/vault`; `readelf -d target/vault`; `readelf -p .rodata target/vault`; `objdump -d -M intel target/vault`. `objdump` e `readelf`: GNU Binutils 2.47. Evidências comparadas com `~/.local/share/mitr3-nexus/workspaces/nexus_vault/evidence_v2.json`. Os comandos de leitura foram executados contra o alvo local sem modificá-lo.

**Veredito final: BLOQUEADO.** Corrigir EV-0001 para “`PT_GNU_STACK` presente e RWE”, retirar a afirmação não comprovada sobre a opção exata de link, e manter EV-0002/EV-0003 qualificadas como verificações estáticas. `UNK-0001` continua aberto até haver autorização específica para validação dinâmica; esta QA não solicita nem executa essa validação.
