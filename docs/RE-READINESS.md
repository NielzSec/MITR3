# MITR3 RE Lane Readiness Pass

**Data de Execução:** 2026-10-19  
**Fixture:** `~/MITR3/engagements/nexus_vault/target/vault` (ELF 64-bit LSB executable, x86-64)  
**Validador:** VANTA ([V])  

---

## Tabela de Prontidão

| Ferramenta | Comando | Resultado | Veredito |
| :--- | :--- | :--- | :--- |
| **rizin** | `rizin -qc "aaa; afl" ~/MITR3/engagements/nexus_vault/target/vault` | Análise completa de funções do vault; símbolos `sym.win` (0x401176), `sym.vuln` (0x40118c), `main` (0x4011ea) mapeados com sucesso. | **vivo** |
| **Ghidra Dump** | `~/MITR3/bin/ghidra-dump.sh ~/MITR3/engagements/nexus_vault/target/vault /tmp/vault_ghidra_readiness.json true` | Export headless PyGhidra executado com sucesso; 14 function dossiers extraídos em JSON estruturado (~76 KB). | **vivo** |
| **ropper** | `ropper --file ~/MITR3/engagements/nexus_vault/target/vault --search 'pop rdi'` | Motor de gadgets ROP ativo; 123 gadgets indexados no vault; busca por `pop rdi` executada com sucesso (0 matches, fixture ret2win). | **vivo** |
| **checksec** | `checksec --file ~/MITR3/engagements/nexus_vault/target/vault` | Mitigações auditadas: Partial RELRO, No canary, Executable stack / NX missing, No PIE (0x400000), RWX segments presentes, Não-stripped. | **vivo** |
| **frida** | `frida --version && frida-ls-devices` | Frida 17.24.3 operacional; enumeração de devices lista `local` (Arch Linux), `barebone` (GDB Remote Stub) e `socket`. | **vivo** |
| **jadx** | `jadx --version` | JADX 1.5.6 operacional para descompilação DEX/APK/JAR. | **vivo** |
| **apktool** | `apktool --version` | Apktool 3.0.3 operacional para decodificação e rebuild de recursos Android. | **vivo** |
| **gdb** | `gdb --version && gdb -batch -ex 'break main' -ex 'run' ~/MITR3/engagements/nexus_vault/target/vault` | GNU GDB 18.1 operacional; breakpoint 1 setado em `main` (0x4011ea), processo iniciado e interceptado na instrução de entrada. | **vivo** |
| **upx** | `cp /bin/true /tmp/opencode/true && upx -9 /tmp/opencode/true && upx -d /tmp/opencode/true` | UPX 5.2.0 operacional; compressão (43320 -> 20180 bytes, 46.58%) e descompressão preservaram hash SHA-256 (`8398af7d1f94a88be3303caa083616ad22a12783e4dfee0373298bc61aef0662`). | **vivo** |

---

## Logs de Execução

### 1. rizin (0.8.2 @ linux-x86-64)
```text
$ rizin -qc "aaa; afl" ~/MITR3/engagements/nexus_vault/target/vault
0x00401000    3 23           sym._init
0x00401030    1 6      -> 4 sym.imp.puts
0x00401040    1 6      -> 4 sym.imp.printf
0x00401050    1 6      -> 4 sym.imp.gets
0x00401060    1 6      -> 4 sym.imp.setvbuf
0x00401070    1 38           sym._start
0x004010a0    1 38           sym.deregister_tm_clones
0x004010d0    1 51           sym.register_tm_clones
0x00401110    1 34           sym.__do_global_dtors_aux
0x00401140    1 44           sym.frame_dummy
0x00401176    1 22           sym.win
0x0040118c    1 90           sym.vuln
0x004011ea    1 73           main
0x00401240    1 13           sym._fini
```

### 2. ghidra-dump.sh (PyGhidra + Ghidra 12.1.2)
```text
$ ~/MITR3/bin/ghidra-dump.sh ~/MITR3/engagements/nexus_vault/target/vault /tmp/vault_ghidra_readiness.json true
[ghidra-dump] target: /home/nielz/MITR3/engagements/nexus_vault/target/vault
[ghidra-dump] out:    /tmp/vault_ghidra_readiness.json
[ghidra-dump] ok | vault x86:LE:64:default | 14 functions | 76174 bytes
```

### 3. ropper (2.0.8)
```text
$ ropper --file ~/MITR3/engagements/nexus_vault/target/vault --search 'pop rdi'
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[INFO] Load gadgets for section: GNU_STACK
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi
```

### 4. checksec (2.7.1)
```text
$ checksec --file ~/MITR3/engagements/nexus_vault/target/vault
[*] '/home/nielz/MITR3/engagements/nexus_vault/target/vault'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### 5. frida (17.24.3)
```text
$ frida --version && frida-ls-devices
17.24.3
Id      Type    Name         OS
------  ------  -----------  ----------
local   local   Local System Arch Linux
barebone remote GDB Remote Stub
socket  remote  Local Socket
```

### 6. jadx (1.5.6)
```text
$ jadx --version
1.5.6
```

### 7. apktool (3.0.3)
```text
$ apktool --version
3.0.3
```

### 8. gdb (18.1)
```text
$ gdb --version | head -n 1
GNU gdb (GDB) 18.1
$ gdb -batch -ex 'break main' -ex 'run' ~/MITR3/engagements/nexus_vault/target/vault
Breakpoint 1 at 0x4011ea
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x00000000004011ea in main ()
```

### 9. upx (5.2.0)
```text
$ cp /bin/true /tmp/opencode/true
$ sha256sum /tmp/opencode/true
8398af7d1f94a88be3303caa083616ad22a12783e4dfee0373298bc61aef0662  /tmp/opencode/true
$ upx -9 /tmp/opencode/true
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     43320 ->     20180   46.58%   linux/amd64   true
$ upx -d /tmp/opencode/true
     43320 <-     20180   46.58%   linux/amd64   true
$ sha256sum /tmp/opencode/true
8398af7d1f94a88be3303caa083616ad22a12783e4dfee0373298bc61aef0662  /tmp/opencode/true
```

---

## § A2-01 (2026-10-19) — Capability Proof (Ghidra Headless Native)

**Escopo:** Prova de capacidade da lane RE (127.0.0.1 / lab local).  
**Alvo:** Amostra C sintética com call-graph de 2 funções (`main` -> `target_calc`).  
**Artefatos:**
- Amostra C fonte: `/tmp/opencode/a2-01-sample/sample.c`
- Binário compilado: `/tmp/opencode/a2-01-sample/sample`
- Log de execução headless: `~/MITR3/reviews/re-lane/a2-01-headless.log`
- Projeto Ghidra retido: `/tmp/opencode/a2-01-ghidra/proj/a2_01_proj.gpr` e `a2_01_proj.rep/`

### Hashes SHA-256
- **Amostra (`sample`):** `b5f98cab5b5fa98512219d66f2af4362c6a02dccd9d060ac3d218a6a29026cb9`
- **Log headless (`a2-01-headless.log`):** `2a7aeed41c1aaa5ac3b9a2813dfe6ec20fc5f46f9596ce9cdefbba1cd2ddef96`

### Timing de Execução
- **Tempo total:** 7.258 s (7258 ms) incluindo inicialização da JVM, importação ELF64, análise completa do descompilador e execução do postScript.

### Comandos Executados

```bash
# 1. Compilação da amostra C
gcc -O0 -no-pie -fno-stack-protector -o /tmp/opencode/a2-01-sample/sample /tmp/opencode/a2-01-sample/sample.c

# 2. Execução Headless com script nativo de iteração de funções
/home/nielz/Tools/ghidra/support/analyzeHeadless /tmp/opencode/a2-01-ghidra/proj a2_01_proj \
  -import /tmp/opencode/a2-01-sample/sample \
  -postScript IterateFunctionsByAddressScript.java true \
  -overwrite > ~/MITR3/reviews/re-lane/a2-01-headless.log 2>&1
```

### Validação do Call Graph e Funções
O log confirmou análise bem-sucedida e listagem exata das funções alvo:
- `target_calc @ 00401136`
- `main @ 0040114a`
- Total: 18 funções identificadas (incluindo stubs de runtime e inicialização).
