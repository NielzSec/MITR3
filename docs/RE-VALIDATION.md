# MITR3 Reverse Engineering Toolchain Validation

**Execution Date:** 2026-10-19  
**Target Tested:** `/bin/ls` (`/usr/bin/ls`, x86_64 ELF) & system JAR (`/usr/lib/jvm/java-27-openjdk/demo/jfc/Notepad/Notepad.jar`)  
**Operator:** VANTA ([V])

---

## Validation Summary Table

| Tool | Version | Test | Result | Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **Ghidra Headless** (`analyzeHeadless`) | 12.1.2 (OpenJDK 27) | Create project in `/tmp/re-vanta`, import `/bin/ls` with `-noanalysis` | **SUCCESS** (`REPORT: Import succeeded`, `Save succeeded for: /ls (test_proj:/ls)`) | JVM startup latency (~8s); external library stubs unresolved on raw import without pre-configured search project |
| **radare2** (`r2`) | 6.2.2 +37485 abi:142 | `iI` metadata extraction + `afl` count on `/bin/ls` | **SUCCESS** (`iI`: x86_64 ELF, NX/PIE/RELRO/Canary true; `afl`: 0 raw, 7 with `aa`, 159 with `aaa`) | Stripped binaries return 0 functions on raw `afl` without prior analysis pass (`aa`/`aaa`); relocations unapplied without `-e bin.relocs.apply=true` |
| **JADX** (`jadx`) | 1.5.6 | Search `/home/nielz/Documents` (maxdepth 5) for `.apk`/`.jar`; fallback to decompile system jar `/usr/lib/jvm/java-27-openjdk/demo/jfc/Notepad/Notepad.jar` with `--no-res` | **SUCCESS** (0 APK/JAR in Documents; successfully decompiled 2/2 classes in Notepad.jar: `Notepad.java`, `ElementTreePanel.java`) | Documents folder contained no APK targets; resource extraction bypassed (`--no-res`) for standalone class decompile |
| **rizin** (`rz-bin`) | 0.8.2 | `rz-bin -I /bin/ls` | **SUCCESS** (Parsed ELF64, GCC 16.2.1, canary: true, NX: true, PIE: true, relro: full) | `rz-bin` provides binary header/metadata inspection; control-flow analysis requires full `rizin` session |
| **REA MCP** | Provider: Ghidra 12.1.2 | `open_binary` on `/bin/ls`, then `procedure_pseudo_code` on procedure `0x105620` (`entry`) | **SUCCESS** (Binary opened with SHA256 `29abfee0...`; decompiled `entry` into C pseudocode invoking `__libc_start_main`) | Ephemeral session state; queries block until backend initial auto-analysis completes; decompiler output is Ghidra pseudocode rather than raw source |

---

## Detailed Execution Logs

### 1. Ghidra Headless
- **Command:** `/opt/ghidra/support/analyzeHeadless /tmp/re-vanta test_proj -import /bin/ls -noanalysis`
- **Output:**
  - `INFO Creating project: /tmp/re-vanta/test_proj (HeadlessAnalyzer)`
  - `INFO IMPORTING: file:///usr/bin/ls (HeadlessAnalyzer)`
  - `INFO Using Loader: Executable and Linking Format (ELF) (ProgramLoader)`
  - `INFO /ls: file created (nielz) (LocalFileSystem)`
  - `INFO REPORT: Save succeeded for: /ls (test_proj:/ls) (HeadlessAnalyzer)`
  - `INFO REPORT: Import succeeded (HeadlessAnalyzer)`
- **Artifacts:** `/tmp/re-vanta/test_proj.gpr`, `/tmp/re-vanta/test_proj.rep`

### 2. radare2 (`r2`)
- **Command:** `r2 -q -c "iI; afl" /bin/ls` & `r2 -q -c "aaa; afl" /bin/ls`
- **Header info (`iI`):**
  - Architecture: `x86`, 64-bit, little-endian ELF
  - Hardening: `canary: true`, `nx: true`, `pic: true`, `relro: full`
  - Stripped: `true`
- **Function count (`afl`):**
  - Unanalyzed: 0 functions
  - Fast analysis (`aa`): 7 functions
  - Deep analysis (`aaa`): 159 functions

### 3. JADX (`jadx`)
- **Discovery in `/home/nielz/Documents`:** 0 APK/JAR files found up to depth 5.
- **Decompiled Target:** `/usr/lib/jvm/java-27-openjdk/demo/jfc/Notepad/Notepad.jar`
- **Command:** `jadx -d /tmp/jadx-test --no-res /usr/lib/jvm/java-27-openjdk/demo/jfc/Notepad/Notepad.jar`
- **Output:**
  - `INFO - done` (2 of 2 classes decompiled)
  - `/tmp/jadx-test/sources/defpackage/Notepad.java`
  - `/tmp/jadx-test/sources/defpackage/ElementTreePanel.java`

### 4. rizin (`rz-bin`)
- **Command:** `rz-bin -I /bin/ls`
- **Output:**
  - `arch: x86`, `bits: 64`, `class: ELF64`
  - `compiler: GCC: (GNU) 16.2.1 20260810`
  - `canary: true`, `NX: true`, `PIE: true`, `relro: full`

### 5. REA MCP (`open_binary` + `procedure_pseudo_code`)
- **Session:** Target `/usr/bin/ls` (SHA256: `29abfee0d588cfbee70103be11aa0a2f81b0d8c1292341e2345fc9f3ffa1558b`)
- **Procedure:** `0x105620` (`entry`)
- **Decompiled Pseudocode:**
  ```c
  void processEntry entry(undefined8 param_1,undefined8 param_2)
  {
    undefined1 auStack_8 [8];
    
    __libc_start_main(FUN_00103580,param_2,&stack0x00000008,0,0,param_1,auStack_8);
    do {
                      /* WARNING: Do nothing block with infinite loop */
    } while( true );
  }
  ```
