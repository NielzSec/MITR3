# MITR3 — Playbook Técnico: Pipeline REA MCP para Engenharia Reversa e Análise de Binários

**Documento:** `docs/REA-MCP-PIPELINE-PLAYBOOK.md`  
**Versão:** 1.0.0  
**Emissor:** MITR3 Security & Intelligence Squad (Custódia: VANTA)  
**Destino:** Equipe Técnica MITR3 / Relatórios de Engenharia Reversa de Binários Nativos  
**Data:** 11 de Novembro de 2026  
**Classificação:** Confidencial / Operacional Interno  

---

## 1. Visão Geral & Posicionamento de Serviço

O site institucional **MITR3** (`https://mitr3-web.zgordola1.workers.dev`) anuncia ao mercado serviços de segurança ofensiva com ênfase no princípio: **"O risco existe. A evidência decide."**

No domínio de **Engenharia Reversa e Análise de Binários Nativos**, a esteira MITR3 emprega o **REA MCP (Reverse Engineering Assistant Model Context Protocol)** integrado a backends de análise estática e dinâmica de grau militar (**PyGhidra / Ghidra 12.1.2 Headless**, **radare2 6.2.2**, **rizin 0.8.2**, **GDB 18.1** e **Frida 17.24.3**).

Este playbook padroniza o fluxo analítico ponta a ponta — desde a ingestão do artefato até a emissão do dossier técnico com evidências criptograficamente verificadas para inclusão nos relatórios entregues a clientes corporativos.

```
+-----------------------------------------------------------------------------------+
|                           PIPELINE REA MCP — MITR3                                |
+-----------------------------------------------------------------------------------+
|  1. INGESTÃO & CUSTÓDIA       -> SHA-256, File Magic, checksec, Mitigações        |
|  2. CARREGAMENTO REA MCP      -> open_binary, binary_overview, layout             |
|  3. DESCOMPILAÇÃO CIRÚRGICA   -> list_procedures, procedure_pseudo_code, batch    |
|  4. ANÁLISE DE CROSS-REFS     -> xrefs, callers, callees, call graph, strings     |
|  5. AUDITORIA DE MEMÓRIA      -> Overflows, Integer, Format String, UAF, Bounds   |
|  6. CORRELAÇÃO DE IMPACTO     -> Verificação sob mitigações de runtime (ASLR/DEP) |
|  7. DOSSIER & RELATÓRIO       -> Formato padrão de entrega para cliente TI/Dev    |
+-----------------------------------------------------------------------------------+
```

---

## 2. Ingestão, Identificação & Cadeia de Custódia

Toda análise de engenharia reversa sob contrato MITR3 inicia com a fixação imutável da identidade do binário sob auditoria.

### 2.1 Coleta de Metadados Criptográficos e de Compilação
Antes de qualquer submissão ao REA MCP, o operador deve extrair e registrar os metadados brutos:

```bash
# 1. Hashing e Caracterização Básica
sha256sum <TARGET_BINARY> | tee <TARGET_BINARY>.sha256
file <TARGET_BINARY>
readelf -h <TARGET_BINARY> | grep -E "Class|Data|Type|Machine|Entry"
```

### 2.2 Auditoria de Mitigações de Runtime (`checksec`)
O perfil de exploração e severidade de vulnerabilidades de memória é diretamente governado pelas proteções ativas no executável e nas bibliotecas compartilhadas:

```bash
checksec --file=<TARGET_BINARY> --extended
```

Matriz de auditoria de mitigações requerida no relatório:
| Mitigação | Status Auditado | Impacto Técnico no Achado |
| :--- | :--- | :--- |
| **RELRO** | `No` / `Partial` / `Full` | Define se a GOT (Global Offset Table) é passível de sobrescrita. |
| **Stack Canary** | `No canary` / `Canary found` | Determina se stack buffer overflows resultam em hijack direto ou abort imediato (`__stack_chk_fail`). |
| **NX / DEP** | `NX enabled` / `NX disabled` | Define se injeção direta de shellcode em pilha/heap é executável ou se exige ROP (Return-Oriented Programming). |
| **PIE / ASLR** | `No PIE` / `PIE enabled` | Fixa endereços estáticos ou impõe necessidade de information leak para bypass de bases dinâmicas. |
| **Fortify Source** | `Yes` / `No` | Verifica wrappers de runtime da glibc para funções com buffer bound conhecido (`__memcpy_chk`). |
| **Stripped** | `Stripped` / `Not stripped` | Indica presença ou ausência da tabela de símbolos ELF/PE (`.symtab`). |

---

## 3. Sessão & Inicialização no REA MCP

O REA MCP fornece a interface semântica estruturada entre o agente analista e o disassembler/decompiler backend (Ghidra headless / Rizin).

### 3.1 Inicialização de Sessão
Para carregar o binário na memória do servidor REA:

```json
// Tool: open_binary
{
  "path": "/absolute/path/to/target_binary"
}
```
*Saída esperada:* Confirmação de abertura de sessão, arquitetura reconhecida, endianness, base address inicial (ex: `0x00400000` para non-PIE ou base 0 para PIE) e ID de sessão persistente.

### 3.2 Visão Estrutural da Imagem
```json
// Tool: binary_overview
{}

// Tool: inspect_binary_layout
{}
```
*Objetivo:* Mapear seções (`.text`, `.rodata`, `.data`, `.bss`, `.got.plt`, `.init_array`), permissões de memória (RX, RW, RWX) e pontos de entrada (`entry`, `_start`, `main`).

---

## 4. Descompilação Cirúrgica & Dossiers de Procedimentos

A descompilação não deve ser executada às cegas sobre toda a base quando se busca precisão cirúrgica em relatórios corporativos. O processo foca nas fronteiras de entrada de dados externos.

### 4.1 Mapeamento e Enumeração de Funções
```json
// Listagem dos procedimentos identificados pelo backend
// Tool: list_procedures
{
  "limit": 100,
  "offset": 0
}

// Busca por procedimentos de parsing, autenticação, rede ou criptografia
// Tool: search_procedures
{
  "query": "parse"
}
```

### 4.2 Extração de Pseudocódigo e Assembly Pareado
Ao localizar um procedimento suspeito ou crítico, extrai-se o pseudocódigo C de alto nível e, simultaneamente, o assembly correspondente para validar a semântica real emitida pelo compilador:

```json
// Descompilação C de alto nível
// Tool: procedure_pseudo_code
{
  "address": "0x0040118c"
}

// Inspeção das instruções nativas para auditoria de alinhamento de stack e offsets
// Tool: procedure_assembly
{
  "address": "0x0040118c"
}
```

### 4.3 Anotação e Normalização de Contexto
Para manter o relatório legível e auditável:
```json
// Renomear procedimentos não resolvidos em binários stripped
// Tool: set_address_name
{
  "address": "0x00401250",
  "name": "parse_packet_header"
}

// Inserir comentário explicativo no seam da vulnerabilidade
// Tool: set_inline_comment
{
  "address": "0x00401274",
  "comment": "[MITR3-VULN] Chamada sem limite de tamanho no buffer de destino"
}
```

---

## 5. Mapeamento de Cross-References (XREFs) & Grafo de Chamadas

A avaliação de risco exige comprovar a **atingibilidade (reachability)** da função vulnerável a partir dos pontos de entrada públicos ou interfaces acessíveis do binário.

### 5.1 Rastreamento de Chamadas (Call Chain)
Para demonstrar se uma função contendo código inseguro pode ser disparada por um usuário não privilegiado:

```json
// Quem chama a função vulnerável? (Callers)
// Tool: procedure_callers
{
  "address": "0x0040118c"
}

// Para onde a função vulnerável desvia o fluxo? (Callees)
// Tool: procedure_callees
{
  "address": "0x0040118c"
}

// Grafo completo de chamadas
// Tool: get_call_graph
{
  "root_address": "0x004011ea",
  "depth": 3
}
```

### 5.2 Cross-References de Dados e Strings (Data XREFs)
Strings hardcoded frequentemente revelam caminhos de arquivos de configuração, credenciais de teste, formatos de serialização e chaves criptográficas:

```json
// Localizar strings sensíveis
// Tool: search_strings
{
  "query": "password"
}

// Localizar referências de código (XREFs) que lêem a string encontrada
// Tool: xrefs
{
  "address": "0x00403010"
}
```

---

## 6. Auditoria de Vulnerabilidades de Memória

A taxonomia de vulnerabilidades nativas auditada pelo pipeline REA MCP cobre as classes críticas de corrupção de memória.

### 6.1 Stack Buffer Overflows (CWE-121)
* **Padrão de Falha:** Alocação estática na pilha (`char buffer[64];`) alimentada por funções sem verificação de comprimento (`gets()`, `strcpy()`, `sprintf()`, `scanf("%s")`, ou `read()` com tamanho superior ao buffer).
* **Inspeção REA:**
  1. Extrair assembly via `procedure_assembly` e inspecionar o prólogo da função (`sub rsp, 0x48`).
  2. Localizar o offset do buffer em relação ao Frame Pointer (`rbp`) ou Saved Return Address (`rbp + 8`).
  3. Checar ausência do stack canary (`fs:0x28` em x86_64).
* **Evidência no Dossier:**
  - Código C descompilado destacando o destino e a fonte descontrolada.
  - Cálculo exato de bytes necessários para atingir o ponteiro de instrução salvo (RIP).

### 6.2 Heap Out-of-Bounds Write / Buffer Overflows (CWE-122)
* **Padrão de Falha:** Alocação de buffer dinâmico (`malloc(size)`) seguida por escrita baseada em tamanho fornecido pelo usuário ou cálculo incorreto de delimitador (`memcpy(dest, src, user_len)`).
* **Inspeção REA:**
  1. Identificar XREFs para alocadores padrão (`malloc`, `calloc`, `realloc`).
  2. Rastrear os registradores que alimentam o argumento de tamanho (`rdi` / `esi`).
  3. Verificar se há sanitização de limite superior antes da chamada de cópia.

### 6.3 Integer Overflows e Truncation (CWE-190 / CWE-197)
* **Padrão de Falha:** Operações aritméticas antes de alocações de memória que sofrem wrap-around (ex: `unsigned short count; size = count * sizeof(element); malloc(size);`).
* **Inspeção REA:**
  1. Verificar conversão entre tipos com sinal e sem sinal (`movsxd`, `movzx`).
  2. Verificar instruções de multiplicação (`imul`, `mul`) sem checagem de carry/overflow flag (`jo`, `jc`).
  3. Demonstrar como um inteiro alto resulta em alocação diminuta e subsequente cópia excessiva.

### 6.4 Format String Vulnerabilities (CWE-134)
* **Padrão de Falha:** Uso direto de buffer controlado pelo usuário como primeiro argumento de format string (`printf(user_buf);` em vez de `printf("%s", user_buf);`).
* **Inspeção REA:**
  1. Pesquisar XREFs para `printf`, `sprintf`, `snprintf`, `syslog`, `fprintf`.
  2. Verificar se o registrador do argumento de formato aponta diretamente para o buffer de entrada.

### 6.5 Use-After-Free (UAF) & Double-Free (CWE-416 / CWE-415)
* **Padrão de Falha:** Liberação de ponteiro (`free(ptr)`) sem anulação (`ptr = NULL;`), seguido de reutilização em outra rotina ou nova liberação do mesmo ponteiro.
* **Inspeção REA:**
  1. Mapear todas as chamadas `free()` e cruzar com o grafo de controle da estrutura de dados.
  2. Localizar acessos de leitura/escrita a membros do objeto após a chamada de desalocação.

### 6.6 Off-by-One Errors (CWE-193)
* **Padrão de Falha:** Loops com condição `<=` em vez de `<`, resultando na sobrescrita de um único byte (geralmente o Least Significant Byte do saved frame pointer).

---

## 7. Formato Padrão de Ficha Técnica de Achado (Finding Dossier)

Todo apontamento em relatórios técnicos de engenharia reversa do MITR3 deve seguir a estrutura rigorosa abaixo:

```markdown
### [MITR3-RE-FINDING-001] Stack Buffer Overflow Não Protegido em `parse_network_frame`

**Classificação:** Crítica (CVSS 3.1: 8.8 - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**CWE:** CWE-121 (Stack-based Buffer Overflow)  
**Alvo Auditado:** `libnet_parser.so` (SHA-256: `a93b2f...`)  
**Endereço Virtual:** `0x00014280` (Offset de arquivo: `0x00004280`)  
**Símbolo / Função:** `parse_network_frame`  

#### 1. Contexto & Descrição do Mecanismo
Durante a análise estática avançada com REA MCP e Ghidra Decompiler, identificou-se que a função `parse_network_frame` aloca um buffer estático na pilha de 128 bytes (`auStack_98 [128]`) e invoca uma rotina de leitura de dados sem validação prévia de comprimento contra o cabeçalho do pacote recebido.

#### 2. Evidência em Pseudocódigo Descompilado (REA MCP)
```c
/* REA Decompiler Output @ 0x00014280 */
int parse_network_frame(char *socket_data, int incoming_len)
{
    char stack_buf[128]; /* auStack_98 @ rbp-0x80 */
    
    if (socket_data == NULL) {
        return -1;
    }
    
    /* VULNERABILIDADE: incoming_len controlado externamente sem validação contra sizeof(stack_buf) */
    memcpy(stack_buf, socket_data, incoming_len);
    
    return process_payload(stack_buf);
}
```

#### 3. Evidência em Instruções Nativas (Disassembly)
```text
0x00014280:  push   rbp
0x00014281:  mov    rbp, rsp
0x00014284:  sub    rsp, 0x90
0x0001428b:  mov    QWORD PTR [rbp-0x88], rdi   ; socket_data
0x00014292:  mov    DWORD PTR [rbp-0x8c], esi   ; incoming_len
0x00014298:  cmp    QWORD PTR [rbp-0x88], 0x0
0x000142a1:  je     0x000142ce
0x000142a3:  movsxd rdx, DWORD PTR [rbp-0x8c]   ; tamanho descontrolado passado para RDX (param 3)
0x000142aa:  mov    rsi, QWORD PTR [rbp-0x88]   ; origem em RSI (param 2)
0x000142b1:  lea    rax, [rbp-0x80]
0x000142b5:  mov    rdi, rax                    ; destino stack_buf em RDI (param 1)
0x000142b8:  call   0x00010340                  ; sym.imp.memcpy
```

#### 4. Grafo de Chamadas & Atingibilidade (Reachability)
- `main` (`0x00011050`) -> `listen_loop` (`0x00011500`) -> `dispatch_worker` (`0x00012210`) -> `parse_network_frame` (`0x00014280`).
- A rota não exige pré-autenticação, tornando o seam atingível a partir de pacotes de broadcast na rede local.

#### 5. Impacto sob as Mitigações Auditadas
- **Stack Canary:** Ausente (`No canary found`). A sobrescrita atinge diretamente o `Saved RBP` e `Saved RIP`.
- **NX/DEP:** Habilitado (`NX enabled`). Execução direta de shellcode em pilha é prevenida por hardware; entretanto, a ausência de PIE permite encadeamento de chamadas (ROP) para `mprotect` ou funções internas.
- **Risco Real:** Corrupção de memória que acarreta encerramento abrupto do serviço (Negação de Serviço) e desvio controlado do fluxo de execução.

#### 6. Recomendação de Correção e Remediação Cirúrgica
1. **Em Código-Fonte C/C++:** Substituir a cópia cega por validação explícita de limites e uso de funções seguras com bound fixo:
   ```c
   if (incoming_len <= 0 || incoming_len > sizeof(stack_buf)) {
       log_security_event("Payload length exceeds allocated buffer boundary");
       return -1;
   }
   memcpy(stack_buf, socket_data, incoming_len);
   ```
2. **Em Flags de Compilação:** Habilitar mitigações modernas no pipeline de CI/CD:
   ```bash
   CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now"
   ```
```

---

## 8. Runbook de Execução Rápida do Operador (Cheat Sheet)

```bash
# ==============================================================================
# SCRIPT DE TRIAGEM RÁPIDA PRÉ-REA (Ambiente Local Arch Linux / MITR3)
# ==============================================================================

# Passo 1: Metadados Criptográficos
TARGET="$1"
echo "[*] Alvo: $TARGET"
sha256sum "$TARGET" > "${TARGET}.sha256"

# Passo 2: Perfil de Mitigações
checksec --file="$TARGET" > "${TARGET}.checksec.txt"

# Passo 3: Rastreio Rápido de Símbolos e Funções Inseguras com Rizin
rizin -qc "aaa; afl | grep -E 'printf|strcpy|gets|memcpy|malloc|free|system'" "$TARGET" > "${TARGET}.vuln_symbols.txt"

# Passo 4: Sessão REA MCP
# Executar as chamadas REA via interface MCP no cliente autorizado:
# - open_binary(path=TARGET)
# - procedure_pseudo_code(address="0x...")
# - xrefs(address="0x...")
# - export_evidence_bundle(output_path="${TARGET}_evidence.json")
```

---

## 9. Governança e Regras de Segurança MITR3

1. **Apenas Binários Autorizados:** É expressamente vedada a análise de binários de terceiros sem autorização formal documentada no termo de serviço (`SCOPE.md`).
2. **Ambiente Isolado (Sandbox):** Qualquer análise dinâmica auxiliar (via GDB ou Frida) deve ser conduzida exclusivamente em containers ou máquinas virtuais isoladas de rede, sem risco de persistência ou telemetria não autorizada.
3. **Imutabilidade de Evidências:** Os artefatos descompilados, logs de sessões REA MCP e relatórios finais devem ter seus hashes SHA-256 arquivados e mantidos sob custódia de VANTA.

---
**Custódia:** VANTA ([V])  
**Equipe:** MITR3 Security & Intelligence Squad  
**Referência:** `docs/REA-MCP-PIPELINE-PLAYBOOK.md`