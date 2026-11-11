# MITR3 — Caderno de Evidências e Grafo de Estados (CTF TryHackMe)

## 1. Contexto Operacional
- **Origem:** Operador `dj` / Orquestração `VANTA`
- **Ambiente:** TryHackMe Lab via interface VPN `tun0` (`192.168.148.45/18`)
- **Alvo:** `MACHINE_IP` (aguardando provisionamento do IP da máquina pelo TryHackMe)
- **Credenciais Iniciais:** `ubuntu` / `tryhackme`
- **Guardiã do Grafo e Evidências:** MEI (Graph Ingestion / Normalizer / QA & Spec Enforcement)

---

## 2. Grafo Canônico de Estados

```
[0. PREPARATION]
       │
       ▼ (SSH Auth: ubuntu@MACHINE_IP)
[1. INITIAL_ACCESS_SSH]
       │
       ▼ (uname, os-release, pkgs, CVE check)
[2. VERSION_CVE_RECON]
       │
       ▼ (sudo -l, SUID, caps, crons, ss -tulpn)
[3. SURFACE_IDENTIFICATION]
       │
       ▼ (locate user.txt, read, sha256)
[4. USER_FLAG]
       │
       ▼ (execute privesc vector -> uid 0)
[5. PRIVILEGE_ESCALATION]
       │
       ▼ (locate root.txt, read, sha256)
[6. ROOT_FLAG]
```

---

## 3. Estrutura de Diretórios de Evidência

| Diretório | Finalidade |
|:---|:---|
| `01-initial-access/` | Banners SSH, logs de conexão, `whoami`, `id`, `uname`, `ip a` iniciais |
| `02-recon/` | Versões de SO/Kernel, lista de pacotes (`dpkg -l`), serviços em execução |
| `03-surface/` | Saídas de `sudo -l`, busca SUID/SGID, capabilities, crontabs, conexões locais |
| `04-user-flag/` | Comprovante de leitura de `user.txt`, metadados de arquivo e hash SHA256 |
| `05-priv-esc/` | Evidência da execução do vetor de escalação, shell root e validação `id` |
| `06-root-flag/` | Comprovante de leitura de `root.txt`, metadados de arquivo e hash SHA256 |

---

## 4. Governança e Integridade Referencial
1. Toda evidência coletada deve ser registrada em `ledger.json` com `evidence_id`, timestamp UTC, `source_tool`, `claim`, `raw_artifact` e `evidence_sha256`.
2. A transição de estado no `state_graph.json` exige integridade referencial: nenhum estado é marcado como `ACHIEVED` sem evidência correspondente validada em disco.
