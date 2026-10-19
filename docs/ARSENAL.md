# MITR3 — ARSENAL (plano de ferramentas)

Data: 2026-10-19 · Autor: Hermes (deepseek) · Autorização: total (squad) · Uso: engajamentos autorizados / CTF / laboratório 127.0.0.1.
Base: inventário real do host (`command -v` varrido hoje). Itens MISS = prioridade de instalação ou integração.

## Estado atual (resumo do que já está no host)
Web/API: burp pro (burp.sh), nuclei, ffuf, katana, httpx, dnsx, subfinder, amass, gau, gobuster, nmap, masscan, sqlmap, saltstack local, semgrep, trivy, osv-scanner, codeql (security-extended), mitr3-scan.sh, api-sec MCP.
RE: ghidra (analyzeHeadless), pyghidra venv, radare2, rizin, jadx, apktool, frida, ropper, checksec via pwntools.
AD/Infra: impacket 0.13.1 (pacman), nxc (netexec), ldapdomaindump, hashcat, john, hydra, aircrack-ng, bettercap.
Outros: darkweb.sh + tor + onionsearch (Robin), SecLists 2.5G, docker (sudo NOPASSWD no host; indisponível neste sandbox).
Fase 1 Web/API: **8/9 CLIs com smoke local válido** em 2026-10-19 (`feroxbuster`, `wpscan`, `sslscan`, `testssl.sh`, `naabu`, `graphql-cop`, `gopherus`, `ysoserial`). InQL está presente como extensão JAR do Burp, com wrapper para localizar o arquivo, mas sem validação na interface. Todos os nove nomes respondem a `command -v`.

## Fase 1 — Web/API (nossa lane principal) — IMPLEMENTADA 2026-10-19 (Hermes, user-space + system pkg)
| ferramenta | status | versão | evidência |
|---|---|---|---|
| feroxbuster | ✅ instalado (~/.local/bin) | 2.13.1 | feroxbuster --version |
| naabu | ✅ instalado (~/go/bin) | 2.6.1 | naabu -version |
| sslscan | ✅ presente (system pkg) | 2.2.3-1 | sslscan --version |
| testssl.sh | ✅ instalado (~/Tools; symlink ~/.local/bin) | git head | testssl.sh --version |
| wpscan | ✅ instalado (system pkg) | 4.1.0 | wpscan --version |
| graphql-cop | ✅ instalado (~/Tools + venv próprio) | git head (doyensec) | graphql-cop -h (Usage OK) |
| inql | ⏳ como extensão Burp (não CLI) | — | a carregar na Burp lane (doyensec/inql) |
| gopherus | instalado (py3-portado) | upstream `90a2fd5` + patch local | base `~/Tools/gopherus`; 12 arquivos: py_compile zero; banner/ajuda/menu Redis: exit 0 |
| ysoserial | ✅ instalado (~/Tools/ysoserial-all.jar) | latest | java -jar ... --help |

Instalação deu em user-space (sem root). Pacotes system já existiam (sslscan/wpscan). Detalhe: feroxbuster via go install falhou (`incompatible` sem package) mas já havia binário em ~/.local/bin (2.13.1) funcionando; naabu via go install okay (2.6.1); graphql-cop precisou de venv próprio (o venv do hermes não tinha pip) com requests/simplejson/termcolor.
- feroxbuster — enumeração de diretórios em paralelo (alternativa mais rápida ao ffuf para discovery bulk)
- wpscan — wordpress específico (muito comum em bounty)
- sslscan + testssl.sh (sslyze opcional) — auditoria TLS/pinning
- naabu — syn scan rápido (projectdiscovery, casa com o resto da família)
- graphql-cop + inql — testes de GraphQL (schema introspection, batching abuse)
- gopherus — SSRF → protocol smuggling auxiliar; base `~/Tools/gopherus`, wrapper Python 3
- ysoserial — gadget chains p/ desserialização Java em campos de teste autorizado

### Execução e validação local — 2026-10-19

Os artefatos apareceram no host após a primeira checagem desta sessão. Os pacotes
Arch foram confirmados por `pacman -Q`; os demais ficam em `~/Tools`, com comandos
em `~/.local/bin`. A checagem abaixo foi refeita sobre os arquivos presentes.
O sandbox recusa `socket()` (`EPERM`) mesmo para `python3 -m http.server --bind
127.0.0.1`; por isso nenhum scan de rede pôde ser validado aqui. Nenhum host
externo foi alvo de scan. A origem dos clones foi verificada por `git remote`;
o teste de checksum contra releases upstream ainda não foi concluído para os
binários e JARs avulsos.

| Ferramenta | Fonte e método previsto | Status | Versão | Evidência local |
|---|---|---|---|---|
| feroxbuster | [epi052/feroxbuster](https://github.com/epi052/feroxbuster), binário em `~/Tools` | instalado | 2.13.1 | `command -v` → `~/.local/bin/feroxbuster`; `feroxbuster --version` → `feroxbuster 2.13.1` |
| wpscan | Arch `extra`, [upstream](https://github.com/wpscanteam/wpscan) | instalado | 4.1.0 | `pacman -Q wpscan` → `1:4.1.0-1`; `command -v` → `/usr/bin/wpscan`; `wpscan --version` → `Current Version: 4.1.0` |
| sslscan | Arch `extra`, [upstream](https://github.com/rbsec/sslscan) | instalado | 2.2.3 | `pacman -Q sslscan` → `2.2.3-1`; `command -v` → `/usr/bin/sslscan`; `sslscan --version` → `2.2.3` |
| testssl.sh | [testssl/testssl.sh](https://github.com/testssl/testssl.sh), clone em `~/Tools` | instalado | 3.3dev (`9bd7e16`) | `command -v` → `~/.local/bin/testssl.sh`; `testssl.sh --version` → `3.3dev`; remote Git oficial |
| naabu | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu), binário em `~/Tools` | instalado, scan pendente | 2.6.1 | `command -v` → `~/.local/bin/naabu`; `naabu -version` → `Current Version: 2.6.1`, junto de `could not initialize router: operation not permitted` |
| graphql-cop | [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop), clone em `~/Tools` | instalado | 1.15 | `command -v` → `~/.local/bin/graphql-cop`; `graphql-cop --help` → Usage; `version.py` → `1.15`; remote Git oficial |
| inql | [doyensec/inql](https://github.com/doyensec/inql), JAR em `~/Tools/inql` | JAR presente, Burp pendente | 6.1.2 no upstream; JAR sem metadata | `command -v` → `~/.local/bin/inql`; `inql --jar` aponta JAR; `jar tf` contém `burp/BurpExtender.class`; ainda não carregado no Burp |
| gopherus | [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus), base nova `~/Tools/gopherus` | instalado (py3-portado) | upstream `90a2fd5` + patch local (sem semver) | `command -v` → `~/.local/bin/gopherus`; 12 arquivos: py_compile zero; banner + ajuda + menu Redis: exit 0, stderr vazio; patch/evidência em `docs/TOOLING-HANDOFF-GOPHERUS.md` |
| ysoserial | [frohoff/ysoserial](https://github.com/frohoff/ysoserial), JAR em `~/Tools` | instalado | v0.0.6 | `command -v` → `~/.local/bin/ysoserial`; `ysoserial --version` lê `pom.properties` → `v0.0.6`; `java -jar` lista payloads |

Para fechar a fase, carregar o JAR do InQL no Burp e confirmar a extensão ativa;
executar os scans de loopback em sessão que permita `socket()`. O Gopherus oficial
exige Python 2; o wrapper agora usa exclusivamente a base nova `~/Tools/gopherus`.
O fechamento deste handoff valida compilação, banner, ajuda e entrada no menu Redis;
os modos de geração completos e a equivalência byte a byte com Python 2 permanecem
fora dessa validação. A evidência anterior da cópia alternativa não valida esta base.
O wrapper `inql` localiza o JAR, mas não converte a extensão em CLI. Para WPScan,
o token da API, quando necessário, deve vir de `WPSCAN_API_TOKEN` no ambiente
local, sem valor no repositório.

## Fase 2 — AD / Windows (suporte a engajamentos na rede)

Integração de código em `bin/mitr3-arsenal.py`, `bin/mitr3-arsenal.sh`,
`bin/mitr3-ad.sh` e `bin/mitr3-cloud.sh`. Instalação real tentada em 2026-10-19:
Impacket 0.13.1 validado; as outras 11 ferramentas das Fases 2/3 seguem ausentes.
Este sandbox ainda retorna `no new privileges` em `sudo -n true` e falha de DNS
para GitHub, PyPI, proxy Go e downloads Google. O NOPASSWD configurado no host
não altera essas restrições do processo sandbox. A tabela automatizada abaixo
registra o estado individual e os caminhos dos logs.

```bash
~/MITR3/bin/mitr3-arsenal.sh install all --update-docs
~/MITR3/bin/mitr3-arsenal.sh check all --json
~/MITR3/bin/mitr3-ad.sh impacket -h
~/MITR3/bin/mitr3-cloud.sh aws --version
```

O instalador prefere pacman oficial; Python usa venv próprio em
`~/Tools/<nome>/.venv` (nunca Hermes), Go usa `~/Tools/<nome>/bin` e gcloud usa
o arquivo oficial do Google. `MITR3_PYTHON` permite selecionar o interpretador
ao criar novos venvs. Nenhum login ou scan faz parte da instalação/checagem.
O health agora inclui os novos comandos na matriz de presença. Procedimento e
opções de retomada no RUNBOOK, seção Arsenal.

- impacket (python) — secretsdump, wmiexec, psexec, GetNPUsers, ntlmrelayx... (coluna central p/ pentest AD)
- bloodhound-python + BloodHound CE (docker) — mapeamento de caminhos de ataque AD
- kerbrute — brute/enum de contas via Kerberos (sem lockout) 
- responder — LLMNR/NBT-NS poisoning em redes autorizadas
- mimikatz não disponível nativamente no Linux — route via impacket (sam/hashdump) ou copia do binário no Windows alvo; documentar quarentena.
- Rubeus/SharpHound/RunPE — coletados no Windows alvo (não "instalar" no Linux; script de aquisição)

## Fase 3 — Cloud (não há nada no host hoje — gap real)
- aws cli + gcloud + az cli — credenciais nos cofres por engajamento
- prowler — auditoria multi-cloud (default alto valor)
- scoutsuite — inventário/config por nuvem
- cloudfox — enumeração de trust/roles a partir do lado atacante
- pacu — framework de exploração AWS (autorizado)
- trufflehog — vazamento de segredos em repos/CI/cloud

<!-- MITR3_PHASE23_STATUS_START -->
### Validação automatizada das Fases 2/3

Atualizado: 2026-10-19T18:49:58.679626+00:00. Comandos de versão/ajuda apenas; sem login ou coleta.

| Ferramenta | Fase | Status | Versão | Evidência |
|---|---|---|---|---|
| [impacket](https://github.com/fortra/impacket) | 2 | instalado/validado | 0.13.1 | `/home/nielz/.local/bin/impacket-smbclient`; /home/nielz/.local/bin/impacket-smbclient -h |
| [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) | 2 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/bloodhound-python.log` |
| [kerbrute](https://github.com/ropnop/kerbrute) | 2 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/kerbrute.log` |
| [responder](https://github.com/lgandx/Responder) | 2 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/responder.log` |
| [aws](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/aws.log` |
| [gcloud](https://docs.cloud.google.com/sdk/docs/install-sdk) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/gcloud.log` |
| [az](https://learn.microsoft.com/cli/azure/install-azure-cli-linux) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/az.log` |
| [prowler](https://github.com/prowler-cloud/prowler) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/prowler.log` |
| [scoutsuite](https://github.com/nccgroup/ScoutSuite) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/scoutsuite.log` |
| [cloudfox](https://github.com/BishopFox/cloudfox) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/cloudfox.log` |
| [pacu](https://github.com/RhinoSecurityLabs/pacu) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/pacu.log` |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | 3 | ausente; instalação bloqueada/falhou | — | command -v: ausente; log: `/home/nielz/MITR3/reports/arsenal-install-20261019T184954507595Z/trufflehog.log` |

Relatório detalhado: `reports/arsenal-phase23-latest.json`.
<!-- MITR3_PHASE23_STATUS_END -->

## Fase 4 — Mobile (apoio a app testing)
- mobsf (docker) — análise estática Android/iOS central
- objection — runtime mobile (SSL pinning bypass, frida auto)
- drozer — attack surface Android (intents, exported components)
- apk-mitm — reempacotar APK injetando proxy/Burp CA (par faço com Burp lane)
- androguard + enjarify — dex análise/stats Python

## Fase 5 — RE / Exploit-dev / Fuzzing
- pwntools (confirmar no python) + ROPgadget + one_gadget — exploit dev (env checksec mesmo bin)
- ensemble (clang wrapper) — cobertura sanitizer/congruência de input
- AFL++ (afl-fuzz) + honggfuzz — fuzzing de binários (complementa ghidra/rizin)
- trivy já está — manter reports por SBOM

## Fase 6 — AI Security (lane que estamos montando)
- wrapper da suíte já indexada no MegaBrain: prompt-injection, llm-top-10, llm-security, appsec-engineer, llm-guardrails → orquestrar como "AI-sec harness" pro nosso pipeline
- corpus JAIL indexado (INDEX.md) → usar como corpus de teste/defesa, não como acelerador de criação
- ferramenta de hardening: input sanitization + instruction hierarchy + output validation nas nossas apps de IA
- benchmark próprio: rodadas OWASP LLM01/ASI no próprio produto antes de entregar

## Implementar-ja-criado (integrar em pipeline)
1. mitr3-scan.sh — já envelopa semgrep+trivy+osv+secrets; encaixar prowler/cloudfox na fase 3 (novas varreduras ao mesmo report)
2. mitr3-codeql.sh — mantém SARIF imutável; adicionar `--pack python` (já tem), js/go presentes
3. mitr3-index.sh — incluir automático de novos cases (burp_lane etc)
4. mitr3-health.sh — Fases 2/3 integradas à matriz de presença; ferramentas da Fase 1 continuam candidatas à inclusão. InQL precisa de checagem de JAR/Burp.
5. Nexus (evidence chain) — lançar nova case do arsenal p/ demonstrar a aquisição de uma ferramenta nova e selar (padrão EV-000x)

## Ownership (quem executa)
- Hermes — specs, coordenação, QA, doc (este doc)
- OpenCode (maestro) — orquestração de execução, pipeline, infra
- Codex — build/QA/toolchain matrix e revisão (dentro da política dele)
- Antigravity — reverse/avaliação de ferramentas RE
- Gemma4 — MegaBrain/índice e apoio editorial
- Robin — deep/dark sources (sem registrar em índice compartilhado itens sensíveis)

## Ordem de execução sugerida
1. Fase 1 (web/API) — maior custo/benefício imediato para os bounties em curso
2. Fases 2 e 3 (AD/cloud) — preparar para engajamentos de rede/nuvem
3. Fase 4 (mobile) + Fase 5 (RE/fuzz) — acionar com casos concretos
4. Fase 6 (AI-sec harness) — conforme evolução das entregas de IA
