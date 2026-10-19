# MITR3 — ARSENAL (plano de ferramentas)

Data: 2026-10-19 · Autor: Hermes (deepseek) · Autorização: total (squad) · Uso: engajamentos autorizados / CTF / laboratório 127.0.0.1.
Base: inventário real do host (`command -v` varrido hoje). Itens MISS = prioridade de instalação ou integração.

## Estado atual (resumo do que já está no host)
Web/API: burp pro (burp.sh), nuclei, ffuf, katana, httpx, dnsx, subfinder, amass, gau, gobuster, nmap, masscan, sqlmap, saltstack local, semgrep, trivy, osv-scanner, codeql (security-extended), mitr3-scan.sh, api-sec MCP.
RE: ghidra (analyzeHeadless), pyghidra venv, radare2, rizin, jadx, apktool, frida, ropper, checksec via pwntools.
AD/Infra: nxc (netexec), ldapdomaindump, hashcat, john, hydra, aircrack-ng, bettercap.
Outros: darkweb.sh + tor + onionsearch (Robin), SecLists 2.5G, docker (sudo NOPASSWD no host; indisponível neste sandbox).
Fase 1 Web/API: **0/9 instaladas neste ambiente** (checagem em 2026-10-19). `wpscan` e `sslscan` constam no repositório Arch `extra`, mas ainda não estão instalados. As sete restantes também não aparecem em `command -v`.

## Fase 1 — Web/API (nossa lane principal) — instalar/implementar
- feroxbuster — enumeração de diretórios em paralelo (alternativa mais rápida ao ffuf para discovery bulk)
- wpscan — wordpress específico (muito comum em bounty)
- sslscan + testssl.sh (sslyze opcional) — auditoria TLS/pinning
- naabu — syn scan rápido (projectdiscovery, casa com o resto da família)
- graphql-cop + inql — testes de GraphQL (schema introspection, batching abuse)
- gopherus — SSRF → protocol smuggling auxiliar
- ysoserial — gadget chains p/ desserialização Java em campos de teste autorizado

### Execução e validação local — 2026-10-19

Nenhuma ferramenta foi marcada como instalada sem `command -v` e uma versão/smoke
local. O sandbox atual bloqueia `sudo` (`no new privileges`) e a resolução de DNS
para GitHub, AUR e proxy Go. Não há pacotes dessas ferramentas em
`/var/cache/pacman/pkg` nem fontes correspondentes já baixadas em `~/Tools`.
Assim, nenhum teste ativo foi executado; nenhum host externo foi alvo de scan.

| Ferramenta | Fonte e método previsto | Status | Versão | Evidência local |
|---|---|---|---|---|
| feroxbuster | [epi052/feroxbuster](https://github.com/epi052/feroxbuster), release oficial em `~/Tools` | bloqueado | — | `command -v feroxbuster` vazio; GitHub sem DNS; `--version` impossível |
| wpscan | Arch `extra` (`pacman -S wpscan`), [upstream](https://github.com/wpscanteam/wpscan) | bloqueado | — | `pacman -Ss '^wpscan$'` → `1:4.1.0-1`; `pacman -Q` e `command -v` ausentes; `sudo` bloqueado |
| sslscan | Arch `extra` (`pacman -S sslscan`), [upstream](https://github.com/rbsec/sslscan) | bloqueado | — | `pacman -Ss '^sslscan$'` → `2.2.3-1`; `pacman -Q` e `command -v` ausentes; `sudo` bloqueado |
| testssl.sh | [testssl/testssl.sh](https://github.com/testssl/testssl.sh), clone oficial em `~/Tools` | bloqueado | — | `command -v testssl.sh` vazio; GitHub sem DNS; `--version` impossível |
| naabu | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu), `go install` | bloqueado | — | `command -v naabu` vazio; `go install ...@latest` falhou no DNS de `proxy.golang.org` |
| graphql-cop | [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop), clone + venv em `~/Tools` | bloqueado | — | `command -v graphql-cop` vazio; `pipx install graphql-cop` não encontrou distribuição (upstream instala por clone) |
| inql | [doyensec/inql](https://github.com/doyensec/inql), extensão Burp em `~/Tools` | bloqueado | — | `command -v inql` vazio; upstream atual é extensão JAR, sem CLI `inql` suportada |
| gopherus | [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus), clone em `~/Tools` | bloqueado | — | `command -v gopherus` vazio; GitHub sem DNS; `--help` impossível |
| ysoserial | [frohoff/ysoserial](https://github.com/frohoff/ysoserial), JAR da release oficial em `~/Tools` | bloqueado | — | `command -v ysoserial` vazio; GitHub sem DNS; `java -jar ...` impossível |

Para retomar em um host com DNS e permissão de instalação: usar `pacman` para os
dois pacotes de `extra`; obter os outros somente dos repositórios upstream acima;
manter clones/JAR em `~/Tools` e expor wrappers em `~/.local/bin`. A validação
exige `command -v`, `--version` ou `--help`/smoke equivalente para cada ferramenta,
seguida de teste de rede somente contra `127.0.0.1`. Para WPScan, o token da API
é opcional para certas funções e deve vir de `WPSCAN_API_TOKEN` no ambiente local,
sem valor no repositório. O InQL atual deve ser validado como JAR carregado no
Burp; `command -v inql` não é um critério aplicável à extensão oficial.

## Fase 2 — AD / Windows (suporte a engajamentos na rede)
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
4. mitr3-health.sh — candidato a receber checagens dos novos tools **após** instalação e validação; não foi alterado nesta fase bloqueada (feroxbuster, sslscan e os demais quando disponíveis).
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
