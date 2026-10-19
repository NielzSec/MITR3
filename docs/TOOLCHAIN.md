# Toolchain MITR3 — auditoria de 2026-10-19

Inventário atual de `bin/mitr3-health.sh --json` e `bin/mitr3-health.sh`: **42 ok, 3 missing, 1 warn** em 2026-10-19. Dos três `missing`, somente **burpsuite** e **codeql** são lacunas de ferramenta; `megabrain-http` é uma checagem de serviço que recebe HTTP 200 e permanece aberta até o timeout de 5 s do `curl`. O aviso é `docker-daemon` (`docker info` falha); o CLI Docker está instalado. Versões abaixo foram verificadas localmente por `pacman -Q`, metadados Go/pipx, arquivos de instalação ou `--version`; `—` indica versão não verificada. Os comandos de instalação são referências para uso futuro; esta auditoria não instalou ferramentas.

| name | version | origin | state | install command |
|---|---:|---|---|---|
| ghidra | 12.1.2-2 | extra/ghidra | ok | `sudo pacman -S ghidra` |
| ghidra-headless | 12.1.4 | cópia local em `~/Tools/ghidra` | ok | distribuição upstream em `~/Tools/ghidra` |
| r2 | 6.2.2-1 | extra/radare2 | ok | `sudo pacman -S radare2` |
| rizin | 0.8.2-2 | extra/rizin | ok | `sudo pacman -S rizin` |
| gdb | 18.1-1 | extra/gdb | ok | `sudo pacman -S gdb` |
| jadx | 1.5.6-1 | extra/jadx | ok | `sudo pacman -S jadx` |
| apktool | 3.0.3 | instalação local `/opt/apktool`, wrapper `/usr/local/bin/apktool` | ok | já instalado; atualização pelo release upstream do Apktool |
| java | 27.u35-1 | extra/jdk-openjdk | ok | `sudo pacman -S jdk-openjdk` |
| python3 | 3.14.8-1 | extra/python | ok | `sudo pacman -S python` |
| go | 1.27.2-1 | extra/go | ok | `sudo pacman -S go` |
| rustc | 1.99.1 | rustup, toolchain stable ativa | ok | `rustup default stable` |
| node | 26.12.0-1 | extra/nodejs | ok | `sudo pacman -S nodejs` |
| docker | 29.9.1-1 | extra/docker | ok; daemon inacessível | `sudo pacman -S docker` |
| nmap | 7.992-1 | extra/nmap | ok | `sudo pacman -S nmap` |
| masscan | 1.3.2-2 | extra/masscan | ok | `sudo pacman -S masscan` |
| sqlmap | 1.10.10-1 | extra/sqlmap | ok | `sudo pacman -S sqlmap` |
| ffuf | 2.3.0 | upstream Go em `~/.local/bin` | ok | `go install github.com/ffuf/ffuf/v2@latest` |
| nuclei | 3.11.1 | ProjectDiscovery Go em `~/.local/bin` | ok | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| httpx | 1.12.0 | ProjectDiscovery Go em `~/.local/bin`; **não** `python-httpx` | ok | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| subfinder | 2.17.0 | ProjectDiscovery Go em `~/.local/bin` | ok | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| katana | 1.8.0 | ProjectDiscovery Go em `~/.local/bin` | ok | `CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| dnsx | 1.3.1 | ProjectDiscovery Go em `~/.local/bin` | ok | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| gau | 2.2.4 | upstream Go em `~/.local/bin` | ok | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| amass | 5.1.1 | OWASP Amass Go em `~/.local/bin` | ok | `CGO_ENABLED=0 go install github.com/owasp-amass/amass/v5/cmd/amass@main` |
| trivy | 0.76.0-1 | extra/trivy | ok | `sudo pacman -S trivy` |
| semgrep | 1.181.0 | pipx local | ok | `pipx install semgrep` |
| osv-scanner | 2.7.0 | upstream Go em `~/.local/bin` | ok | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` |
| checksec | 3.2.0-2 | extra/checksec | ok | `sudo pacman -S checksec` |
| ropper | 1.13.13-2 | extra/ropper | ok | `sudo pacman -S ropper` |
| pwntools | 4.15.0 | pipx local, fornece `pwn` | ok | `pipx install pwntools` |
| frida | frida-tools 14.11.0; CLI 17.24.3 | PyPI/frida-tools via pipx | ok | `pipx install frida-tools` |
| impacket | 0.13.1-1 | extra/impacket; também pipx 0.13.1 | ok; health agora verifica `smbclient.py` | já instalado; `sudo pacman -S impacket` |
| netexec | 1.5.1+1108.ae683dba | checkout Git via pipx | ok | `pipx install git+https://github.com/Pennyw0rth/NetExec` |
| chisel | 1.13.0 | upstream Go em `~/.local/bin` | ok | `go install github.com/jpillora/chisel@latest` |
| mitmproxy | 12.2.3-1 | extra/mitmproxy | ok | `sudo pacman -S mitmproxy` |
| upx | 5.2.0-1 | extra/upx | ok | `sudo pacman -S upx` |
| afl-fuzz | 5.00c-1 | extra/afl++ | ok | `sudo pacman -S afl++` |
| gh | 2.102.0-1 | extra/github-cli | ok | `sudo pacman -S github-cli` |
| msfconsole | 6.5.6-1 | extra/metasploit | ok | `sudo pacman -S metasploit` |
| hashcat | 7.1.2-2 | extra/hashcat | ok | `sudo pacman -S hashcat` |
| hydra | 9.7-1 | extra/hydra | ok | `sudo pacman -S hydra` |
| burpsuite | — | AUR/burpsuite Community (confirmar AUR) | missing | `yay -S burpsuite` |
| codeql | — | bundle oficial GitHub CodeQL | missing; sem pacote confirmado em pacman/AUR | baixar `codeql-bundle-linux64.tar.zst` de [codeql-action releases](https://github.com/github/codeql-action/releases), extrair e adicionar o diretório `codeql/` ao `PATH` |
| megabrain-http | — | serviço MCP remoto configurado em `nielz-aspire-a315-53.tailb82a64.ts.net/mcp` | health: missing; teste externo recebeu HTTP 200, mas `curl --max-time 5` expirou na conexão aberta | não é pacote; ajustar a checagem de disponibilidade para ler só o status HTTP |
| ollama | cliente 0.40.6 | instalação local `/usr/local/bin/ollama` | ok no health; serviço não responde a `ollama --version` | instalação local/upstream já presente |
| docker-daemon | Docker 29.9.1-1 | serviço e permissão de grupo do Docker | warn; `docker info` falha | relogar no grupo `docker` e verificar o serviço; não é falta do CLI |
| Chromium (Playwright) | Google Chrome for Testing 156.0.8078.4 | cache Playwright `~/.cache/ms-playwright/chromium-1248` | instalado; fora do health check | `npx playwright install chromium` |

Para os binários de `go install`, verificar se o diretório de destino está no `PATH`; neste host os novos binários aparecem em `~/.local/bin`. `ghidra` e `ghidra-headless` são versões diferentes, pois o segundo vem de uma cópia local.

## Instalado em 2026-10-19

Confirmados no ambiente nesta data: `apktool` 3.0.3, `frida-tools` 14.11.0, `checksec` 3.2.0-2, `ropper` 1.13.13-2, `pwntools` 4.15.0, `impacket` 0.13.1, `netexec` 1.5.1+1108.ae683dba (Git/pipx), `gau` 2.2.4, `amass` 5.1.1, `osv-scanner` 2.7.0, Rust 1.99.1 e Chromium do Playwright 156.0.8078.4. Também presentes: `semgrep` 1.181.0, `gh` 2.102.0-1, `afl++` 5.00c-1, `upx` 5.2.0-1, `mitmproxy` 12.2.3-1, `rizin` 0.8.2-2 e `trivy` 0.76.0-1. Estes sete já constavam como disponíveis na primeira leitura desta auditoria; esta seção registra o estado atual, não atribui a ela a data de instalação de cada pacote.

## Lacunas reais

1. **burpsuite:** binário ausente. Falta o proxy gráfico para inspeção e reprodução manual de fluxos web/API; `mitmproxy` já cobre parte do trabalho. Caminho Arch: `yay -S burpsuite` (Community, AUR).
2. **codeql:** CLI ausente. Falta o bundle oficial com consultas compatíveis para análise estática e criação de bancos CodeQL; obter `codeql-bundle-linux64.tar.zst` no release oficial e adicionar `codeql/` ao `PATH`.

Referências de instalação: [ArchWiki Burp Suite](https://wiki.archlinux.org/title/Burp_Suite), [AUR android-apktool identificado no projeto](https://github.com/iBotPeaches/Apktool/issues/3334), [ProjectDiscovery](https://docs.projectdiscovery.io/tools/nuclei/install), [ffuf](https://github.com/ffuf/ffuf), [Amass](https://github.com/owasp-amass/docs/blob/master/docs/index.md), [Frida](https://frida.re/docs/installation/), [NetExec](https://www.netexec.wiki/getting-started/installation/installation-on-unix), [CodeQL CLI](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli).

## osv-scanner - semantica de faixa (2026-10-19)

Em `requirements` sem pin, o `osv-scanner` resolve a **versão mínima** da faixa: `pip>=X` pode virar `pip 9.0.3`. Os advisories resultantes são artefatos dessa resolução, não evidência da versão instalada no ambiente. Casos observados: `internal_baseline` F-02 e `internal_nexus_retest`.

Para reportar vulnerabilidades de runtime, auditar o ambiente instalado (`pip freeze` registrado em lock) ou a imagem construída. Usar `trivy image` como fonte de verdade para a imagem em execução e confirmar as versões com `pip list` dentro do container antes de publicar o achado.

## Pipeline unico

`~/MITR3/bin/mitr3-scan.sh <case> <target> [label]` executa `semgrep` (`p/python`, `p/secrets`), `trivy fs` (`vuln`, `secret`, `misconfig`), `osv-scanner` e `secrets-audit`. O pipeline sela os resultados com SHA256 e escreve `findings.md`. Tempo observado: **19 s** em `mitr3-nexus-re`.

## Lacunas Ghidra no case `nexus_vault` (2026-10-19)

1. **Post-script Python no headless — resolvido.** Neste host, executar `~/.local/share/pyghidra-venv/bin/pyghidra --install-dir ~/Tools/ghidra <bin> scripts/ghidra_headless_dumper.py <out.json>`; o wrapper é `~/MITR3/bin/ghidra-dump.sh`. Validado no alvo `nexus_vault`: `vuln` com `frame=80` e `callers=[main]`; `win` com `frame=8` e `callers=[]` (EV-0009, quarto provider). O erro anterior, `Ghidra was not started with PyGhidra. Python is not available`, fica resolvido ao iniciar pelo PyGhidra.
2. **Binários nativos sem bit de execução — corrigido, sujeito a regressão.** Arquivos como `~/Tools/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile` estavam em modo `0600`, causando `EACCES` na decompilação. Foi aplicado `chmod +x` em `~/Tools/ghidra/**/os/linux_x86_64/*`; na conferência atual, `decompile` está em modo `0711`. Após cada atualização do Ghidra, conferir novamente o bit executável dos binários nativos antes de confiar no resultado da decompilação.
