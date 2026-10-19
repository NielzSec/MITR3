# RUNBOOK — operação do host

Comandos que resolvem os incidentes recorrentes. Cada item traz o sintoma, a causa e a ação.

## MCP parado ou com config velha (OpenCode)

Sintoma: ferramenta some do catálogo, `failed: Connection closed`, ou token antigo em uso.

```
opencode mcp list          # status por servidor
opencode reload            # recarrega config e sobe os MCPs sem reiniciar a sessão
opencode mcp list          # confirmar "connected"
```

`opencode reload` foi validado em 2026-10-19: apisec-ng voltou `connected` e respondeu 200
sem reiniciar o seat. Não matar processo de MCP à mão — o cliente derruba a entrada e só
o reload a traz de volta.

## MCP parado nos agentes Hermes

```
hermes mcp list
hermes mcp test <nome>
```
Config alterada exige sessão nova: `hermes --resume <session-id> --provider dahl -m <modelo>`.

## Docker

- Operacional: `sudo docker ...` (regra NOPASSWD em `/etc/sudoers.d/50-mitr3-docker`).
- Shell interativo sem sudo: `newgrp docker` ou novo login. O grupo só entra na sessão no login.
- Nunca passar a senha do root por pipe em comando de agente: fica em argv e histórico.

## Deepseek / provider dahl

Sintoma: `HTTP 404: model ... not found` ao resumir sessão.
Causa: o provider volta para `ollama-launch` (127.0.0.1:11434) e o modelo só existe na dahl.
Ação: `hermes --resume <session> --provider dahl -m deepseek-ai/DeepSeek-V4-Flash-0731`.

## Servidor de teste em shell de agente

Nunca em foreground. Padrão:
```
python3 -m http.server 8089 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > /tmp/srv.pid
...
kill $(cat /tmp/srv.pid)
```

## Varredura estática de um alvo

```
~/MITR3/bin/mitr3-scan.sh <case> <target> [label]
```
19 s num repo pequeno; evidência selada e `findings.md` no case.

## CodeQL security-extended

```
~/MITR3/bin/mitr3-codeql.sh <repo_dir> [python|javascript|go]
```

Python é o padrão. Para Python e JavaScript, o wrapper cria banco com `--build-mode=none` (sem build) em `/tmp/opencode/codeql-db-<nome>-<lang>-<timestamp>`. Cada resultado fica em **`~/MITR3/engagements/codeql_<repo>_<hash>/runs/<timestamp>_<lang>/`**: `codeql-findings.md`, `evidence/codeql-<lang>.sarif`, `evidence/SHA256SUMS` e `logs/database-{create,analyze}.log`. Confirme cobertura no log (`CodeQL scanned X out of Y`) e integridade com `cd <pasta_da_execução> && sha256sum -c evidence/SHA256SUMS`. Não copie SARIF sem saneamento para RAG.

Go **não suporta `--build-mode=none`** na CLI 2.27.2; o script bloqueia Go por padrão. Para repositório de confiança em que compilação local seja permitida: `MITR3_CODEQL_ALLOW_GO_BUILD=1 ~/MITR3/bin/mitr3-codeql.sh <repo_dir> go`; esse modo usa `autobuild` e pode executar código do projeto. Resultados prévios deixados na raiz dos repositórios por outras ferramentas não são editados pelo wrapper atual. Recomenda-se nunca sobrescrever evidências existentes.

## Dossiers de função no Ghidra (PyGhidra)

O `analyzeHeadless -postScript foo.py` do host recusa `.py` (`Ghidra was not started with
PyGhidra. Python is not available`). Caminho que funciona — CLI `pyghidra` em venv própria:

```
~/MITR3/bin/ghidra-dump.sh <binario> <saida.json> [fast_mode]
```

Por dentro: `~/.local/share/pyghidra-venv/bin/pyghidra --install-dir ~/Tools/ghidra
<bin> <dumper.py> <out.json>`, com `GHIDRA_INSTALL_DIR` exportado. O dumper é
`mitr3-nexus-re/scripts/ghidra_headless_dumper.py` (saída no formato Evidence v2).
Receita de instalação: `python3 -m venv ~/.local/share/pyghidra-venv &&
~/.local/share/pyghidra-venv/bin/pip install pyghidra`.

## Burp Suite Professional (loader v1.18 + JDK 21)

Artefatos em `~/Tools/burp/` (selo `SHA256SUMS` no diretório):
`BurpLoaderKeygen_v1.18.jar` (md5 `75321ccbab4bb4aa4e2f30314a824513`, sha1 `b2c5cab65fadcbef9c0ea286ae710115eb7c58c5` — confere com o recebido),
`burpsuite_pro_v2026.3.3.jar` (PortSwigger, 659 MB), `jdk/` → symlink para `java-21-openjdk`.

- Lançamento diário: `~/MITR3/bin/burp.sh [args]` — smoke test: `burp.sh --version` → `2026.3.3-47134`.
  A licença é injetada em runtime pelo agente (`-javaagent:BurpLoaderKeygen_v1.18.jar`); a GUI do keygen
  só é necessária para re-ativação. Comando idêntico ao botão "Run" do keygen (capturado por xdotool).
- A ativação foi feita uma vez em 2026-10-19; o título da janela prova o estado: `- licensed to ...`.
- v1.18 é obrigatório para JDK 25+ (removeu `jdk.internal.org.objectweb.asm`); por isso JDK 21.
  `-noverify` emite aviso de deprecação no JDK 21 — esperado, mantido igual ao comando do keygen.
- Headless/scanner via CLI: sem flag nativa de headless nesta versão; para automação futura, usar
  `--config-file` (com "unpause spider and scanner") ou xvfb quando instalado.
