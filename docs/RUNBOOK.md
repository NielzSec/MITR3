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
