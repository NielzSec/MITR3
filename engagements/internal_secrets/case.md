# Case — internal_secrets

- id: internal_secrets
- type: internal_audit
- scope: superfície de credenciais do host de operação (configs, tokens, históricos)
- authorization: interna — máquina do squad, autorizada por Kai em 2026-10-19
- operator: OpenCode (maestro)
- opened: 2026-10-19 11:23
- state: closed (postura limpa; 1 higiene aplicada)

## Objective

Verificar se credenciais reais desta máquina estão em arquivos legíveis por outros
usuários, se os diretórios que as contêm são privados, e se há token em formato
frágil que dependa de tratamento no launcher.

## Target surface

- `~/.hermes/{auth.json,config.yaml,.env,.hermes_history}`
- `~/.config/opencode/opencode.json`
- `~/.config/mitr3-secrets/{apisec.token,dahl.token}`
- `~/.bash_history`
- varredura ampla de `~/.hermes`, `~/.config`, `~/Documents/MegaBrain-OSINT4ALL`
  (fonte e caches incluídos, para medir ruído do método)

## Method

- `bin/mitr3-secrets-audit.py` — 12 regras de formato de credencial; relata caminho,
  linha, regra, modo e dono; **nunca** grava valor, só o comprimento do match
- verificação de modo/dono com `stat` nos arquivos que contêm segredo
- inspeção de nomes de chave em `.env` (sem valores)

## Timeline

- 2026-10-19 11:23 case aberto, varredura ampla (30.804 arquivos, 65 s)
- 2026-10-19 11:24 varredura ampla concluída; 2.703 hits brutos
- 2026-10-19 11:25 triagem por modo e caminho; varredura dirigida em 8 arquivos
- 2026-10-19 11:26 `secret.txt` de scratch ajustado para 0600; evidência selada

## Evidence

| arquivo | conteúdo |
|---|---|
| `evidence/secrets_surface.json` | varredura ampla (ruidosa por desenho) |
| `evidence/secrets_targeted.json` | 8 arquivos de credencial, 3 hits JWT |
| `evidence/SHA256SUMS` | selo dos dois JSON |

## Notes

- Nenhum valor de credencial foi impresso, copiado para relatório ou commitado.
- A varredura ampla é ruído: manpages do ffmpeg e código do próprio hermes contêm
  literais de exemplo; `state.db` contém JWT de sessão em texto.
