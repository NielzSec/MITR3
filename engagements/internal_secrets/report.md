# Technical report — internal_secrets

Data: 2026-10-19 · Operador: OpenCode (maestro) · Escopo: superfície de credenciais do host.
Estado: encerrado. Nenhum segredo legível por terceiros. Uma correção de permissão aplicada.

## Executive summary

Os arquivos que contêm credenciais reais nesta máquina estão em modo 0600 dentro de
diretórios 0700. Nenhum segredo de valor real foi encontrado em arquivo 0644. O único
arquivo 0644 com conteúdo semelhante a segredo era um fixture de teste de 35 bytes na
área de scratch, ajustado para 0600. O achado que sobra é de método, não de exposição:
a varredura ampla com regex de credencial produz 2.703 hits dominados por exemplos em
documentação e por JWT dentro do banco de sessão do agente — o que confirma que
auditoria de segredo precisa de caminho dirigido, não de força bruta no home.

## Postura observada

| arquivo | modo | dono | observação |
|---|---|---|---|
| `~/.hermes/auth.json` | 0600 | nielz | JWT de sessão do agente |
| `~/.hermes/config.yaml` | 0600 | nielz | provider keys por referência de env |
| `~/.hermes/.env` | 0600 | nielz | `GEMINI_API_KEY`, `DAHL_API_KEY` em texto |
| `~/.hermes/.hermes_history` | 0600 | nielz | histórico com JWT em linha |
| `~/.config/opencode/opencode.json` | 0600 | nielz | MCP args, sem chave literal |
| `~/.config/mitr3-secrets/apisec.token` | 0600 | nielz | prefixo `secbolt:` no conteúdo |
| `~/.config/mitr3-secrets/dahl.token` | 0600 | nielz | 39 bytes |
| `~/.hermes/cache/scratch/webapi-val/secret.txt` | 0644 → **0600** | nielz | fixture de 35 bytes |

Diretórios: `~/.config/mitr3-secrets` 0700, `~/.hermes` 0700.

## Findings

### S-01 — fixture de scratch legível por outros usuários

- severity: INFO → **corrigido**
- asset: `~/.hermes/cache/scratch/webapi-val/secret.txt` (0644, 35 bytes)
- origem: artefato da validação web/API do deepseek
- ação: `chmod 600`; sem conteúdo de valor
- evidência: `secrets_surface.json`, hit com `file_mode` 0o644

### S-02 — token do APIsec guardado com prefixo `secbolt:`

- severity: LOW (higiene)
- asset: `~/.config/mitr3-secrets/apisec.token` (850 bytes, prefixo `secb`)
- análise: o servidor espera JWT puro; o arquivo carrega `secbolt:<jwt>` e o launcher
  remove o prefixo em runtime. Funciona, mas qualquer outro consumidor do arquivo quebra
- ação recomendada: normalizar o arquivo no momento da rotação, ou documentar o prefixo
  como contrato. Não alterado nesta rodada — o token é vivo e a troca é do dono da conta
- evidência: `secrets_targeted.json`, fallback registrado em `~/MITR3/README.md`

### S-03 — chaves de provider em `.env` de 28 KB

- severity: INFO (aceito)
- asset: `~/.hermes/.env` — contém `GEMINI_API_KEY` e `DAHL_API_KEY` em texto claro
- risco: qualquer processo que rode como `nielz` lê o arquivo; é o modelo de ameaça de
  um host de operador único, não de host compartilhado
- ação: manter 0600; se o host passar a ter mais de um usuário humano, migrar para
  `pass` ou keyring e trocar `.env` por referência

### S-04 — ruído da varredura ampla

- severity: INFO (método)
- números: 30.804 arquivos, 2.703 hits, 65 s; 2.678 em 0600, 24 em 0644, 1 em 0700
- os 24 hits em 0644 são manpages do ffmpeg e HTML de documentação
- conclusão: regex de credencial em home inteiro não é sinal; o pipeline deve rodar
  em lista dirigida. `bin/mitr3-secrets-audit.py` aceita caminhos, então a lista é o controle

## Remediation

1. ~~`chmod 600` no fixture de scratch~~ feito.
2. Rotacionar `apisec.token` para JWT puro na próxima troca (dono da conta).
3. Se entrar um segundo usuário humano: keyring + `.env` por referência.
4. Rodar `mitr3-secrets-audit.py` só na lista de arquivos de credencial, nunca no home.

## Unknowns

- Não foi feita verificação de que os JWTs encontrados estão ativos; o case mede exposição, não validade.
- Históricos de shell de outros usuários e backups fora de `$HOME` não foram varridos.
