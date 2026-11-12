# MITR3 — BlackOps: runbook de ferramentas OPSEC

**Data:** 2026-11-11 | **Staging:** `master` | **Agente:** BlackOps (opsec) — backend Hermes
**Regra de ouro:** leitura antes de execução (`#all-mitr3`), nenhuma escrita em canal, nenhum alvo sem escopo aprovado pelo operador dj.

## Mapa tools ↔ implementação

| Tool declarado (`hackbots/bots.json`) | Implementação real | Estado |
|---|---|---|
| `secrets-guard` | `bin/mitr3-secrets-audit.py` | ✓ existente (VANTA usa no fluxo de Git) |
| `tor-routing` | `bin/darkweb.sh` (fetch/head/search/status via SOCKS 127.0.0.1:9050) | ✓ existente |
| `slack-auditor` | Composio (leitura) + `bin/mitr3-slack-audit.py` (análise) | ✓ novo |
| `opsec-scanner` | `bin/mitr3-opsec-scan.py` | ✓ novo |

## slack-auditor — auditoria OPSEC do canal

Objetivo: detectar segredos/exposição publicados no `#all-mitr3` (tokens, chaves, credenciais em URL, IPs internos, contatos privados). Nunca postar; saída mascarada.

1. Ler o canal via Composio MCP (Slack): `SLACK_FIND_CHANNELS` (`query: "all-mitr3"` → `C0C9ZLLU094`) → `SLACK_FETCH_CONVERSATION_HISTORY` paginando por `response_metadata.next_cursor`. Sincronizar resposta ao workbench e salvar o JSON unificado.
2. Copiar o dump para o host (arquivo `dump.json` contendo `results[].response.data.messages`, ou `{"messages":[...]}`, ou lista crua).
3. Rodar:
   ```bash
   python3 bin/mitr3-slack-audit.py dump.json          # relatório mascarado
   python3 bin/mitr3-slack-audit.py dump.json --json   # saída para o Maestro
   ```
4. Saída: `0` limpo, `1` achados, `2` erro de entrada. Achados com `severity` high/critical → reportar ao operador com `ts`/`user` de referência e pedir revogação/rotação da credencial. **Nunca colar o valor completo em log ou canal.**

## opsec-scanner — perímetro próprio

Objetivo: varredura passiva de headers de segurança e exposição de paths em infraestrutura nossa (ex.: `mitr3-web` no edge Cloudflare). Só GET, sem payload.

```bash
python3 bin/mitr3-opsec-scan.py https://mitr3-web.zgordola1.workers.dev
python3 bin/mitr3-opsec-scan.py https://... --json
```

Verifica: headers ausentes (CSP, HSTS, XCTO, XFO, Referrer/Permissions-Policy), `Server`/`X-Powered-By` expondo versão, cookies sensíveis sem `Secure`/`HttpOnly`, e 200 em paths sensíveis (`/.git/HEAD`, `/.env`, `/package.json`, `/server-status`, `/.git/config`). Achados → relatório com `report_sha256`; enviar ao Maestro/operador antes de qualquer correção acordada.

## darkweb-monitor (Robin) — fontes

Fontes agora em `~/MITR3/docs/monitor/sources.conf` (`nome|url` por linha, só `.onion` verificada; o script recusa linha sem `.onion`). Seed com as 3 fontes atuais; Robin adiciona fonte nova como linha nova, sem tocar código. Rotina 09:30, 1 GET por fonte, ≤50 s, sequencial.

## Testes

`tests/test_opsec_tools.py` — 6/6 OK, offline (sem rede): detecção/mascaramento do slack-auditor (3 shapes de dump) e avaliação de headers/cookies do opsec-scanner (fetch mockado).
