# TelegramBot — proposta de proteção do proxy (não implantada)

O CódigoQL registrou `py/partial-ssrf` e `py/stack-trace-exposure` em
`job_hunter/engine/auth_proxy.py`; a revisão independente também apontou
fallback inseguro de token e repasse de headers de autenticação ao upstream.

O módulo `proxy_safety.py` é uma **proposta independente** de regras reutilizáveis.
O código original em `~/Documents/TelegramBot` **não foi modificado**.

## Validação reproduzível

```bash
python3 -m unittest discover \
  -s ~/MITR3/reviews/telegrambot -p test_proxy_safety.py -v
```

Resultado nesta data: **7 testes passaram** (rotas permitidas, rejeição de URL
anômala e métodos não autorizados, segredo ausente/fraco, credencial válida,
autenticação e remoção dos headers confidenciais). Não há requisição de rede.

## Integração — responsabilidade OpenCode + QA Codex

1. Levantar quais rotas/métodos Ollama são realmente usados antes de aplicar
   a allowlist; o módulo contém apenas endpoints comuns.
2. Exigir segredo forte via `PROXY_TOKEN` ou `JOBHUNTER_KAGGLE_KEY`, sem fallback.
   Guardar no secret manager e não imprimir valor no TUI.
3. No endpoint, substituir path livre por `safe_ollama_path(path, request.method)`,
   abortando com HTTP 404/405 em caso de `ValueError` **antes** da requisição.
4. Filtrar headers com `safe_forward_headers(dict(request.headers))`, sem repassar
   `Authorization`, `X-API-Key` ou `Cookie` ao upstream.
5. Trocar mensagem externa contendo `str(e)` por erro genérico e logging
   interno saneado.
6. Cobrir aplicação com ASGITransport e MockTransport, incluíndo rotas usadas
   em produção e streaming. Revalidar CodeQL antes/depois e obter revisão Codex.

## Limites

A allowlist é deliberadamente conservadora e pode precisar de mais rotas
Ollama (p. ex. listagem/gestão de modelos). Não integrar sem mapeamento e testes.
O scanner CodeQL marca regra SSRF parcial com 9.1, mas isso **não comprova**
capacidade de alcançar outros hosts no cenário atual. HTTPX no host demonstrou
normalização da URL para o mesmo localhost para caminhos anômalos comuns.

Referência: `~/MITR3/docs/TELEGRAMBOT-CODEQL-QA-20261019.md`
