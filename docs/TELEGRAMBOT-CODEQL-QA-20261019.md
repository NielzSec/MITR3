# MITR3 — QA independente dos alertas CodeQL no TelegramBot
Data: 2026-10-19 | GPT-6, triagem estática não intrusiva
Alvo: `/home/nielz/Documents/TelegramBot`
Fonte: `~/MITR3/engagements/codeql_TelegramBot_a27f79feb0/runs/20261019T160744205955425_python/codeql-findings.md`

## Resumo
O CodeQL retornou **6 alertas**: 1 CRITICAL, 4 HIGH, 1 MEDIUM.
**Severidade da regra não é prova de exploração.** Nenhum alvo de rede foi testado.
Não fiz modificações no TelegramBot, que está em uso pelo time.

## Prioridade 1 — proxy de autenticação
Arquivo: `job_hunter/engine/auth_proxy.py`

1. **Possível SSRF parcial** (`py/partial-ssrf`, 9.1 / CRITICAL por metadados da regra), linha 41: `path` vem da rota FastAPI e alimenta `httpx.AsyncClient.request(url=f"/{path}")`. HTTPX tem `base_url` fixo de localhost por padrão. Um teste **offline de montagem de URL**, com HTTPX 0.28.1 no host, mostrou que caminhos `/api/tags`, `//example.invalid/x`, `/../admin` mantêm o destino `127.0.0.1:11434`; houve normalização de `/../admin` para `/admin`. Isto **não confirma SSRF para host externo**, mas confirma que o cliente pode controlar o endpoint interno, o que pede allowlist de rotas/métodos e teste com ASGITransport. Não alterar automaticamente o proxy sem mapear endpoints Ollama legitimamente usados.
2. **Autenticação fail-open com token padrão estático** (observação de revisão manual, não alerta do CodeQL): `PROXY_TOKEN` possui fallback para valor conhecido no próprio código. Se o segredo de produção faltar, o serviço pode aceitar o valor público; a gravidade depende de exposição via Cloudflare. Remediação: exigir variável `PROXY_TOKEN` ou segredo do Kaggle, validar mínimo de entropia e abortar startup se ausente. NÃO registrar o valor.
3. **Headers de autenticação repassados ao upstream**: o proxy apenas remove `host` e `content-length`; `Authorization`, `X-API-Key`, `Cookie` e hop-by-hop permanecem. Passar somente headers de negócio permitidos; evitar envio de credenciais do gateway ao Ollama.
4. **Erro interno retornado ao consumidor** (`py/stack-trace-exposure`, MEDIUM, linha 55): `str(e)` pode revelar endereços internos ou detalhes de falha. Resposta externa genérica, log local saneado com correlation ID.

## Prioridade 2 — outros alertas
- `py/clear-text-logging-sensitive-data` em `job_hunter/tests/full_code_audit.py:124,130`: o relatório imprime campos de erro da checagem Supabase; confirmar se alguma exceção ou string de conexão contém credencial. Não foi observado vazamento real. Recomendar sanitização de erros, mensagens curtas.
- `py/jinja2/autoescape-false` em `job_hunter/engine/cover_letter_generator.py:71`: a saída parece ser carta de texto, não página HTML, então **possível falso positivo conforme o destino**. Manter evidência e documentar o contexto.
- `py/jinja2/autoescape-false` em `job_hunter/engine/pdf_compiler.py:238`: saída HTML é salva em arquivo e transformada em PDF; avaliar se há conteúdo não confiável no contexto. Para HTML, ativar autoescape e testar layout/PDF.
- O arquivo `full_code_audit.py` imprime conclusão textual de “100% seguro”; trocar por status baseado apenas nos testes executados, sem garantia universal.

## Plano de validação para OpenCode + Codex (sem alterar produção)
1. Criar uma cópia isolada do proxy e testes offline com FastAPI TestClient/HTTPX ASGITransport + MockTransport upstream, cobrindo autorização inválida, token ausente, rotas indevidas, URL anômala, headers confidenciais e exceções.
2. Implementar fail-closed, allowlist de rotas/métodos e headers, mascarar exceções. Rerodar testes e CodeQL security-extended; preservar comparação SARIF antes/depois.
3. Confirmar se o serviço é acessível fora de localhost pelo túnel Cloudflare e se há controles de autenticação adicionais **sem fazer testes invasivos**.
4. Codex faz QA independente antes de qualquer deploy. Não indexar segredos no MegaBrain.

## Referências
- CodeQL rule documentation: https://codeql.github.com/codeql-query-help/python/py-partial-ssrf/
- HTTPX AsyncClient: https://www.python-httpx.org/api/
- Evidência local: runner CodeQL e source, sem testes de rede.

**Estado: needs-review**, não explorado e não corrigido. OpenCode é o maestro; GPT-6 permanece auditor externo.
