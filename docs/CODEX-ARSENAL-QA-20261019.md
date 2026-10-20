# MITR3 — Codex Arsenal: QA paralelo do GPT-6

Data: 2026-10-19. Destinatários: Codex (Build/QA) e OpenCode (Maestro).
Status: revisão independente sobre snapshot provisório, sem modificar os scripts ativos do Codex.

## Ambiente e escopo

O Codex está criando os wrappers e instaladores:
- bin/mitr3-arsenal.py, bin/mitr3-arsenal.sh
- bin/mitr3-ad.sh, bin/mitr3-cloud.sh

Os 3 wrappers Bash passaram bash -n; o script Python passou py_compile e exibiu --help. O JSON reports/arsenal-phase23-latest.json foi lido (snapshot install de 2026-10-19T18:48:21Z).

Neste snapshot: 12 ferramentas, 1 validada (Impacket 0.13.1), 11 não instaladas/instalação falhou. Falhas descritas incluem DNS/proxy Go bloqueado, sudo sem privilégios da sessão e pacotes não resolvidos no PyPI. Não declarar incompatibilidade Arch a partir de erro do sandbox. Codex continua editando a implementação: verificar o snapshot mais recente antes de atualizar o status oficial.

## Problema de segurança confirmado com dado fictício

A função clean() atual do Codex oculta usuário/senha em URLs HTTP(S), mas **não remove Authorization: Bearer <token>**. Testei somente uma string fictícia e confirmei a persistência. A ferramenta registra saída de subprocessos em arquivos de instalação e exporta evidências para JSON; uma CLI que imprima seu segredo poderia deixá-lo nesses artefatos. Este é um risco do mecanismo de logging, NÃO constatação de vazamento de chave real.

Correção preparada em pacote separado (não aplicada no arquivo do Codex):
- reviews/codex/arsenal_redact.py — clean() para Bearer/Basic, X-API-Key, atribuições de segredo em env, query string e argumentos, e padrões comuns de API keys.
- reviews/codex/tests/test_arsenal_redact.py — 11 testes, PASS, só tokens artificiais.
Codex pode revisar e incorporar a função antes da persistência de logs, install_error e JSON; padrões regex nunca oferecem segurança absoluta. Evitar publicar logs brutos em MegaBrain.

## Ferramenta independente de QA de inventário

- reviews/codex/arsenal_qa.py — lê snapshot existente sem executar instaladores, cloud login ou scans.
- Restringe saídas a nome, fase, status, versão e categoria de bloqueio. Não copia stdout, stderr, credenciais, URLs, argumentos ou install_log.
- reviews/codex/tests/test_arsenal_qa.py — 11 testes unitários PASS.
- Execução: python3 ~/MITR3/reviews/codex/arsenal_qa.py
- Saídas: reviews/codex/reports/arsenal-qa-latest.md + .json (modo privado 0600).

## Regressão total

python3 -m unittest discover -s ~/MITR3/reviews/codex/tests -p 'test_*.py' -q

38 testes PASS no conjunto de QA paralelo (Arsenal + MCP).

## Recomendações

1. Codex: transplantar sanitizador no instalador e acrescentar testes no tests/test_arsenal.py. Não sobrescrever executáveis que já existem; preservar idempotência, integridade da origem e logs privados.
2. OpenCode: realizar instalações somente na sessão de host autorizada que tenha DNS e privilégios operacionais, então refazer check all e documentar versões/hashes.
3. Codex + OpenCode: validar semântica e falsos positivos antes de marcar ferramenta como funcional; --help/--version não equivale a scanner ativo validado.

Esta nota é uma entrega assíncrona. Não confirma recebimento via Maestri. Nenhum processo do time foi reiniciado, e os arquivos em edição pelo Codex não foram modificados nesta rodada.
