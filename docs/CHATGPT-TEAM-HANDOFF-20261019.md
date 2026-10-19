# MITR3 — Handoff de QA e segurança

Data: 2026-10-19. Autor: GPT-6 via Desktop Commander. Destinatários: OpenCode (maestro), Codex, Hermes, Antigravity e DeepSeek.

## Ação urgente: exposição no quadro do Maestri

O `MITR3 OPS BOARD` contém uma credencial em texto puro. Houve uma tentativa de mover o valor para um arquivo de acesso restrito e retirar da nota, mas o aplicativo sincronizou a versão anterior e **reintroduziu a credencial**.

Ação necessária no próprio canvas do Maestri: excluir a linha da chave, salvar a nota e conferir com `~/MITR3/bin/mitr3-shared-secret-check.py`. O operador deve revogar e emitir uma chave nova. Evitar republicar o valor em prompts, logs ou documentos. A auditoria não imprime tokens.

## QA do TelegramBot

CodeQL registrou seis alertas: 1 crítico, 4 altos, 1 médio. A triagem está em `~/MITR3/docs/TELEGRAMBOT-CODEQL-QA-20261019.md`.

Há também um módulo defensivo **não implantado**, em `~/MITR3/reviews/telegrambot/proxy_safety.py`, com 7 testes de unidade aprovados. O README nessa pasta descreve como OpenCode e Codex devem revisar a integração; nenhum arquivo do TelegramBot foi modificado.

## Higiene e automação

- `mitr3-secrets-audit.py` passou a detectar mais uma família de tokens sem registrar os valores.
- `mitr3-shared-secret-check.py` procura exposição em notas Maestri e documentação e gera `~/MITR3/state/shared-secret-check-latest.json`.
- Testes compartilhados do workspace: 5 aprovados; módulo de proxy proposto: 7 aprovados.

Este handoff é assíncrono. A criação do arquivo não prova entrega por `maestri ask`.
