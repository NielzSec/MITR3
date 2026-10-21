Gatekeeper — Build & QA
UTC dinâmico. SEC-03: index e worktree com padrões existentes; SEC-06: hooks, ambiente e pins; SEC-07: hash externo, permissões e schema do log.
RB-01..08: baseline, manifesto de escopo, cópias atômicas em tmpfs, diff reverso, restauração ensaiada, comparação de bytes/modos, recusa de conflitos e preservação de processos. Comandos livres são proibidos.
Testes: 45/45 PASS (38 novos do gatekeeper + 7 existentes Chrome). Git e tmpfs reais; bubblewrap simulado nos unitários, smoke real PASS no workspace.
Dry-run real: exit 1/BLOCK. APPROVED_EVIDENCE_REQUIRED; SEC-03 também BLOCK/PermissionError, sem divulgar conteúdo. Não há atestado de ausência de segredos no workspace.
Limites: ensaio para substituir arquivos existentes, sem backup durável ou rollback de recursos vivos. Não mede saúde funcional REA/MegaBrain/JEV. Revisão independente e aceite OpenCode/humano de liberação permanecem separados; não emitidos por esta execução.
Nenhum serviço/configuração produtiva alterado. Evidências anteriores preservadas.

SHA-256:
d4658de34289d93ed919887344d843a38c1e9ab334a6f996aa5f4d8dcab30d6f  labs/security-enforcement/scripts/validate_gates.py
3de43748327779d57c2b83b1fc607ae159802c51f73b7367d760a57be629ede8  labs/security-enforcement/tests/test_validate_gates.py
5a6886c5a4205d522a6ffc511d1891e7b2cb4a08df0c532a62f8b75c9ad902e9  labs/security-enforcement/README.md
66742d7e4e10213932a1ec8eb2f615cf9490644983e2a7fa364023d66b284d6e  bin/mitr3-secrets-audit.py
7151423a810a14550671caf00dac3fbabc935a42d6c9c9ea6148486f6a59e825  docs/REVERSE-NEXT-GATES-G-SECURITY-ROLLBACK-v01.md
8665af4e14862a6c641caa2e7b663dd2547b5501160a93382e74a36bdb629a82  docs/MITR3-REVERSE-NEXT-MASTERPLAN-20261021.md
