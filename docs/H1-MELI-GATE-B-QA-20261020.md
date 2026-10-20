# MITR3 — Portão B, QA web/API — FAIL (correções documentais)
Data: 2026-10-20. Auditor: GPT-6 QA. Plano: `docs/H1-MELI-TESTPLAN.md` commit `ff62fb6`; checklist `docs/H1-MELI-GATE-B-CHECKLIST-20261020.md` commit `983d41a`. Escopo/API: `structured_scopes_all.json`, SHA256 `146d115e8b0ad9f3da81efa7a3c284c042c1b3a3660f4f4d8ae3f6241f155d62`.

**FAIL do Portão B para início de testes ativos; Portão A PASS permanece válido.** Claims JEV (0.86–0.91) foram fornecidas pelo maestro e registradas, não reexecutadas por GPT-6. A evidência mecânica de IDs/eligibilidade é aceita, mas o conteúdo do plano não está pronto para execução.

## Pendências específicas
1. **Corrigir tiers da tabela de priorização §1:** todos os 14 identificadores ativos utilizados no plano (2 APIs e 12 wildcards) têm `Tier 1` no atributo `instruction` do extrato completo. O plano rotula como `Tier 2` todos os wildcards P1/P2 exceto `*.adminml.com`. Isso distorce inventário, triagem e cálculo de bounty. Manter `Crypto` sem tier e Point Smart adiado. Garantir que lista 14/14 permaneça `submission=true` após correção.
2. **Remover ou isolar H8 (race condition em pagamento):** a hipótese propõe duas requisições para testar corrida enquanto a spec v4 §7 proíbe concorrência. Duas requisições espaçadas NÃO testam uma condição de corrida; não executar H8 neste plano. Só reincluir após mudança de requisitos e autorização explícita do programa para método adequado, mantendo apenas ambiente e instrumentos de teste, sem dinheiro real.
3. **Eliminar ambiguidade de automação:** §3 lista Burp Intruder 'não massivo' simultaneamente com proibição de fuzzer/crawler e execução manual. Fixar apenas navegação/requisições individuais deliberadas via Repeater, sem execução automatizada de lote/Intruder ou força bruta.
4. **Reconduzir H4 a test users próprios:** sua evidência mínima atual cita PII de *outro usuário*, ao passo que §5 exige STOP imediato ao encontrar PII de cliente. Investigar somente dados de contas de teste controladas, sem coleta de terceiros; eventual PII acidental = parada e minimização.
5. Após correções **registrar novo SHA/commit do plano** e reapresentar revisão QA+JEV sobre os trechos efetivos alterados. A aprovação do Portão A não precisa ser reaberta se escopo, política e restrições não mudarem.

**Não houve teste ativo nem alteração de produção por este QA. `execution=STOP` até Portão B PASS.**
