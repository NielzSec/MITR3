# Emenda — portões QA+JEV substituem o portão humano (H1)

**Data:** 2026-10-20 · **Decisão:** Kai (operador) · **Maestro:** OpenCode
**Supersede:** `docs/HACKERONE-QA-RUNBOOK-20261020.md` §1 (human gate) e §3 (H1-6 aprovação humana antes do submit).

## Decisão

O fluxo de seis fases do projeto passa a valer para o engajamento HackerOne:

1. Especificação → 2. **Clarificação (Portão A)** → 3. Plano → 4. Tarefa → 5. **Análise (Portão B)** → 6. Implementação.

Os dois portões deixam de ser assinatura humana e passam a ser **parecer técnico de QA (GPT-6) + JEV**:

- **Portão A:** QA verifica se a especificação está sem ambiguidade e se o escopo mapeia exatamente a política e o extrato estruturado da API; JEV mede a suficiência das evidências que sustentam cada afirmação de escopo. Saída: `gate-a.md` com `PASS/FAIL` e justificativa por item.
- **Portão B:** QA revisa plano/tarefas e evidências; JEV julga claim por claim. Saída: `gate-b.md` com `PASS/FAIL`; `FAIL` devolve para a fase anterior.
- **Submissão:** só ocorre com A e B em `PASS` e o relatório passando pelo mesmo par (QA revisa o texto; JEV mede a suficiência da evidência). O titular da conta HackerOne permanece `nielzsec`; o registro de autoria e a trilha de auditoria ficam no caso.

## O que NÃO muda

- As regras do programa vinculam a operação inteira: sem varredura massiva, sem DoS, sem força bruta, sem engenharia social, sem malware, sem acesso além da prova mínima.
- Evidência redigida; sem PII, tokens ou cookies em artefatos públicos.
- Toda mudança de requisito volta à especificação, nunca direto para execução.
- Nenhum gabarito/segredo em log, repositório ou índice.

## Registro de autorização

O operador autorizou o alvo MercadoLibre em 2026-10-20, forneceu a política do programa e determinou a substituição dos portões humanos por QA+JEV. A autorização de escopo é registrada como `scope_validated_by_qa_jev=true` somente após o Portão A `PASS`, com referência às evidências (extrato da API sha `349db7e2…`, política sha `74df70a9…`, veredito QA, decisões JEV).

## Critério de parada

`FAIL` em qualquer portão = `execution=STOP` para o item afetado. Violação de regra do programa = parada imediata do engajamento e registro no caso.
