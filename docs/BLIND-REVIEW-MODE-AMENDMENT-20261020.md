# MITR3 — Emenda de modo de revisão (v3/v4)

**Data:** 2026-10-20 · **Autoridade:** Kai (operador humano, dono do protocolo) · **Maestro:** OpenCode

## Decisão registrada

Kai autoriza que a revisão dos conjuntos cegos v3/v4 seja executada por **QA (GPT-6) + JEV em trilha shadow**, em substituição ao segundo revisor humano externo designado no pacote `MITR3-REVIEWER2-PACKET-V3V4-20261020.md`.

- A permissão é humana, explícita e datada; está registrada aqui como autorização do operador.
- O pacote de revisão permanece o mesmo: 40 observações, 20 claims, rubrica 0/1/2, S/P/N/C/U, sem gabarito.
- GPT-6 e JEV produzem pareceres em **trilhas separadas e congeladas** antes de qualquer comparação.
- Nenhum dos dois vê as notas do outro antes do congelamento.
- Divergência entre as trilhas (inclusive 2 pontos na escala) retorna a Kai como adjudicação humana — a emenda substitui o revisor 2 dedicado, não o poder de decisão final.

## O que NÃO muda

- Gabaritos (expected_answer/expected_ids/forbidden_ids) continuam fora do alcance de QA/JEV durante a revisão.
- v5 permanece congelado e intocado; não é usado para calibrar juiz nem prompt.
- Gate D de produção permanece congelado.
- Nenhuma nota emitida por LLM entra como prova em relatório HackerOne (runbook H1-5 segue valendo).

## Rastreabilidade

- Pacote: `docs/MITR3-REVIEWER2-PACKET-V3V4-20261020.md` (sha `01b63b59…`).
- Trilha JEV: relatório a ser gerado por `jev_evidence` (megabrain MCP, provider typesafe, `jev-latest`), congelado com sha256.
- Trilha GPT-6: parecer entregue via Arch por GPT-6, congelado com sha256 na chegada.
- Comparação somente após ambos os shas registrados.
