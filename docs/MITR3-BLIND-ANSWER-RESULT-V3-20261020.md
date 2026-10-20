# Blind answers v3 — resultados mecânicos

Data: 2026-10-20 · Conjunto: `blind-answers-antigravity-v3` (commit `337d80b`,
sha256 `ba1b0f230e04fb94ea292a7c41dc55cb0d9cb4e38e3c0c582455b35c53d4e9ae`,
autor Antigravity — sidecar confere com o arquivo).
Mede as correções `d46c5b2` (queries EN na etapa A) e `161bbd3` (critério de abstenção
do compositor), implementadas APÓS o v2. Modelo: `dahl/deepseek-ai/DeepSeek-V4-Flash-0731`,
2 passadas — 10/10 resultados idênticos entre passadas (estabilidade que o v2 não tinha).

## Resultado (10 itens)

| item | tipo | resultado mecânico |
|---|---|---|
| 01–05 | respondíveis | **5/5 responderam** com citação literal + ID esperado citado; passada 1 = passada 2 |
| 06, 07 | respondíveis | DOCUMENT_IDENTITY nas 2 passadas — bug na camada de identidade (abaixo) |
| 08, 09 | controle negativo | MODEL_ABSTAIN — **abstenção correta** |
| 10 | controle negativo | NO_EVIDENCE — **abstenção correta** |

Zero IDs proibidos citados · zero NAMESPACE_MIX · zero INSTRUCTION_CLAIM/QUOTE.
Suite adversarial intacta (16/16).

## Alineação mecânica de IDs (não é nota humana)

- 01: `CVE-2024-3400` citado (esperado); cita 4 CVEs PAN-OS relacionadas além.
- 02: `CVE-2023-27997` exato.
- 03: `CVE-2023-2868` citado + aresta local `cwe_of → CWE-20`.
- 04/05: esperado `V8.2.2`/`V6.2.4`, citado `ASVS-V8.2.2`/`ASVS-V6.2.4` — diferença de
  formato de ID; juízo 0/1/2 é do revisor humano.
- IDs proibidos citados: **0** em todos os itens.

## Fratura achada: DOCUMENT_IDENTITY (06/07)

- Causa raiz: `mitr3-rag-intel.py search` tem lookup exato para ids (`CASE-…`,
  `ASVS-…`, CVE) mas normalizava a query com `strip().upper()` — o id misto
  `CASE-jctf-rsa-41140` virava `CASE-JCTF-RSA-41140` e errava por case. CVEs
  passavam porque já são maiúsculas. (Sintoma parecido com o FTS5: `-` é operador
  NOT no MATCH — lookup de id nunca deve passar por FTS.)
- Fix `bb0b83a`: `id IN (?,?)` com forma normalizada + literal. Teste de regressão
  incluído (165 testes verdes). Verificação de diagnóstico pós-fix: item 06 agora
  responde com citação; item 07 trouxe evidência e o compositor abstém (variância).
- **Medição formal desta correção: somente em v4 cego, autor novo.** O v3 é
  regressão e está congelado.

## Correção humana pendente (revisor: Kai)

Itens 01–05 têm propostas com evidência anexada; 06/07 abstiveram por erro de
camada (agora corrigido); 08/09/10 abstiveram corretamente. Gabarito com rubrica
em `evals/blind/blind-answers-antigravity-v3.json`.
