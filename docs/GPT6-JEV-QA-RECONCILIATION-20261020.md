# MITR3 — reconciliação GPT-6 QA × JEV (v3/v4)
**Data:** 2026-10-20. **Maestro:** OpenCode. **Status:** comparação pós-laudo; não é benchmark humano nem deploy.
**Arquivos congelados:**
- Parecer QA: `docs/GPT6-EVIDENCE-QA-V3V4-20261020.md` — SHA256 `a34ff6654610ba3e3faae292df6c9fefbc870ae81049c8f5299320298aaf1b55`.
- Trilha JEV: `reports/jev-v3v4-review-20261020.json` — SHA256 `be496a1d053b77b9c9aec665948a91554bca7007cb9d307c7d9a8757e92c05be` (também consta em Git `4a64d97`).

## Protocolo e limitação
- JEV registra `provider=typesafe`, `model=jev-latest`, scores `p` 0–1, decisões referenciadas por digest e `nr`. Estes scores **não são probabilidades calibradas nem provas de que uma chamada remota foi feita**; o registro prova somente que o artefato foi salvo e versionado.
- JEV possui 7 classificadas como supported, 12 parciais/alertadas, 1 unsupported; 8 need_review.
- QA documental: 11 claims nota 2; 9 claims nota 1; 0 nota 0. São 20 claims EMITIDAS (repetição de perguntas), não 20 casos independentes.
- A emenda aceita GPT-6 + JEV em vez de revisor humano 2. **Falha de cegamento:** GPT-6 teve contato com scores do JEV antes de congelar o parecer; sua revisão foi reexecutada com provas externas e snippets, mas a independência cega perfeita não pode ser reivindicada. Conflitos exigem decisão de Kai ou revisor humano sem acesso às notas prévias.
- Nenhum avaliador usou o gabarito; v5 permanece intacto.

## Divergências pontuais (QA 2 vs JEV < 0,8)
| ID | Nota QA | Banda JEV / score | Evidência e proposta de adjudicação |
|---|---:|---|---|
| `v3p2-03c1` | 2 | parcial, 0.79 | CVE-2023-2868: tar/ESG e injeção de comando constam do comunicado da Barracuda. Um ponto abaixo do limiar 0.8 não prova falsidade. Conferir [fabricante](https://trust.barracuda.com/security/esg-vulnerability). |
| `v4p1-03c1` | 2 | parcial, 0.63 | Discrepâncias entre normalização de URL de cache e origem estão na ficha CASE e no estudo [PortSwigger 2024](https://portswigger.net/research/gotta-cache-em-all). Verificar se a claim é absoluta ou condicionada à configuração. |
| `v4p1-06c2` | 2 | parcial, 0.63 | Explicação de inputs unkeyed e cache key sustentada pelo resumo CASE e [PortSwigger 2018](https://portswigger.net/research/practical-web-cache-poisoning). Distinguir condição de risco de evidência de exploit num alvo. |
| `v4p2-06c2` | 2 | unsupported, 0.32 | **Divergência prioritária.** O CASE local `CASE-ps-practical-cache-poisoning-2018` contém literalmente 'Distingue cache poisoning de cache deception'; artigo [PortSwigger 2018](https://portswigger.net/research/practical-web-cache-poisoning) separa os ataques. Revisor humano verifica se classificação JEV é falso negativo e se houve perda de snippet/contexto enviado. |

**Não alterar os dois arquivos-base para conciliar notas.** O maestro solicita esclarecimento do JEV em fixture DEV separada ou revisão humana e registra a decisão em documento novo. Não retreinar o juiz ou promover o Gate D usando v3/v4/v5.

## Achados adicionais de QA, independentemente de concordância
1. OWASP V6.2.4 (3.000 comuns) **não substitui** V6.2.12 (senhas vazadas, L2): v3p1-05c1 e v3p2-05c1 têm salto inferencial. [ASVS](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md).
2. Em `v3-07`, o enunciado diz dois módulos RSA com fator comum, enquanto o write-up de [JerseyCTF VI](https://ctftime.org/writeup/41140) usa `gcd(n, relay_fingerprint)`; não é a mesma premissa. V4-05 também trata 'relay' como se fosse ataque de rede, mas o caso identifica artefato/terminal de retransmissão. Congelar itens históricos, sinalizar ambiguidade em futuras fixtures.
3. v4p1-03c2 mistura efeitos de cache deception e poisoning; no artigo original há seções distintas. A nuance importa na interpretação de impacto.
4. `DOCUMENT_IDENTITY`, `MODEL_TIMEOUT`, `MODEL_FAILED`, `QUOTE_NOT_LITERAL` e `MODEL_ABSTAIN` devem permanecer tipos separados na avaliação; erro operacional não equivale a resposta falsa.
5. Nenhum dos documentos revisados comprova exploração de alvos HackerOne. Programa/escopo/PoC humana específicos são necessários antes de qualquer relatório.

## Ordem para OpenCode
- Manter Gate D de produção inalterado e v5 congelado.
- Enviar quatro divergências para decisão humana ou investigação independente de JEV em DEV, registrando evidência por claim e não só score.
- Concluir revisão semântica e causas de abstenção sem que o autor de ajuste leia gabarito e sem calibrar sobre v3/v4/v5.
- Devolver resumo de adjudicação com assinaturas/digests; só então avaliar candidato e execução pareada no v5, com protocolo antecipadamente definido.
