# MITR3 — disposição do QA para as divergências D1–D4
**Data:** 2026-10-20 · **Emissor:** GPT-6, QA externo · **Para:** OpenCode (maestro) e operador humano.
**Tipo:** aprovação técnica da opção (a) na dimensão **correção factual da claim**. **NÃO** é assinatura do operador nem confirmação de execução de sonda não testemunhada.

## Decisão

**APROVO manter as notas 2 atribuídas pelo GPT-6 para D1, D2, D3 e D4 na dimensão CORREÇÃO FÁTICA em relação à fonte primária**, condicionando a resolução do ciclo de QA a manter **separadamente** a suficiência da evidência que chegou ao JEV. Os alertas da trilha JEV não são anulados. A aprovação NÃO promove o Gate D, não autoriza deploy, não declara JEV errado e NÃO configura consentimento humano delegado para assinatura da folha de adjudicação.

| Divergência | Claim | Nota QA factual | Avaliação da evidência transmitida / JEV | Disposição técnica |
|---|---|---:|---|---|
| D1 | `v4p2-06c2` — distinção poisoning/deception no contexto de unkeyed | **2** | **INCOMPLETA** para o vínculo completo: quote local apenas diz que poisoning e deception são distintos; não estabelece sozinha o vínculo com unkeyed inputs. JEV `0.32` com packet e `0.73` em evidência enriquecida conforme sonda **relatada** por OpenCode. | Manter QA 2 factual; preservar flag de suporte insuficiente no pacote; priorizar enriquecimento da fonte. |
| D2 | `v3p2-03c1` — CVE-2023-2868 ESG/tar | **2** | **SUFICIENTE** no trecho local para identificação do problema; JEV `0.79`, próximo ao limiar operacional 0.8, sem evidência de erro material. | Manter QA 2, registrar discrepância de limiar; não rotular JEV como falso positivo por 0.01. |
| D3 | `v4p1-03c1` — divergência de normalização de URL | **2** | **RESUMIDA** no trecho da ficha CASE. Mecanismo completo depende do estudo original, condições e configuração do cache. JEV `0.63`. | Manter QA 2 factual; manter flag de qualidade insuficiente do trecho transmitido e condicionais. |
| D4 | `v4p1-06c2` — unkeyed inputs/poisoning | **2** | **RESUMIDA** no trecho da ficha CASE: evidencia influência fora da cache key, mas não carrega todos os detalhes causais; JEV `0.63`. | Manter QA 2 factual; preservar advertência e solicitar melhor amostra de evidência. |

## Fontes primárias verificadas
- Barracuda ESG `CVE-2023-2868`: https://trust.barracuda.com/security/esg-vulnerability (arquivo .tar, validação de nomes, injeção de comandos).
- PortSwigger, James Kettle, *Practical Web Cache Poisoning* (2018): https://portswigger.net/research/practical-web-cache-poisoning. Descreve unkeyed inputs, cache keys, poisoning e menciona a distinção frente a web cache deception.
- PortSwigger, Martin Doyhenard, *Gotta cache 'em all* (2024): https://portswigger.net/research/gotta-cache-em-all. Descreve discrepâncias de parsing/normalização entre caches e origem e consequências de cache poisoning/deception.

## Distinções e riscos que devem ficar visíveis
1. **Duas dimensões, não uma:** `source_factually_correct=2` versus `packet_entailment=S|P|N|C|U`. Não renomear o score do JEV como erro ou evidência de correção.
2. As quotes do v4 **são substrings literais das fichas CASE resumidas**, mas a própria ficha CASE é uma **paráfrase condensada** das fontes externas originais. Portanto, não afirmar que o Gate D aceitou citações não literais; o problema é **perda de informação na fonte empacotada**.
3. Somente D1 possui um A/B de enriquecimento mencionado na folha; a extensão da causa a D3/D4 é hipótese técnica forte, não experimento causal confirmado item a item.
4. A sonda `0.32/0.34→0.73` aparece na folha do maestro, sem transcript bruto nem metadados de requisição neste pacote. Este QA verificou o **registro** e sua coerência com as fontes, não reexecutou chamadas remotas ao JEV.
5. Os relatórios v3/v4 permanecerão congelados; não usar suas perguntas para ajuste iterativo de candidato. `v5` continua selado. A comparação futura só é válida se baseline/candidato, rubrica, corpus, modelo, seeds, custo/latência e limites estiverem registrados **antes** da rodada.
6. A emenda `BLIND-REVIEW-MODE-AMENDMENT` reserva a **assinatura da adjudicação humana** ao operador. Esta nota é o *OK do QA* que o maestro solicitou; não assinar por ele.

## Próxima ação do maestro
- Registrar a disposição técnica D1–D4 na folha SEM apagar a avaliação JEV ou subscrever assinatura humana.
- Pedir ao operador a adjudicação humana formal, se ainda não registrada. Se a assinatura já for comprovada, consolidar a conclusão da revisão v3/v4.
- Separadamente, desenhar em **branch DEV** enriquecimento com trechos primários de fonte de confiança, mantendo quotes verificáveis na janela **efetivamente fornecida ao compositor** e SHA256/namespace. Não estender arbitrariamente a janela sem política de orçamento, privacidade e controles anti-injeção.
- Somente então congelar candidato e métricas pré-registradas para v5. Gate D em produção fica INALTERADO.

## Integridade das bases
- Folha do maestro `docs/ADJUDICATION-SHEET-V3V4-20261020.md`: SHA256 `c20d6c722b5b6e1e459b3ea933aad7fc13b166646e982461b2ca7a0bb1785b9a`.
- Laudo QA `docs/GPT6-EVIDENCE-QA-V3V4-20261020.md`: SHA256 `a34ff6654610ba3e3faae292df6c9fefbc870ae81049c8f5299320298aaf1b55`.
- Reconciliação `docs/GPT6-JEV-QA-RECONCILIATION-20261020.md`: SHA256 `72b07c8cee8494a2fe27a4353dad42a6770ed0f6b1040633f6a0de43441c87ab`.
- Relatório JEV `reports/jev-v3v4-review-20261020.json`: SHA256 `be496a1d053b77b9c9aec665948a91554bca7007cb9d307c7d9a8757e92c05be`.
