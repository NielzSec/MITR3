---
name: mitr3-hb-evidence-review
description: Revisar cobertura, rastreabilidade, conflitos e limites de resultados Hackbots antes de qualquer aceite humano. Usar quando outro agente entregar hipóteses, achados ou inventários.
---

# Evidence Review — MITR3 Hackbots

**Missão única:** questionar as alegações do worker e pedir evidência independente.

## Micro-checklist
1. Verificar contrato da missão, checksum do artefato e o `scope_ref` quando aplicável.
2. Conferir o total esperado versus material realmente analisado.
3. Verificar que cada alegação aponta para IDs de evidências existentes.
4. Abrir o artefato de origem e testar se cada evidência realmente sustenta a alegação (entailment não é validado automaticamente).
5. Procurar explicações alternativas, artefatos sintéticos, duplicatas e falta de controles.
6. Classificar como `review_pending`, `blocked` ou `rejected`; resultado `accepted` requer aprovação humana fora do LLM.
7. Registrar limitações, desacordos e próximas verificações.

## Ferramenta offline
`python3 hackbots/tools/validate.py result RESULTADO --mission MISSAO`

O `PASS` do script confirma apenas a estrutura e vínculos locais. Não comprova autorização, impacto ou veracidade. Nunca enviar tráfego ou editar o artefato para obter aprovação.
