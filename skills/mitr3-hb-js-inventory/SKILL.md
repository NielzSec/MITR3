---
name: mitr3-hb-js-inventory
description: Identificar referências literais a endpoints em JavaScript fornecido pelo operador, com origem, hash e cobertura. Usar para preparar inventários offline de APIs; não executa testes de rede.
---

# JS Endpoint Inventory — MITR3 Hackbots

**Missão única:** extrair referências estáticas observáveis, sem concluir vulnerabilidade ou existência do endpoint.

## Entradas
- Missão validada pelo `mitr3-hb-scope-gate`.
- Caminho JS local dentro de `~/MITR3`; SHA256 e identificação da amostra.
- Não aceitar URL remota como entrada.

## Micro-checklist
1. Validar contrato e hash do artefato.
2. Analisar exclusivamente o arquivo fornecido, sem baixar bundles adicionais.
3. Executar `python3 hackbots/tools/js_inventory.py hackbots/examples/sample.js` **somente como teste sintético**, ou trocar pelo caminho autorizado.
4. Registrar arquivo, linha, tipo de chamada e caminho encontrado.
5. Documentar resultados ignorados: templates dinâmicos, aliases, falsos positivos possíveis e clientes HTTP não reconhecidos.
6. Deduplicar por rota mantendo a origem de cada ocorrência.
7. Produzir proposta de resultado; não declarar exploração ou finding confirmado.
8. Encaminhar à revisão independente, nunca aprovar a própria evidência.

## Contrato e QA
`~/MITR3/hackbots/contracts/result.schema.json` e `tools/validate.py`.
Não expor cookies, tokens, fragments nem query strings. Não enviar requisições HTTP. Nunca elevar prioridade com base somente em nome de endpoint.
