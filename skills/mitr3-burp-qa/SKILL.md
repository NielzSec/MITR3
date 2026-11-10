---
name: mitr3-burp-qa
description: QA de evidências Burp Suite via exportação XML sanitizada, com um único operador live e demais agentes offline.
---

# MITR3 — Burp Suite Squad Bridge (OFFLINE para agentes)

**Leia:** `docs/MITR3-BURP-SQUAD-WORKFLOW-20261021.md` e a política do programa em `docs/H1-0-MERCADOLIBRE-SPEC-20261020.md`.

## Princípios de autoridade
- **OpenCode** é o único operador do navegador/Burp/Repeater com requisições **individuais e manuais**. Burp Proxy HTTP History pode ser consultado passivamente, mas criar e disparar requisição requer gate.
- **Codex, VANTA, Hermes e JEV:** não usam Burp MCP completo nem cookies/sessões. Apenas report derivado de `bin/mitr3-burp-qa.py` e evidência primária redigida por pessoa autorizada.
- O cliente Burp MCP oficial possui ferramentas de execução (HTTP/Intruder) e leitura de histórico potencialmente sensível. **NÃO ativar/vincular** esse MCP a agentes múltiplos; não expor porta por rede/Tailscale; não auto-aprovar alvos, nem permitir edição de configuração.
- **Não rodar loaders/keygens** presentes em Downloads ou Tools; somente instalação Burp oficial licenciada ou Community verificada.

## Protocolo mínimo
1. OpenCode conduz navegação controlada (sessões isoladas A/B) e Repeater manual, sem Intruder/Scanner/crawl/race/pagamento.
2. O export Burp *bruto* fica em `engagements/H1-MELI/artifacts/` (gitignored, modo 0600, diretório 0700). Arquivo XML pode guardar segredos inclusive em BASE64; jamais colar/mostrar ao LLM.
3. Selecionar poucas mensagens (1 a 6) e exportar via `Save items`. Nomear controle e tratamento por hipótese (A-control.xml, B-test.xml).
4. Extrair metadados sem exposição de valores:
   ```bash
   cd ~/MITR3
   chmod 600 engagements/H1-MELI/artifacts/A-control.xml engagements/H1-MELI/artifacts/B-test.xml
   python3 bin/mitr3-burp-qa.py \
     --input A-control=engagements/H1-MELI/artifacts/A-control.xml \
     --input B-test=engagements/H1-MELI/artifacts/B-test.xml \
     > engagements/H1-MELI/evidence/derived-burp-summary.json
   chmod 600 engagements/H1-MELI/evidence/derived-burp-summary.json
   ```
5. **Auditar saída antes de compartilhar**: a ferramenta gera aliases HMAC efêmeros, contagens, status e códigos sem corpos. Sem cópia de dados de terceiro. Codex deve comparar resposta real no canal local seguro e confirmar propriedade/efeito; apenas derivado vai aos outros agentes.
6. JEV avalia claims com evidência, não transforma HTTP 200 nem string refletida em prova. Abster se não houver estado antes/depois e confirmação de objeto/dono.

## Antifalso-positivo
- `address_id` foi retratado; a sessão B exibiu seu próprio objeto.
- L1/L-B2: 400 e error_catalog_code 84 indicam falha semântica na variante, não uma prova geral de ACL.
- L-B1: comparar campos de preço/quantidade e frete por aliases **no response do backend de review**, nunca somente total da UI, `cho_id` ou HTTP 200. Se HTML não-JSON, o extrator registra `not_json` e demanda revisão manual independente.
- Classes hipotéticas publicadas em `knowledge/research-patterns/casebook-v1.json` não são evidência de falha atual.

## Stop
O limite conservador local é 60 req/host/h incluindo navegação, sem concorrência, sem batch. Parar em 429, 403 inesperado, WAF/captcha, 5xx em sequência, PII de terceiro, mudança de escopo, efeitos financeiros/externos. Nenhuma PoC live é liberada por esta skill.
