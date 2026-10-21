# h1_meli_onda10 — staging OFFLINE de payloads (H-ORDER10.1)

Espec: docs/H1-MELI-SPEC-V10.md · Matriz: C1 (A comprador) / C2 (C vendedor) / X1 (B terceiro).
100% OFFLINE — nenhum request emitido nesta preparação. Envio exige emissor OpenCode + GATE QA+JEV.

## Placeholders
- $ORDER_ID   = pedido real de A (compra no anúncio de C, cartão teste APRO)
- $AUTH_TOKEN_A / $AUTH_TOKEN_B / $AUTH_TOKEN_C = tokens de sessão de cada test user
  ($AUTH_TOKEN_C adicionado: necessário para o C2; não listado na missão)

## Limites constitucionais (fixos)
- User-Agent FIXO (idêntico nos 3 templates): Chrome/126 Linux desktop — não alterar entre C1/C2/X1.
- Cabeçalhos exatos: Host, User-Agent, Accept, Authorization. Apenas leitura (GET). Sem cookie/x-csrf (leitura por Bearer na API).
- Orçamento de requisições: Teto estrito de 10 requisições para toda a Onda 10 (incluindo setup do vendedor C, publicação do item de teste, checkout simulado no navegador e as 3 requisições manuais GET de sonda C1/C2/X1). Teto de taxa: 60/host/h, execução estritamente serial.
- Parada imediata (fail-closed): 429, 403 anômalo, WAF ou menção a cobrança real.

## Inspeção (leitura local)
```bash
# listar a estrutura
find engagements/burp_lane/h1_meli_onda10 -type f -not -path '*/templates/*'
# conferir placeholders sem segredo embutido (staging é puro)
grep -rE '\$(ORDER_ID|AUTH_TOKEN_[ABC])' engagements/burp_lane/h1_meli_onda10/templates
# validar sintaxe raw HTTP (sem envio): head -1 de cada template
for f in engagements/burp_lane/h1_meli_onda10/templates/*.req; do head -1 "$f"; done
# confirmar User-Agent idêntico nos 3
grep -i '^User-Agent:' engagements/burp_lane/h1_meli_onda10/templates/*.req | sort -u
# integridade dos templates via SHA-256
sha256sum engagements/burp_lane/h1_meli_onda10/templates/*.req
```

## Ordgem de uso (quando autorizado, por OpenCode APENAS)
C1 -> C2 -> X1, serial. Registar ledger de requests + hash das respostas brutas.
