# H1 — Plano de teste web/API: MercadoLibre

**Data:** 2026-10-20 · **Autor:** OpenCode (maestro; deepseek não entregou) · **Base:** spec v4 `ad63aca`, Portão A PASS `534d5e1`
**Status:** planejamento. **Nenhum tráfego enviado.** Execução só após Portão B PASS.

## 1. Prioridade de ativos (subset do escopo de 88)

| Ordem | Ativo | Tier | Racional |
|---|---|---|---|
| P0 | `api.mercadolibre.com` | 1 | superfície de marketplace, autenticação e objetos de usuário |
| P0 | `api.mercadopago.com` | 1 | pagamentos, OAuth2, merchant management |
| P1 | `*.adminml.com` | 1 | separação administrativa; risco de BFLA/BOLA |
| P1 | `*.mercadolivre.com.br` | 1 | maior mercado; sessão e fluxo de checkout |
| P1 | `*.mercadolibre.com.ar` / `*.mercadolibre.com.mx` | 1 | variação regional de sessão/erros |
| P2 | `*.mercadolibre.com` / `*.mercadolibre.cl` / `*.mercadolibre.com.co` / `*.mercadolibre.com.pe` / `*.mercadolibre.com.uy` | 1 | XSS/CSP e redirects |
| P2 | `*.mercadopago.com` / `*.mercadopago.cl` / `*.mercadopago.com.ar` | 1 | fluxo de pagamento regional |
| — | `Crypto` | sem tier | somente `/crypto/*` em `www.mercadopago.com.mx`, `www.mercadopago.cl`, `www.mercadopago.com.br` |
| — | Point Smart | 1 | **adiado** — fora deste plano |

Tier confirmado no campo `instruction` do extrato: **todos os 14 ativos web/API citados são Tier 1**.

## 2. Hipóteses (OWASP WSTG / API Top 10)

| # | Hipótese | Ativo | Evidência mínima |
|---|---|---|---|
| H1 | BOLA/IDOR em objetos de usuário/transação | api.mercadolibre.com | dois test users, resposta do objeto do outro com campo não público, sem ação destrutiva |
| H2 | BFLA em endpoint administrativo exposto | *.adminml.com | função de admin acessível com test user comum, prova read-only |
| H3 | Falha de validação de redirect/OAuth | api.mercadopago.com | `redirect_uri` aceito fora do allowlist, sem capturar token de terceiro |
| H4 | Exposição de dados em resposta de erro/verbose | APIs | stack trace ou path interno em **conta própria de laboratório**; qualquer dado de terceiro = parada imediata |
| H5 | CSRF em ação sensível sem token/Origin | web | ação de estado replicada com test user, sem vítima real |
| H6 | XSS refletido/armazenado com bypass de CSP | web | execução em contexto do ativo, CSP violada documentada |
| H7 | SSRF em parâmetro de URL/imagem | APIs/web | callback para domínio nosso, sem varrer rede interna |
| H8 | **ADIADO** — race condition exige concorrência, proibida nesta fase | mercadopago | não testar sem método autorizado que demonstre corrida |
| H9 | Exposição de chave/token em app ou JS público | web/mobile | chave de baixo privilégio confirmada com **uma** chamada read-only |
| H10 | Subdomain takeover | wildcards | conteúdo de verificação + DNS/HTTP, sem cookies/phishing |

## 3. Técnicas

**Permitidas:** navegação manual, Burp Repeater com requisições **individuais e manuais**; sem Intruder, sem automação de lotes, test users oficiais, cartões de teste, comparação de respostas entre dois test users, análise de JS público.

**Proibidas:** scanner/crawler/fuzzer automatizado, brute force, enumeração em massa, DoS, GraphQL DoS, engenharia social, malware, criação massiva de contas, acesso a dados de terceiros, persistência, pivot, exploração além da prova mínima.

## 4. Contas e CVSS

- Test users oficiais do programa; nunca conta real de cliente.
- `PR=High` no CVSS para findings obtidos com test user.
- Cartões de teste oficiais para fluxo de pagamento; nenhum valor real.

## 5. Limites operacionais

- 60 requisições por host por hora; uma sessão; sem concorrência.
- Sem payloads em massa; um caso por hipótese.
- Sem coleta de PII; redigir tudo antes de sair da máquina.

**Parada imediata:** 429/403 repetidos, 5xx em sequência, WAF agressivo, qualquer PII de cliente, degradação, mudança de escopo/política. Registrar ativo, horário e motivo; não contornar bloqueio.

## 6. Evidência

Passos numerados; request/response redigidos (sem cookies/tokens/PII); impacto; CVSS 3.1 com justificativa; hash SHA256 do artefato; timestamp UTC. Template e validação offline: `bin/mitr3-h1.py template|validate`.

## 7. Fora deste plano

Mobile (plano próprio, Antigravity), Tier 3/leaks (plano próprio, Robin), Point Smart (adiado), Crypto fora dos três caminhos, SDK MercadoPago/secure inputs, KYC, Melidolar, Collaborators, GraphQL com impacto DoS, `.cn`.

## 8. Sequência

1. P0 API: H1, H3, H4 (read-only) — deepseek.
2. P1 adminml: H2 — deepseek + Codex (revisão de evidência).
3. P1/P2 web: H5, H6, H7 — deepseek.
4. H8: somente com test cards e cenário controlado.
5. H9/H10: passivo primeiro; confirmação read-only.
6. Cada finding → validador → Portão B (QA+JEV) → relatório.

## 9. Critério de sucesso

Finding reproduzível, dentro do escopo, com impacto demonstrável e evidência redigida; nenhuma violação de regra do programa; nenhum dado de terceiro coletado.
