# H1-0 — Especificação v1: MercadoLibre (bug bounty)

**Data:** 2026-10-20 · **Operador:** Kai (`nielzsec`) · **Maestro:** OpenCode
**Programa:** `mercadolibre` (ID 33462) · estado `open` · triage ativo · bounty ativo
**Fonte do escopo:** API HackerOne `/v1/hackers/programs/mercadolibre/structured_scopes` (sha `349db7e2…`, 25 registros) e política oficial (sha `74df70a9…`, 15.313 bytes). Cópias privadas em `~/.local/share/mitr3/h1/mercadolibre/` (0600).
**Missão:** primeiro engajamento real do time MITR3 — encontrar, validar e reportar vulnerabilidades elegíveis, começando por reconhecimento passivo e testes manuais criativos. Nenhum relatório é submetido sem os dois portões QA+JEV (emenda de 2026-10-20).

## 1. Escopo — 22 ativos elegíveis (bounty + submission)

### Aplicativos móveis
| Ativo | Tipo |
|---|---|
| `com.mercadopago.wallet` | Google Play |
| `com.mercadopago.MercadoPago` | App Store |
| `com.mercadolibre` | Google Play |
| `com.3mosquitos.MercadoLibre` | App Store |
| `com.mercadoenvios.driver` | Google Play |
| `com.mercadoenvios.crowdsourcing` | Google Play |

### APIs e URLs
| Ativo | Tipo |
|---|---|
| `api.mercadopago.com` | URL |
| `api.mercadolibre.com` | URL |

### Wildcards
| Ativo | Tipo |
|---|---|
| `*.adminml.com` | wildcard |
| `*.mercadolibre.cl` · `*.mercadolibre.com` · `*.mercadolibre.com.ar` | wildcard |
| `*.mercadolibre.com.co` · `*.mercadolibre.com.mx` · `*.mercadolibre.com.pe` · `*.mercadolibre.com.uy` | wildcard |
| `*.mercadolivre.com.br` | wildcard |
| `*.mercadopago.cl` · `*.mercadopago.com` · `*.mercadopago.com.ar` | wildcard |

### Outros
| Ativo | Tipo | Observação |
|---|---|---|
| `Point Smart` | hardware | método de teste físico precisa de definição no Gate A |
| `Crypto` | other | ativo não-URL; superfície precisa de definição no Gate A |

### Fora de escopo (submission=false)
`*.kangu.com.br`, `developersforum`, `Redelcom`.

## 2. Regras do programa que vinculam toda a operação

- **Sem varredura automatizada massiva.** Teste criativo e manual é o esperado; scanners em massa não são permitidos.
- Proibidos: DoS/DDoS, força bruta, spam, engenharia social/phishing, malware, criação massiva de contas, comprometer conta/dados de terceiros, degradar serviço, ataques físicos.
- **Test users** permitidos; para findings com essas contas, `PR` no CVSS é **High**; cartões de teste oficiais permitidos.
- Considerações de código/SAST: não subir resultado bruto de scanner; CVE/0-day só 30 dias após publicação e com PoC demonstrável pela internet; dependency confusion fora; supply-chain com pacote público e PoC válido dentro.
- **Mobile:** fora — certificate pinning/SSL, ofuscação, SafetyNet/anti-instrumentação, componentes exportados sem impacto real, deeplinks `mercadopago://in-app-browser` e `meli://in-app-browser`.
- **Subdomain takeover:** exigir prova de inserção de conteúdo + evidência DNS/HTTP; sem cookies/phishing.
- **XSS sem bypass de CSP** tem severidade reduzida/zero.
- **Tier 3 (não-aplicativo):** exposição de credenciais/documentos ligados à MercadoLibre; uma bounty por local de origem; validade pode ser confirmada com **uma** chamada não destrutiva; proibido acessar/exfiltrar além da confirmação; exige evidência de vínculo.
- Exclusões de feature: `Melidolar`, KYC (ações não monetárias sem validação), GraphQL com impacto DoS, `Collaborators`; SDK de integrações MercadoPago e secure inputs não pagam bounty; domínios `.cn` fora.
- Piso de CVSS 2.0 para low; fórmula de high/critical: `((CVSS × Tier) × 10) + bônus`.
- **Signal 1.0** no último ano é requisito; contas abaixo usam trial reports — confirmar elegibilidade da conta `nielzsec` no Gate A.

## 3. Padrão de evidência (obrigatório para qualquer finding)

1. Ativo exato + URL/endpoint + método.
2. Passos de reprodução numerados, com conta/test user identificado por rótulo (nunca credencial real).
3. Request/response redigidos (sem cookies, tokens, PII de terceiros).
4. Impacto concreto e CVSS 3.1 justificado; sem inflação.
5. Prova mínima — nada além do necessário para demonstrar a falha.
6. Hash do artefato de evidência + timestamp UTC.

## 4. Fluxo de seis fases (emenda QA+JEV)

1. **Especificação** — este documento (v1).
2. **Clarificação → Portão A (QA + JEV)** — ambiguidades resolvidas; escopo e restrições verificados contra política e extrato da API; veredito `PASS/FAIL` com evidências.
3. **Plano** — hipóteses por ativo, técnicas permitidas, ordem, taxa, critérios de parada.
4. **Tarefa** — unidades ordenadas com dono, entrada, saída e limite.
5. **Análise → Portão B (QA + JEV)** — revisão cruzada do plano/evidências; JEV mede suficiência de cada claim; `PASS/FAIL`.
6. **Implementação** — execução, evidência, relatório, submissão somente após Portão B.

Mudança de requisito volta para a especificação; nunca direto para execução.

## 5. Perguntas abertas para o Portão A

1. `Crypto` e `Point Smart`: qual é a superfície testável e o que conta como prova sem violar as restrições?
2. Mapeamento Tier 1/2/3 por ativo: a API não expõe o tier; a política cita tiers mas não a tabela por ativo — como classificar sem arbitrar?
3. Elegibilidade da conta `nielzsec` frente ao requisito de Signal 1.0 / trial reports.
4. `*.adminml.com` é infraestrutura administrativa — há restrição adicional de método (ex.: sem login bruto, sem fuzzing)?
5. Limite operacional de requisições para "teste criativo" sem caracterizar varredura massiva.
