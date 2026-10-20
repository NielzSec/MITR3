# H1-MELI-TIER3-PLAN — MercadoLibre credential/document exposure (passive)

**Data:** 2026-10-20 (UTC) · **Operador:** Robin · **Escopo:** H1 program 33462 · **Fase:** 3/6
**Regra:** passivo · sem acesso/validação/exfiltração · bounty por local de origem · confirmação não-destrutiva (1 chamada) após Portão B

---

## 1 · Método

1. **Levantamento de surface** — enumerar subdomínios via CRT.sh (certificados TLS) dos domínios no escopo H1 para identificar infraestrutura interna que possa vazar credenciais.
2. **Busca pública indexada** — GitHub (search API + web-indexed), paste sites (Pastebin, 0x0, dpaste), Google dorking em `site:pastebin.com mercadopago`, arquivos JSON/XML/YAML expostos com padrões `mercadopago.com`, `mercadolibre.com`, `MELI_APP_ID`, `CLIENT_SECRET`, `access_token`, `MERCADO_PAGO`.
3. **Documentação pública** — verificar se SDKs ou integrações de terceiros expõem credenciais em repositórios públicos, vs. placeholderslegítimos.
4. **Cross-check** — confirmar vínculo com `@mercadolibre` / `@mercadopago` (organização, domínio no código-fonte, README vinculado); qualquer achado sem vínculo é descartado.

**Nunca:** acessar o valor de qualquer segredo encontrado · fazer login em qualquer sistema · usar credenciais · exfiltrar dados · brute-force · fuzzing automatizado.

---

## 2 · Fontes consultadas (resultados desta rodada)

### CRT.sh — certificados TLS (domínios do escopo)
| Domínio | Status | Observação |
|---|---|---|
| `api.mercadopago.com` | ❌ 502 upstream indisponível | plano dry-run registrado; não houve dados |
| `api.mercadolibre.com` | ❌ 502 upstream indisponível | idem |
| `mercadolibre.com` | ❌ 502 upstream indisponível | idem |
| `mercadopago.com` | ❌ 502 upstream indisponível | idem |
| `www.mercadolibre.com` | ❌ 502 upstream indisponível | idem |

*CRT.sh indisponível na janela; subdomínios internos não puderam ser enumerados nesta rodada.*

### GitHub — busca por credenciais vinculadas (via websearch indexação pública)
| URL | Tipo | Vínculo | Observação |
|---|---|---|---|
| `github.com/mercadopago/mercadopago-mcp-server` | SDK público (MCP Server) | ✅ organização oficial | README mostra `<ACCESS_TOKEN>` em placeholder config JSON — **placeholder**, não secreto real |
| `github.com/mercadopago/sdk-python` | SDK oficial Python | ✅ organização oficial | `client_id_example`, `client_secret_example` — **placeholders legítimos** |
| `github.com/mercadopago/sdk-nodejs` | SDK oficial Node.js | ✅ organização oficial | `YOUR_ACCESS_TOKEN` / `<ACCESS_TOKEN>` — **placeholders** |
| `github.com/mercadopago/sdk-php` | SDK oficial PHP | ✅ organização oficial | `APP_USR-...` no código — **padrão de formato**, não valor exposto |
| `github.com/mercadopago/sdk-js` | SDK oficial JS | ✅ organização oficial | `YOUR_PUBLIC_KEY` — **placeholder público** |
| `github.com/mercadopago/mercadopago-claude-marketplace/blob/main/SECURITY.md` | Doc segurança | ✅ organização oficial | Alerta para rotar secret imediatamente se exposto — **documentação de resposta a incidentes**, não segredo |
| `github.com/mercadolibre/demo-mercadopago-mcp-server` | Demo MCP | ✅ organização oficial | Mostra `CLIENT_ID`/`CLIENT_SECRET` com valores de placeholder em config — **não-secretos** |
| `github.com/mercadolibre/python-sdk` | SDK oficial (descontinuado) | ✅ organização oficial | `client_id_example`, `access_token_example` — **placeholders** |
| `github.com/3l3ctr0n1c5/dx-nodejs` | Fork de SDK | ⚠️ terceiro | `ACCESS_TOKEN` hardcoded em código — analisar se é token real ou exemplo; requires confirmação sem acesso |
| `github.com/MissaelAnda/laravel-mercado-pago` | Integração Laravel | ⚠️ terceiro | `MERCADO_PAGO_ACCESS_TOKEN`, `MERCADO_PAGO_PUBLIC_KEY` em vars de ambiente — **verificar se valores reais ou example** |
| `github.com/api-evangelist/mercado-pago` | API Evangelist | ⚠️ terceiro | Não expõe credenciais; apenas docs pública |

**Nenhuma credencial real confirmada nesta rodada.** O que foi encontrado são placeholders documentais ou valores de exemplo dos SDKs oficiais.

### Paste sites (verificação direta — sem acesso, apenas planejado)
*Sem execução nesta rodada por limitação de acesso direto a pastebin.com (passivo puro via search indexado).*

| Query planejada | Fonte | Status |
|---|---|---|
| `mercadopago access_token` | Pastebin.com (search) | não executado — passivo via websearch apenas |
| `mercadopago api_key` | 0x0.ninja | não executado |
| `site:dpaste.org mercadopago` | dpaste | não executado |

---

## 3 · Candidatos a finding (requerem verificação)

| # | Localização | Tipo de artefato | Vínculo evidência | Ação de verificação (após Portão B) |
|---|---|---|---|---|
| C1 | `github.com/3l3ctr0n1c5/dx-nodejs` | `ACCESS_TOKEN` hardcoded no fonte | Fork de SDK MercadoPago · diff contra SDK oficial | 1 chamada GET `https://api.mercadopago.com/users/me` com o token (não-destrutiva) · **nunca** exfiltrar além da confirmação |
| C2 | `github.com/MissaelAnda/laravel-mercado-pago` | `MERCADO_PAGO_ACCESS_TOKEN` em config Laravel | Integração ativa · README sugere uso em produção | Verificar se o valor no repo é placeholder (comparar com patterns de token test vs. prod) sem extrair o valor |
| C3 | Pastebin/0x0/dpaste (não verificado) | Documentos de integração ou configs | search indexado para `mercadopago access_token` | Localizar via websearch · confirmar vínculo · **nunca** acessar beyond da URL/title |

---

## 4 · Limites operacionais (esta tarefa)

| Limite | Detalhe |
|---|---|
| **CRT.sh offline** | 502 upstream em todas as consultas de domínio; subdomínios internos não enumerated |
| **GitHub search bloqueado** | Rate-limit de API (sem key); websearch indexa apenas repositórios populares/thin |
| **Nenhuma credencial confirmada** | O que existe são placeholders dokumentais; C1 e C2 requerem análise deeper sem acesso |
| **Fora de escopo** | `.kangu.com.br`, `developersforum`, `Redelcom` · domínios `.cn` · Certificate Pinning/SSL bypass |
| **Não é bounty** | SDKs oficiais com placeholders não constituem exposição de credenciais de produção |
| **Regra de 1 chamada** | Após Portão B, confirmação de C1/C2 limitada a 1 request não-destrutiva por local |

---

## 5 · Próximos passos (após Portão B)

1. Obter chave CRT.sh (ou usar Censys/Virustotal) para enumerar subdomínios internos de `*.mercadolibre.com` / `*.mercadopago.com`
2. Verificar C1 (`3l3ctr0n1c5/dx-nodejs`) — diff contra SDK oficial, confirmar se `ACCESS_TOKEN` é placeholder ou real
3. Verificar C2 (`laravel-mercado-pago`) — extrair nome da variável, não o valor; comparar com padrão test `APP_USR-`
4. Executar websearch dedicado em paste sites: `mercadopago access_token pastebin`, `mercadopago secret github`
5. Se CRT.sh voltar: enumerar todos os subdomínios de `*.mercadopago.com` e `*.mercadolibre.com`

---

*Coleta passiva · nada executado · nada exfiltrado · artefatos não indexados em RAG*
