# MITR3 — Threat Model H-ORDER10.1

FASE 5 — Análise conceitual

Alvo: API de Pedidos do Mercado Livre Referência: HackerOne #33462 (escopo específico não verificado) Vulnerabilidade investigada: BOLA / Broken Object Level Authorization Método: controles positivos C1/C2 + controle negativo X1 Classificador: JEV em modo shadow, com validação QA

## 1. Modelo de identidades e permissões

| Ator | Identidade     | Papel     | Acesso esperado           |
| ---- | -------------- | --------- | ------------------------- |
| A    | `3780339606`   | Comprador | Próprio pedido            |
| C    | Novo test user | Vendedor  | Venda associada           |
| B    | `3780339608`   | Terceiro  | Sem acesso ao pedido de A |

Invariante fundamental:

\\[ \operatorname{CanRead}(B,O_A)=false \\]

A autorização deve ser avaliada novamente para cada objeto e sub-recurso, independentemente da autenticação válida de B.

## 2. Matriz de superfícies BOLA

As rotas abaixo são documentadas publicamente. Uma superfície de análise não representa uma vulnerabilidade comprovada.

| Superfície       | Referência de API                                  | Risco conceitual                                                              | Validação esperada                              |
| ---------------- | -------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------- |
| Pedido principal | `GET /orders/{id}`                                 | Autorização baseada apenas em sessão, sem vínculo ao pedido                   | Validar comprador/vendedor                      |
| Shipments        | `/orders/{id}/shipments` e `/shipments/{id}`       | Autorização do envio desacoplada da autorização do pedido                     | Validar vínculo entre pedido, envio e ator      |
| Billing info     | `/orders/billing-info/{site_id}/{billing_info_id}` | Controle de acesso fiscal diferente do controle do pedido                     | Restringir dados fiscais aos atores autorizados |
| Notes            | `/orders/{id}/notes`                               | Notas privadas do vendedor expostas a identidades externas                    | Validar escopo e propriedade da nota            |
| Feedback         | `/orders/{id}/feedback`                            | Exposição de opiniões ou mensagens além da visibilidade permitida             | Aplicar política por papel e campo              |
| Claims           | `/post-purchase/v1/claims/{claim_id}`              | Relação entre reclamação, pedido e participantes validada de forma incompleta | Validar participantes e escopo da reclamação    |
| Orders Search    | `/orders/search`                                   | Resultados de busca com filtragem de autorização inconsistente                | Verificar autorização por item retornado        |

A documentação confirma as rotas de pedidos, notas, feedback, envios e reclamações.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers

+3



Atenção ao billing info: a rota legada `/orders/{order_id}/billing_info` está depreciada; o fluxo atual documentado utiliza um identificador próprio de faturamento. Isso torna especialmente importante verificar a associação entre pedido, documento fiscal e usuário.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers



Atenção aos claims: a documentação utiliza `/post-purchase/v1/claims/...`, não necessariamente `/orders/{id}/claims`.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers



## 3. Matriz de discrepâncias REST × BFF × GraphQL

As superfícies BFF `/vendas/api/...` e resolvers GraphQL são tratadas como hipóteses arquiteturais, não como endpoints confirmados ou autorizados para teste.

| Vetor conceitual    | Possível divergência                                               | Invariante de segurança                                       |
| ------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------- |
| REST × BFF Web      | Políticas diferentes para o mesmo objeto                           | Mesmo principal e objeto devem produzir direitos equivalentes |
| REST × Mobile       | Representações distintas com exposição desigual                    | Cada canal deve aplicar ACL independentemente                 |
| GraphQL resolvers   | Autorização na consulta principal, mas não em objetos relacionados | Cada resolver protegido valida o principal                    |
| Agregação BFF       | Dados retornados de vários serviços com permissões distintas       | A agregação preserva a interseção das permissões              |
| Cache compartilhado | Dados privados associados a contexto de autorização incorreto      | Cache deve isolar respostas por identidade e permissão        |
| Paginação e buscas  | Filtragem de ACL aplicada de modo inconsistente                    | Todos os itens retornados satisfazem a política               |
| Versões de API      | Migração altera campos disponíveis                                 | Versões antigas e novas preservam a autorização               |

Critério de discrepância:

\\[ \operatorname{ACL}(REST,O,U) = \operatorname{ACL}(BFF,O,U) = \operatorname{ACL}(GraphQL,O,U) \\]

A igualdade se refere à decisão efetiva de autorização, não à igualdade literal dos payloads. A visão do comprador pode diferir da visão do vendedor.

A comparação entre canais deve ocorrer apenas quando ambos estiverem explicitamente no escopo autorizado.

## 4. Critérios para diferenciar BOLA, dados públicos e scaffolding

| Evidência observada em X1                         | Interpretação                                               | Resultado                  |
| ------------------------------------------------- | ----------------------------------------------------------- | -------------------------- |
| HTTP 200 com catálogo público                     | Não comprova dados privados                                 | Não é BOLA                 |
| HTTP 200 com corpo vazio/genérico                 | Possível scaffolding                                        | Exige controles adicionais |
| HTTP 200 com marcador privado exclusivo de A      | Potencial vazamento real                                    | Candidato a TRUE_BOLA      |
| HTTP 403 sem vazamento, B validamente autenticado | Negação de acesso                                           | SECURE_ENFORCEMENT         |
| HTTP 404 com C1 também inválido                   | Objeto ou fixture não comprovado                            | INCONCLUSIVE               |
| HTTP 200 idêntico para A, B e C                   | Possível comportamento universal de sandbox                 | Não confirma BOLA          |
| HTTP 206 com dados parciais                       | Resposta incompleta; autorização ainda precisa ser avaliada | Verificar conteúdo         |

A API Orders pode retornar `206 Partial Content` quando alguns campos não estão disponíveis. Portanto, esse status também não permite inferências isoladas sobre autorização.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers



### Invariantes obrigatórios do JEV

- INV-B01: C1 comprova o pedido real pertencente a A.
- INV-B02: C2 comprova a relação legítima do vendedor C com a venda.
- INV-B03: B está autenticado independentemente e não possui permissão sobre o objeto.
- INV-B04: X1 usa o mesmo objeto e operação comparável de C1.
- INV-B05: Marcadores privados são definidos antes da análise e não são meros reflexos dos parâmetros da requisição.
- INV-B06: Dados de catálogo público nunca são classificados como PII privada.
- INV-B07: Respostas genéricas de sandbox não sustentam achados positivos.
- INV-B08: A exposição é reproduzível, sem mistura de sessões ou contaminação de cache.
- INV-B09: Evidências são correlacionadas por identificadores de execução e SHA-256.
- INV-B10: QA e Maestro aprovam qualquer achado antes da emissão.

## 5. PoC minimalista, não destrutiva

FLUXO DE VALIDAÇÃO

G0 — Escopo HackerOne aprovado

Somente contas, ativos e dados próprios autorizados

C1 — Comprador A

Baseline positivo

Pedido próprio

C2 — Vendedor C

Baseline positivo

Venda vinculada

G1 — Validação dos controles

Propriedade, identidade e fixture confirmados

X1 — Terceiro B

Uma leitura controlada do mesmo pedido de teste

G2 — Classificador JEV + QA

TRUE_BOLA

SECURE_ENFORCEMENT

NEGATIVE_SCAFFOLDING

INCONCLUSIVE

### Procedimento

1. Verificar a política vigente do programa HackerOne e obter autorização para os recursos envolvidos. Não consegui confirmar que a referência `#33462` constitui autorização específica.
2. Criar um único pedido entre A e C, com identificadores e dados sintéticos.
3. Registrar C1 e C2 mediante leituras legítimas e guardar somente as evidências necessárias.
4. Executar X1 exclusivamente com B, sem enumeração de pedidos, coleta de terceiros ou alteração de estado.
5. Classificar a resposta, reproduzir minimamente um possível positivo e interromper a investigação assim que houver prova suficiente.
6. Submeter o relatório com evidências redigidas, contexto, limitações e resultado QA.

O HackerOne exige respeito à política particular de cada programa, proíbe testes inseguros sem autorização e orienta que relatórios não incluam PII de terceiros.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.hackerone.com\&sz=32)

HackerOne

+1



## 6. Critério de emissão de achado

```
TRUE_BOLA_CONFIRMADO =
    G0_SCOPE_APPROVED
    AND G1_BASELINE_VALID
    AND B_UNAUTHORIZED
    AND PRIVATE_DATA_PROVEN
    AND INDEPENDENT_REPRODUCTION
    AND G2_QA_APPROVED
    AND HUMAN_GATE_APPROVED
```

Se qualquer condição obrigatória falhar, o JEV deve bloquear a emissão de `TRUE_BOLA`.

### Conclusão para o MITR3

A investigação H-ORDER10.1 deve priorizar consistência de autorização entre o pedido principal, os sub-recursos e suas representações em diferentes canais.

O risco arquitetural central é uma decisão de autorização correta no recurso principal não ser preservada durante o acesso a dados relacionados.

Estado da hipótese: `NOT_CONFIRMED`. A matriz identifica pontos de revisão, mas não constitui evidência de vulnerabilidade no Mercado Livre.
