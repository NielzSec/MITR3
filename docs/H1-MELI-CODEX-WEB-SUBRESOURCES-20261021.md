# MITR3 — Parecer técnico: ACL dos sub-recursos Orders

Hipótese: H-ORDER10.1 — BOLA Escopo: Shipments, Billing Info e Notes Referência: documentação pública do Mercado Livre, consultada em 21/10/2026 Natureza: análise de contrato e arquitetura, sem testes ativos.

## 1. Matriz de cabeçalhos e versionamento

| Recurso                                                | Cabeçalhos documentados                                    | Obrigatoriedade e observações                                                                                                |
| ------------------------------------------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `GET /orders/{id}/shipments`                           | `Authorization: Bearer`, `X-New-Domain: true`              | OAuth obrigatório. `X-New-Domain` direciona para Hosted View; documentado como necessário para chamadas públicas dessa visão |
| `GET /shipments/{id}`                                  | `Authorization: Bearer`, `x-format-new: true`              | Ambos obrigatórios no contrato atual; `x-format-new` passou a ser exigido em todas as chamadas de Shipments desde 12/10/2025 |
| `GET /orders/{id}/billing_info`                        | `Authorization: Bearer`; historicamente `x-version: 2`     | Endpoint legado depreciado. Não recomendado para novas validações                                                            |
| `GET /orders/billing-info/{site_id}/{billing_info_id}` | `Authorization: Bearer`; verificar versão da representação | Endpoint atual recomendado. O `billing_info_id` deve ser obtido do pedido legítimo                                           |
| `GET /orders/{id}/notes`                               | `Authorization: Bearer`                                    | Nenhum cabeçalho adicional obrigatório foi identificado na documentação específica para leitura                              |

Fontes oficiais: Orders/Shipments&#x20;

[image](https://www.google.com/s2/favicons?domain=https://global-selling.mercadolibre.com\&sz=32)

Mercado Livre Global Selling

+1

, Billing Info&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers

+1

&#x20;e Notes&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers

.



### Distinções importantes

- `X-Caller-Id`: aparece na documentação de outras APIs do Mercado Livre, mas não identifiquei exigência pública universal desse cabeçalho para os três recursos analisados. Não se deve presumir que ele é obrigatório nem usá-lo para declarar outra identidade.
- `X-New-Domain`: controla a seleção da representação hospedada de `/orders/{id}/shipments`. A Hosted View retorna uma lista, inclusive quando existe apenas um envio.
- `X-Api-Version: 2`: é opcional na visão anterior de `/orders/{id}/shipments`, com implicações para campos pessoais retornados. Não é equivalente a `x-format-new: true`.
- `x-version: 2`: pertence ao versionamento de Billing Info; não deve ser confundido com `X-Api-Version` de Shipments.&#x20;

  [image](https://www.google.com/s2/favicons?domain=https://global-selling.mercadolibre.com\&sz=32)

  Mercado Livre Global Selling

  +1



O princípio é validar cada requisição com o contrato oficial de sua própria rota, sem transportar automaticamente cabeçalhos de uma API para outra.

## 2. Como separar erros de contrato de autorização

| HTTP / erro | Causa possível                                            | Tratamento no JEV        |
| ----------- | --------------------------------------------------------- | ------------------------ |
| `400`       | ID inválido, parâmetro incompatível ou contrato incorreto | `SCHEMA_ERROR`           |
| `401`       | Token inválido, ausente ou caller não identificado        | `AUTHN_ERROR`            |
| `403`       | Falta de permissão funcional ou autorização sobre objeto  | `DENIED_CANDIDATE`       |
| `404`       | Objeto inexistente, rota legada ou ocultação por ACL      | `AMBIGUOUS_404`          |
| `204`       | Pedido sem envio associado ou propagação pendente         | `NO_CONTENT`             |
| `200`       | Resposta válida, possivelmente genérica                   | Validar conteúdo e posse |

A documentação oficial confirma que a ausência de permissão funcional pode produzir `403` com código `PA_UNAUTHORIZED_RESULT_FROM_POLICIES`, enquanto `/orders/{id}/shipments` pode retornar `204` durante a associação assíncrona do envio.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developers.mercadolivre.com.br\&sz=32)

Mercado Livre Developers

+1



Regra: uma resposta negativa de terceiro só comprova enforcement quando a requisição equivalente do proprietário funciona, a sessão do terceiro está válida e o contrato da API foi satisfeito.

## 3. Arquitetura recomendada — autorização por relação com o objeto

Adotar ReBAC (Relationship-Based Access Control), combinada com RBAC para permissões funcionais e ABAC para atributos e estados do recurso.

API Gateway / OAuth

Token validado · Identidade autenticada

Policy Decision Point

Principal + Operação + Recurso + Relação

Orders

Buyer / Seller

Shipments

Order / Pack

Fiscal / Notes

ACL específica

### Política conceitual

```
def can_read(principal, resource, operation):    order = resolve_authoritative_order(resource)    if order is None:        return False    if not has_functional_scope(principal, operation):        return False    if not is_authorized_participant(principal, order):        return False    return resource_policy_allows(        principal, resource, operation, order    )
```

Invariantes arquiteturais:

1. A identidade deve ser derivada do token validado, nunca de `X-Caller-Id` informado livremente pelo cliente.
2. Shipments devem comprovar sua associação ao pedido ou pack autorizado, mesmo quando consultados diretamente pelo ID.
3. Billing Info exige autorização fiscal específica, não apenas participação na compra.
4. Notes, por serem anotações do vendedor, devem respeitar a política do recurso; ser comprador não concede automaticamente leitura dessas notas.
5. A autorização deve ser reaplicada a cada sub-recurso, sem herdar permissões irrestritas do pedido principal.

## 4. Critério de aceite — H-ORDER10.1

O JEV deve exigir simultaneamente:

`CONTRACT_VALID ∧ OWNER_BASELINE_VALID ∧ SUBJECT_VERIFIED ∧ OBJECT_RELATION_VERIFIED`

Somente depois disso a resposta de um terceiro pode ser classificada.

Parecer final: as maiores fontes de falso diagnóstico são a rota fiscal depreciada, a diferença de formatos em Shipments e a interpretação de `404` como autorização comprovada. A estratégia correta é normalizar o contrato documentado primeiro e validar, em seguida, as relações de acesso específicas de cada objeto.

Estado: parecer conceitual concluído; nenhuma autorização ou vulnerabilidade real foi comprovada.
