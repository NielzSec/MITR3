# H1-MELI — relatório técnico final da Onda 10

Data das execuções: 21/10/2026 (UTC). Emissor live: OpenCode, conforme informado pelo Maestro.
Síntese Codex: inspeção local offline dos artefatos; nenhuma nova requisição ao alvo.

## Resultado consolidado

**Base Order: NEGATIVE na variante testada.** Os controles de comprador e vendedor
receberam HTTP 200 com o mesmo pedido. O terceiro recebeu HTTP 403 e
`not_owned_order`, em envelope de erro de autorização, sem dados do pedido.
Isso sustenta ACL atuante para esta leitura, objeto e conjunto de identidades;
não demonstra ausência universal de BOLA no produto.

**Shipments: INCONCLUSIVE.** O controle positivo C1 retornou HTTP 404 e
`not_found_shipping_for_order_id`. O pedido consultado estava em
`payment_required`, com ausência de identificador de envio nos controles base.
A evidência é consistente com ausência de objeto de envio disponível no pedido
pendente. Sem controle positivo válido, não foi possível avaliar a ACL de Shipments.

Não há candidato BOLA sustentado por estas execuções. Billing Info não foi avaliado
nos dois diretórios analisados.

## Objeto, papéis e execuções

Pedido: `2000019100583370`. Mapeamento utilizado: `swap_bc=true`.

| Caso | Papel | Token | Test user |
|---|---|---|---|
| C1 | Comprador | A | 3780339606 |
| C2 | Vendedor | B | 3780339608 |
| X1 | Terceiro não envolvido | C | 3780429720 |

Os IDs de comprador A e vendedor B coincidem com os corpos dos controles base.
A identidade C e a associação aos tokens foram informadas pelo Maestro; estes
artefatos de resposta não são uma nova prova independente de `/users/me`.
Nenhum token, endereço, item ou conteúdo privado é reproduzido neste relatório.

- **Base:** `20261021T220628.774181Z`, de 22:06:28.774326 a 22:06:32.353705 UTC.
  Sequência observada: C1 → C2 → X1, três respostas preservadas.
- **Shipments:** `20261021T220941.313465Z`, de 22:09:41.313679 a 22:09:41.512278 UTC.
  Uma resposta C1_shipments; execução interrompida em `POSITIVE_CONTROL_FAILED`.
  C2 e X1 não foram executados nessa sequência.

## Resultados por caso

| Recurso | Caso | HTTP | Código de erro da API | Resultado observado |
|---|---|---|---|---|
| Base Order | C1 / A | 200 | Nenhum erro de API | Controle positivo; pedido e buyer/seller vinculados |
| Base Order | C2 / B | 200 | Nenhum erro de API | Controle positivo; corpo idêntico ao de C1 |
| Base Order | X1 / C | 403 | `not_owned_order` | Negação de leitura ao terceiro; NEGATIVE após revisão |
| Shipments | C1 / A | 404 | `not_found_shipping_for_order_id` | Objeto de envio indisponível; controle positivo falhou |
| Shipments | C2 / B | Não executado | — | Parada após C1 |
| Shipments | X1 / C | Não executado | — | ACL do terceiro não testada |

Status HTTP conferidos nos arquivos de cabeçalhos e nos summaries. `payment_required`
é estado de negócio do pedido, não código de erro HTTP dos controles 200.

## Fundamentação e diferença em relação ao runner

Os corpos C1/C2 base são byte a byte idênticos, contêm itens não vazios e vinculam
pedido, comprador A e vendedor B. X1 contém somente `error`, `message`, `status`
e `cause`; `cause` está vazio. O erro é `not_owned_order` e a mensagem pertence ao
contexto de autorização. Não há payload do pedido nessa resposta.

O summary original da base registra `STOPPED`, X1=`INCONCLUSIVE` e
`INCONCLUSIVE_RESPONSE`. A mensagem textual da API não pertence à allowlist
conservadora de mensagens do classificador. **NEGATIVE é a conclusão técnica desta
revisão do envelope de erro**, não o veredito automático originalmente gravado.
O summary e as evidências originais foram preservados sem alteração.

Em Shipments, a negação já ocorre para o comprador autorizado, antes de qualquer
contraste com o terceiro. O 404, associado à ausência de shipping ID e ao estado
pendente do pedido, impede tratar esse resultado como prova de ACL segura ou de
vulnerabilidade. Não se infere que a rota nunca tenha suporte ou objeto disponível.

## Governança e orçamento

- **5 unidades consumidas no orçamento da onda, de um teto de 10 (50%).** O
  `session_ledger.json` registra `count=5`: uma reserva C1 anterior às 21:56:24.451563,
  três tentativas da base e uma tentativa de Shipments.
- Os dois diretórios comprovam **quatro respostas HTTP**, não cinco. A reserva
  anterior permanece `RESERVED`, sem resposta nestes artefatos; é contabilizada
  conservadoramente, sem afirmar que o envio chegou ao servidor.
- C1_shipments também permanece `RESERVED` no ledger, mas sua resposta 404 está
  preservada. O ledger termina com `stopped=true`. Nenhum contador foi resetado
  ou liberado nesta revisão.
- A janela de uma hora do ledger global para `api.mercadolibre.com` soma **6**
  unidades às 22:06:33 UTC e **7** às 22:09:42 UTC, ambas abaixo de **60/host/h**.
  Esses totais incluem registros além das cinco unidades da sessão; não são
  contagens intercambiáveis. Resultados count=0 não duplicam reservas count=1.
- Os limites estão respeitados **segundo os ledgers disponíveis**. Eles não
  comprovam completude de tráfego de navegador/setup eventualmente não registrado.
- As respostas da base têm timestamps separados por aproximadamente 1,69 s e
  1,68 s, consistentes com a sequência serial. Não há 429 nos quatro resultados.
  Não houve continuação de Shipments após a falha do controle positivo.

## Integridade e cadeia de evidências

Fontes privadas, relativas à raiz do repositório:

1. `reports/onda10_execution/20261021T220628.774181Z/`: sete arquivos listados em
   SHA256SUMS (três corpos, três cabeçalhos e summary), todos verificados.
2. `reports/onda10_execution/20261021T220941.313465Z/`: três arquivos listados
   (corpo e cabeçalhos de C1_shipments e summary), todos verificados.

Os dois `SHA256SUMS.sha256` também conferem com os respectivos manifestos:

| Artefato | SHA-256 |
|---|---|
| Manifesto Base | `aca5575d6a05885aa03e70185a3e3ec487a6bd2c1e58174755def25d94ae607a` |
| Manifesto Shipments | `b1e860d5c8f78faba7e171cedd15156227a8bd2c9f18554a6330a99ab7287164` |
| Session ledger no momento da revisão | `fbaf00eccc6ef9a47625eaee3cca6b68b5595b935a2ff285afaffaeec7cc4ef8` |
| Rate ledger global no momento da revisão | `23f661ce4f0bc68e96e6f1d1d926585222f5cfd5b252beae7fa6594d991dd027` |

Diretórios inspecionados: modo 0700; artefatos: modo 0600. Raw permanece privado.
Os ledgers são mutáveis; seus hashes identificam o estado consultado nesta revisão.
SHA-256 comprova consistência dos bytes com os selos, não assinatura digital,
identidade do emissor, autorização operacional ou completude da captura.

Encerramento técnico: **Base NEGATIVE; Shipments INCONCLUSIVE; nenhum finding
confirmado.** Este relatório não autoriza novas sondas nem substitui adjudicação
independente QA/JEV. O selo do próprio relatório está no arquivo adjacente
`H1-MELI-ONDA10-RELATORIO-FINAL.md.sha256`.
