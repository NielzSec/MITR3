# Diagnóstico A–D com fixture pública de desenvolvimento

**DEV somente; não é repetição, tuning ou nota do v4.** Nenhuma pergunta,
gabarito ou relatório congelado foi lido pelo diagnóstico. A referência à onda
`MODEL_ABSTAIN` do v4 é o problema informado pelo time, não uma nova avaliação
dos seus itens. O pipeline de resposta e seus prompts não foram alterados.

## Fixture e política de dados

Fixture nova e independente: `tests/fixtures/answer-stage-dev-v1.json`, três
perguntas públicas conceituais sobre HSTS, CSP e Content-Type no ASVS. Cada item
indica um documento público para o controle de evidência; não tem resposta,
claims esperadas, quotes, classificação de correção ou gabarito. Esse documento
não entra no prompt de A; serve apenas para construir o pacote de referência
no experimento C.

Runner: `bin/mitr3-stage-diag.py`. Fonte local: ASVS 5.0.0, namespace local,
`source_url=https://github.com/OWASP/ASVS/tree/v5.0.0`, com hash do documento
verificado pelo pipeline. Só dados públicos locais, sem `--remote`.

Artefato novo: `reports/stage-diag-dev-20261020.json`. Registra apenas contagens,
IDs públicos, hashes do pacote, comprimentos, booleanos de substring, códigos e
taxas agregadas. Não registra perguntas, queries em texto, prompts, corpos de
fonte, claims, quotes ou diagnósticos de erro do provedor. IDs citados fora do
pacote são substituídos por `[unlisted-id]`. As perguntas públicas estão somente
na fixture, não duplicadas como log de prompt. Nenhum segredo é persistido.

## Transporte e limite de comparação

Modelo: `google/gemini-3.5-flash-lite`, provedor já autorizado. Usa a API
[generateContent](https://ai.google.dev/api/generate-content), sem tools,
`store=false`, sem histórico local ou sessões OpenCode. A chave é lida do ambiente
e enviada somente em header; respostas e erros ficam em memória. O cliente não
imprime nem persiste request/response brutos. Esse controle de logging não
substitui os termos de tratamento de dados do provedor.

Isso evita criar novas sessões OpenCode com prompts brutos. Mantém as funções
atuais `plan_prompt`, `plan_gate`, `composition_prompt`, `evidence_package` e
`gate`, mas **não reproduz o wrapper `--agent plan` do CLI OpenCode**. Portanto
os resultados isolam essa execução DEV do modelo e gate, não demonstram a causa
do comportamento do v4 em outro modelo/agente. Não foi instalado modelo local.

Foram 3 chamadas A e 9 chamadas C, uma execução por condição, sem seleção de
melhor resposta. Não há revisão semântica independente nesta medição.

## A — plano e consultas

| Caso DEV | Consultas geradas | Consultas distintas | Erro de plano |
|---|---:|---:|---|
| dev-hsts | 2 | 2 | nenhum |
| dev-csp | 2 | 2 | nenhum |
| dev-content-type | 2 | 2 | nenhum |
| Total | 6 | 6 | 0/3 |

As strings das queries ficam somente em memória e são executadas no índice e no
bridge. Para evitar log acidental de valores indevidos gerados pelo modelo,
persistem-se contagens e IDs, não as queries textuais. Nenhum identificador novo
é aceito pelo plan_gate se não estiver na pergunta.

## B — recuperação e trecho efetivamente enviado

Índice e bridge foram chamados para cada uma das seis queries, ambos com limit 5.
Os rankings de IDs coincidiram em **6/6** pares. **5/6 queries** retornaram algum
documento: a segunda query CSP retornou vazio nos dois caminhos. Isso é taxa de
retorno, não recall contra gabarito. Os três pacotes agregados contêm material
relevante ao conceito público de cada fixture, mas isso não prova entailment.

Comprimentos abaixo vêm de **deserializar o JSON dentro do prompt C realmente
construído**, não do documento completo no SQLite. Ordem igual à transmissão:

| Caso | ID transmitido | Caracteres de snippet |
|---|---|---:|
| HSTS | ASVS-V3.4.1 | 259 |
| HSTS | ASVS-V3.7.4 | 300 |
| HSTS | ASVS-V3.1.1 | 300 |
| HSTS | ASVS-V6.5.6 | 113 |
| HSTS | ASVS-V6.5.7 | 145 |
| CSP | ASVS-V3.4.3 | 300 |
| CSP | ASVS-V3.4.7 | 95 |
| CSP | ASVS-V3.2.1 | 300 |
| CSP | ASVS-V3.4.8 | 300 |
| CSP | ASVS-V3.1.1 | 300 |
| Content-Type | ASVS-V6.2.5 | 227 |
| Content-Type | ASVS-V3.4.4 | 300 |
| Content-Type | ASVS-V3.2.3 | 257 |
| Content-Type | ASVS-V9.2.2 | 300 |
| Content-Type | ASVS-V3.2.1 | 300 |

O artefato também inclui bytes UTF-8: ASVS-V3.4.8 tem 300 caracteres e 306 bytes.
Texto completo e trecho não são intercambiáveis. O hash do corpo completo é
conferido antes de usar esse corpo apenas para classificar uma falha de quote;
o corpo não é gravado no diagnóstico.

## C — MODEL_ABSTAIN medido, não deduzido do resultado final

Cada pergunta passou por três condições de composição, sem modificar o prompt:

1. `retrieved`: pacote montado com as queries de A, até cinco registros.
2. `empty`: pacote vazio deliberado. Na produção isso seria interceptado como
   `NO_EVIDENCE` antes de C; aqui chama-se C diretamente para medir sua decisão.
3. `reference`: documento público indicado pela fixture, usando a mesma janela
   de até 300 caracteres. Tem evidência citável sobre o conceito, sem resposta
   pronta. “Suficiente” significa que há requisito diretamente citável, não que
   todas as explicações conceituais possíveis foram comprovadas.

| Condição | Chamadas | Composições com boolean válido | MODEL_ABSTAIN | Gate aceita proposta |
|---|---:|---:|---:|---:|
| retrieved | 3 | 3 | 0/3 | 3/3 |
| empty | 3 | 3 | 3/3 | 0/3 |
| reference | 3 | 3 | 0/3 | 3/3 |

Nenhum MODEL_TIMEOUT, MODEL_FAILED ou MODEL_JSON foi observado nessas chamadas.
O modelo distinguiu pacote vazio de pacote com requisito citável nesta fixture.
**A onda conceitual de abstenções não se reproduziu aqui.** Isso não demonstra
que o v4 esteja correto, incorreto ou resolvido: não foram usados seus itens,
gabaritos, relatórios ou o mesmo wrapper de agente.

## D — separar quote não literal, janela e pacote diferente

Para cada citação, compara-se em memória a substring com espaços colapsados:

- Está no trecho transmitido e no trecho do gate: `literal`.
- Estava no pacote enviado, mas o pacote do gate mudou e a quote saiu dele:
  `different_package`.
- Não está no trecho enviado, mas está no documento público completo verificado:
  `outside_window` (inclui campos como lesson que não foram transmitidos).
- Não está em nenhum dos dois: `nonliteral_or_paraphrase`. Isso **não prova
  semanticamente uma paráfrase**: pode ser alucinação, erro ou transformação.
  Entailment exige revisão independente; não usamos o gerador para aprovar-se.

Nas seis composições reais não abstidas, todas as citações eram literais e o
hash do pacote enviado era igual ao do gate. **QUOTE_NOT_LITERAL: 0/6**.
Não há falha real nesta amostra para atribuir a uma das três causas.

Controles determinísticos separados dos resultados do modelo:

| Controle sintético | Casos | Código do gate | Categoria distinguida |
|---|---:|---|---|
| Texto deliberadamente não literal | 3 | QUOTE_NOT_LITERAL em 3/3 | nonliteral_or_paraphrase |
| Texto do documento/campo fora do trecho transmitido | 3 | QUOTE_NOT_LITERAL em 3/3 | outside_window |
| Citação literal original, trecho do pacote do gate removido | 3 | QUOTE_NOT_LITERAL em 3/3 | different_package |

Esses nove controles validam a instrumentação e o gate; **não são nove erros do
modelo**. São produzidos em memória, sem registrar quotes de controle ou corpos
originais. Detectar pacote diferente depende de comparar os dois hashes; apenas
olhar o código QUOTE_NOT_LITERAL não distingue as causas.

## Conclusão e reprodução segura

Nesta rodada DEV, A gerou seis consultas, B transmitiu pacotes não vazios nos
três casos, C absteve somente no controle vazio, e D não rejeitou quotes reais.
Não há evidência DEV de que perguntas conceituais, por si só, impliquem abstenção
sob esse transporte. Fatores ainda não isolados para o problema informado do v4:
wrapper/agente, formulação da pergunta, cobertura factual do trecho e escolhas
estocásticas. Nenhum desses fatores foi ajustado com base no cego.

```sh
python3 bin/mitr3-stage-diag.py --model google/gemini-3.5-flash-lite \
  --output /tmp/novo-stage-dev.json
python3 -W error::ResourceWarning -m unittest discover -s tests
```

O script só usa a fixture DEV fixa; não aceita caminho de conjunto cego. Output
novo, exclusivo e 0600. Testes novos usam mocks, sem rede. Não repetir até obter
um resultado desejado nem misturar os números com métricas dos conjuntos cegos.
Uma futura correção do pipeline exige patch separado e nova medição cega.
