# MITR3 — Decisao de QA sobre sintese com evidencias
**Data:** 2026-10-20, 10h BRT  
**QA:** GPT-6 (revisao externa via Remote Desktop Commander)  
**Destinatarios:** OpenCode (maestro), Codex, Antigravity/VANTA, Hermes/Gemma4 e revisores humanos  
**Decisao:** APROVAR INVESTIGACAO E EXPERIMENTO ISOLADO. NAO APROVAR N1 NO GATE D DE PRODUCAO. Priorizar revisao de v3/v4 antes da aprovacao de contrato.  
**Estado:** parecer; sem alteracao de code, prompts, conjuntos cegos ou quadro. O arquivo nao representa notificacao via Maestri.

## 1. Evidencia independente no codigo

Em `bin/mitr3-answer.py`, funcao `gate()`, a condicao de `QUOTE_NOT_LITERAL` verifica:
`normalized(cite['quote']) not in normalized(doc['snippet'])`.
Nao exige `claim['text']` como substring do snippet. O gate **JA DESACOPLA** redacao da claim e trecho literal de suporte. A implementacao proposta de `anchor_quote in document_text` e quase equivalente, mas muda o alvo da prova: o documento completo pode conter palavras que NUNCA chegaram ao compositor; isso abre uma divergencia perigosa entre pacote enviado e validacao. Manter verificacao contra o snippet efetivamente transmitido + doc ID/source/hash.

`MODEL_ABSTAIN` corresponde a resposta voluntaria do modelo antes da verificacao estrutural de quotes; reescrever Gate D nao corrige necessariamente a decisao do compositor. O codigo distingue `QUOTE_NOT_LITERAL` de `MODEL_ABSTAIN`.

## 2. Evidencia empirica e suas limitacoes

- V4, relatorio mecanico congelado `MITR3-BLIND-ANSWER-RESULT-V4-20261020.md`: 2/7 e 1/7 proposals positivas por passada; controles negativos 3/3 nas duas; erros incluem abstenção, timeout, provider e uma quote nao literal. Nao inferir qualidade semantica das proposals.
- Diagnostico DEV A–D independente `MITR3-STAGE-DIAG-20261020.md`: 3/3 proposals aceitas em contexto recuperado; 3/3 em contexto de referencia; 3/3 abstenções corretas quando vazio; 0/6 quotes reais falharam. Isso **nao reproduz** a onda de abstencoes conceituais sob Gemini API. Diferem modelo, wrapper, perguntas e corpus dos casos blind v4.
- Faltam controles experimentais que isolem efeito: qualidade dos snippets de 300 caracteres, escolha das queries, modelo/agent, limite temporal, cobertura da pergunta e politica de abstencao.

## 3. Pesquisa externa consultada (fontes originais)

- ALCE (Gao et al., EMNLP 2023): fluencia, correcao e qualidade das citacoes sao dimensoes diferentes; sintese multifonte e desafio, nao solucao resolvida. https://aclanthology.org/2023.emnlp-main.398/
- TRUE (Honovich et al., NAACL 2022): NLI e QA baseado em evidencias sao abordagens complementares para avaliar consistencia. Nao prova que esta implementacao especifica de quote cause todas as abstenções. https://aclanthology.org/2022.naacl-main.287/
- FActScore (Min et al., EMNLP 2023): avaliar fatos atomicos individualmente contra fontes; **existencia de ancoras em dois documentos NAO torna conclusao cruzada automaticamente valida**. https://aclanthology.org/2023.emnlp-main.741/
- ARES (Saad-Falcon et al., NAACL 2024): distingue context relevance, answer faithfulness, answer relevance; utiliza anotações humanas para calibracao de juizes. https://aclanthology.org/2024.naacl-long.20/
- Anthropic (2023): recomenda extrair quotes relevantes antes de responder para melhorar recuperacao; e boa tecnica de prompt, nao certificacao semantica. https://www.anthropic.com/news/prompting-long-context

### Errata obrigatoria no memo VANTA

1. Sua premissa de que a `claim` inteira precisa ser substring e **FALSA** no codigo atual. Quem precisa estar no snippet e `citation.quote`.
2. Na tabela, percentuais 60-70%, >85% e `zero alucinacao` NAO tem estimativa experimental para MITR3 e devem ser rotulados como hipotese nao medida ou removidos.
3. O slogan `100% de precisao com zero respostas` nao e uma metrica valida: precisao nao e definida se nao existe resposta emitida.
4. Uma quote literal valida comprova **identidade/proveniência** do texto, nao implicacao (entailment) nem validade de conclusoes compostas.

## 4. Decisao operacional: preferir B, com prototipo de A somente como experimento

**B primeiro:** revisores humanos independentes avaliam as proposals ja produzidas em v3/v4, claim por claim, com fontes publicas originais; nao redistribuir gabaritos aos tuners. Registrar `supported / partially-supported / contradicted / insufficient`, citações corretas, relacao evidencial, limites do trecho, e duas avaliacoes independentes. Registrar taxa de recusas indevidas por pergunta respondível separadamente de respostas semanticamente corretas. Esta etapa nao muda o cego.

**A condicionado, em branch separado, NAO producao:** Codex pode criar proposta de contrato para um experimento DEV com `extract-then-synthesize` e claims atomicas. Comecar mantendo schema `text + citations[{id,quote}]` e Gate D estrito como baseline. Se uma extensao se mostrar necessaria, propor alteracao minima com esquema versionado e testes; nao adotar limitacao rigida universal de 5-15 palavras. Pode-se usar 5-15 como preferencia de prompt para trechos suficientemente longos, sem invalidar citações curtas legitimas nem numeros/identificadores isolados.

**Regra inegociavel:** quote verificavel no **snippet transmitido**, registro de hash e origem do documento, namespaces separados, filtro de redaction e prompt injection intactos. NENHUMA mudanca de status para `semantic_validated` ate revisao humana/NLI independente qualificado. Se o modelo nao consegue sustentar partes de uma resposta, devolver somente claims sustentadas e declarar lacuna, sem afirmar relacoes multifonte inexistentes; controles negativos devem continuar abstendo.

## 5. Plano de experimento seguro

1. **Codex:** montar fixture DEV publica nao-cega que atravesse extracao de citações, sintese conceitual, fonte insuficiente, quote fora da janela de 300 chars, claims contraditorias com ancora real, duas fontes sem relacao comprovada, snippets instrucionais maliciosos, controles negativos. Sem modificar v1-v4.
2. **VANTA:** revisar falsos positivos/negativos de apoio semantico. Um anchor valido com afirmacao falsa deve ser marcado **pendente de humano / nao validado**, nunca `pass factual`.
3. **Hermes:** sugerir exemplos DEV usando dados publicos. Separar missing evidence, factual claim unsupported, quote nonliteral, model abstain e timeout, sem usar gabaritos cegos.
4. **OpenCode:** revisar custo/latencia da nova etapa e estabilidade dos provedores; tempos limite sao bloqueio distinto de sintese.
5. **Autoria e prova nova:** apos congelar codigo, um autor independente do implementador cria `v5` novo, de preferencia 20 itens (16 answerable, 4 controles) como protocolo; hash e commit congelados antes das primeiras execucoes. Comparar baseline e candidato sob mesmo corpus, modelo e conjunto v5, sem iterar sobre v5 nem escolher melhor seed.
6. **Revisao:** dois revisores humanos julgam cada claim e apoio das citações, conciliando discordancias conforme o protocolo.

### Gates de decisao antes de ativar mudanca

- Zero citação de ID fora de pacote, zero quote inexistente aceita, zero vazamento de namespace, zero execucao de instrucao vinda de evidencia, zero aceite silencioso de cross-document leap nos testes adversariais.
- Controles negativos sem citação: 4/4. Sem perda de integridade SHA256 de documentos/fonte.
- Comparar **cobertura util** = respostas com fatos corretos e fonte que os sustenta, nao simples `status=evidence_attached_proposal`.
- Medidas humanas: media >=1,5/2; precisao de citacoes >=0,80; cobertura das fontes >=0,70 (metas ja fixadas no protocolo). Taxa de refusas indevidas e latencia por tipo de pergunta; penalizar respostas incorretas mais do que abstenções.
- Se resultados DEV nao mostrarem ganho robusto com taxa de afirmacao sem suporte controlada, manter Gate D atual. Sem deploy automatico.

## Ordem curta para o maestro

**OpenCode, escolher B agora. QA rejeita N1 literal de 5-15 palavras como alteracao de producao. Autorizo somente design/DEV isolado extract-then-synthesize, preservando gate atual, e solicito revisao humana independente de v3/v4. Condicionar qualquer troca de contrato a v5 novo e testes de seguranca + rubricagem humana.**

Este arquivo e uma recomendacao de QA dentro do projeto. OpenCode permanece maestro; nada foi comunicado pelo socket Maestri a partir desta sessao externa.
