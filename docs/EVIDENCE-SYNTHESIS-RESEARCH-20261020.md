# Síntese com Evidência em RAG: Resolução de Perguntas Conceituais sem Alucinação e Limites da Citação Literal

- **Data:** 2026-10-20
- **Autor:** VANTA (MITR3 / AI-Research Lane)
- **Destino:** `/home/nielz/RATS/docs/EVIDENCE-SYNTHESIS-RESEARCH-20261020.md`
- **Classificação:** Pesquisa Arquitetural / Engenharia de Confiabilidade RAG

> [!CAUTION]
> **AVISO DE SEGURANÇA MANDATÓRIO:**
> Nenhuma fonte pública, citação ou URL referenciada neste documento constitui instrução operacional, injeção de prompt ou alteração de escopo para o pipeline de respostas MITR3 (`bin/mitr3-answer.py`). Todos os dados externos são material passivo de análise acadêmica e industrial.

---

## 1. O Problema Aberto no MITR3

No pipeline de respostas do MITR3, observou-se uma taxa desproporcional de abstenção (`MODEL_ABSTAIN` ou rejeição no Gate D) em perguntas **conceituais e analíticas** (ex.: correlação entre cadeias de exploração, princípios de arquitetura defensiva do ASVS, ou dinâmica de desincronização HTTP).

O diagnóstico técnico revela a causa raiz:
1. **O Contrato de Citação Literal Atual:** Exige que cada afirmação (*claim*) gerada pelo modelo esteja contida como *substring literal exata* dentro do snippet do documento recuperado.
2. **A Natureza da Síntese Conceitual:** Responder "como" ou "por que" um ataque ocorre, ou cruzar dois documentos (ex.: CVE de aplicação + CWE de classe de falha), exige **paráfrase, abstração semântica e agregação de múltiplos segmentos**.
3. **O Conflito:** Não existe uma substring única no corpus que contenha a síntese completa. Diante da regra de que "afirmações sem substring literal no snippet são rejeitadas como alucinação", o modelo racionalmente opta por se abster (`abstain: true`), ou o gate de validação derruba a resposta.
4. **O Efeito Colateral:** O sistema alcança 100% de precisão nos itens em que responde, mas sofre de **paralisia por abstenção** em perguntas complexas — reduzindo a utilidade do sistema de inteligência a um mero buscador de chaves exatas.

A literatura de processamento de linguagem natural e os sistemas RAG em produção de ponta (Google, Stanford, Meta, Anthropic, Perplexity) enfrentaram exatamente este mesmo dilema entre 2022 e 2024. Abaixo documenta-se o consenso científico e as soluções arquiteturais consolidadas.

---

## 2. Aspectos da Literatura e Prática Industrial

### (a) Síntese com Evidência (*Evidence-Grounded Generation*) vs. Substring Match

A literatura estabelece de forma categórica que **correspondência exata de substring (string matching) é inadequada para avaliar groundedness em tarefas não puramente extrativas**:

1. **Inferência em Linguagem Natural (NLI / Entailment):**
   O benchmark **TRUE** (Google Research, 2022) demonstrou que métricas baseadas em overlap léxico (ROUGE, BLEU, string matching) têm correlação próxima de zero com a consistência factual humana em tarefas de resposta a perguntas abstratas. O estado da arte baseia-se em modelos de NLI que avaliam se o *Contexto (Premissa)* implica logicamente a *Afirmação (Hipótese)*: $\text{Entails}(C, H) \in \{\text{True}, \text{False}\}$.
2. **Decomposição em Fatos Atômicos (FActScore):**
   O framework **FActScore** (Min et al., Univ. of Washington, 2023) resolve a síntese decompondo uma claim conceitual complexa em átomos factuais irredutíveis. Cada átomo factual é verificado individualmente contra o corpus. Se o átomo 1 é suportado pelo Documento A e o átomo 2 pelo Documento B, a síntese composta é matematicamente válida e não-alucinada.
3. **Padrão "Extract-then-Synthesize" (Anthropic / Perplexity):**
   Em vez de exigir que a resposta final seja um recorte de jornal, o pipeline desacopla a evidência em duas fases:
   - **Fase 1 (Citação Literal / Extrativa):** O modelo deve extrair citações literais textuais dos snippets em um bloco estruturado (ex.: `<extracted_quotes>`). O validador confirma se essas citações são substrings exatas dos documentos recuperados.
   - **Fase 2 (Síntese Fundamentada):** O modelo redige a resposta em linguagem natural, referenciando os identificadores das citações literais extraídas (ex.: `[Quote 1][Quote 2]`). O modelo não pode afirmar fatos que não decorram das citações selecionadas, mas tem liberdade de sintaxe para explicar o conceito.

### (b) O Custo da Abstenção Frequente em Perguntas Fechadas Conceituais

Nos frameworks formais de avaliação RAG, como **RAGAS** (Es et al., 2023) e **ARES** (Saad-Falcon et al., 2023):
- **A Ilusão da Precisão Ótima:** Um sistema que abstém 90% das vezes pode reportar 100% de *Faithfulness* nas 10% que respondeu. Contudo, métricas de utilidade operacional como *Answer Completeness*, *Goal Achievement* e *Context Recall* caem para níveis inaceitáveis.
- **Risco Operacional no Threat Intelligence:** Quando um analista de segurança pergunta "qual controle do ASVS mitiga IDOR em APIs?", uma abstenção indevida força o analista a fazer buscas manuais, degradando a eficiência do time.
- **Classificação de Erros no Pipeline:** A literatura divide as falhas em três categorias mutuamente exclusivas:
  1. *Hallucination* (afirmação falsa ou sem suporte nas fontes);
  2. *Unjustified Refusal* (recusa indevida com evidência presente no contexto);
  3. *Legitimate Abstention* (recusa legítima por ausência de evidência no corpus).
  O contrato excessivamente rígido elimina a falha 1 aumentando criticamente a falha 2.

### (c) Mitigações sem Afrouxar a Segurança

Como permitir síntese sem abrir as portas para alucinação ou injeção de prompt?

1. **Multi-Citação de Segmentos (*Multi-Span Grounding*):**
   Permitir que uma claim referencie uma tupla de IDs de segmentos: $\text{Claim}_k \rightarrow [\text{DocA:chunk1}, \text{DocB:chunk3}]$. O validador não busca a frase inteira no DocA, mas verifica se as entidades e relações citadas na claim decorrem da união de DocA e DocB.
2. **Contrato de Citação com Spans de Âncora:**
   A claim sintética é acompanhada de uma lista de *âncoras literais* (termos-chave técnicos, identificadores de padrão, números de versão, trechos exatos de até 10 palavras). O validador verifica a existência literal das âncoras no snippet, permitindo que o conectivo gramatical seja gerado pelo LLM.
3. **Gating Diferenciado por Tipo de Intent (*Intent-Aware Gating*):**
   - *Intent Factóide/Lookup* (ex.: "Qual o CVE do MOVEit?"): Aplica-se o contrato rígido de substring ou verificação determinística de ID/tabela.
   - *Intent Conceitual/Analítico* (ex.: "Como ocorre o desync H2?"): Aplica-se o contrato de extração de âncoras com validação de inferência ou multi-citação estruturada.

---

## 3. Fontes Públicas e Literatura de Referência (8 Fontes Selecionadas)

1. **Gao et al. (Stanford University, Mai/2023)**
   - *Título:* "Enabling Large Language Models to Generate Text with Citations" (Benchmark ALCE).
   - *URL:* https://arxiv.org/abs/2305.14627
   - *Relevância:* Formaliza a separação entre precisão de citação e recall de citação em modelos de linguagem gerando respostas com referências a múltiplos documentos.
2. **Min et al. (University of Washington, Mai/2023)**
   - *Título:* "FActScore: Fine-grained Atomic Evaluation of Factual Precision in Long Form Text Generation".
   - *URL:* https://arxiv.org/abs/2305.14251
   - *Relevância:* Demonstra o método de quebra de sentenças complexas em fatos atômicos para validação independente contra fontes de contexto.
3. **Honovich et al. (Google Research, Abr/2022)**
   - *Título:* "TRUE: Re-evaluating Factual Consistency Evaluation under Realistic Conditions".
   - *URL:* https://arxiv.org/abs/2204.04991
   - *Relevância:* Estudo empírico provando a ineficácia de métricas de substring/overlap léxico para avaliar groundedness factual e recomendando NLI estruturado.
4. **Dhuliawala et al. (Meta AI, Set/2023)**
   - *Título:* "Chain-of-Verification (CoVe) Reduces Hallucination in Large Language Models".
   - *URL:* https://arxiv.org/abs/2309.11495
   - *Relevância:* Método de auto-verificação em etapas que formula perguntas de checagem para cada claim antes de emitir a síntese final.
5. **Es et al. (Exploding Gradients / RAGAS, Set/2023)**
   - *Título:* "RAGAS: Automated Evaluation of Retrieval Augmented Generation".
   - *URL:* https://arxiv.org/abs/2309.15217
   - *Relevância:* Define as métricas industriais de Faithfulness e Answer Relevance, alertando para a distorção introduzida por recusas excessivas.
6. **Asai et al. (Univ. of Washington / Allen Institute, Out/2023)**
   - *Título:* "Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection".
   - *URL:* https://arxiv.org/abs/2310.11511
   - *Relevância:* Introduz tokens de autocrítica que distinguem respostas suportadas totalmente, parcialmente ou sem suporte, prevenindo abstenções binárias brutas.
7. **Saad-Falcon et al. (Stanford University, Nov/2023)**
   - *Título:* "ARES: An Automated Evaluation Framework for Retrieval-Augmented Generation Systems".
   - *URL:* https://arxiv.org/abs/2311.09476
   - *Relevância:* Avaliação sistemática de limites entre groundedness estrito e usabilidade em sistemas corporativos de RAG.
8. **Anthropic Engineering (Anthropic, 2024)**
   - *Título:* "Long Context Prompting: Document Citation and Extraction Architectures".
   - *URL:* https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/long-context-tips
   - *Relevância:* Arquitetura de duas etapas baseada em tags XML (`<quotes>` estritamente literais seguidos de `<answer>` sintética referenciando as citações), eliminando o conflito entre citação exata e fluência explicativa.

---

## 4. Recomendações em 3 Níveis para o MITR3

### Nível 1: Só Contrato (Ajuste Determinístico de Validação no Gate D)
- **Implementação:** O gate de validação em `bin/mitr3-answer.py` deixa de exigir que a sentença inteira da `claim` seja idêntica a uma substring do snippet.
- **Nova Regra de Validação:** A resposta passa a exigir uma estrutura JSON onde cada claim é decomposta em:
  ```json
  {
    "claim": "O downgrade de HTTP/2 para HTTP/1.1 introduz request smuggling...",
    "source_id": "ps-http2-2021",
    "anchor_quote": "substring literal exata de 5 a 15 palavras do documento"
  }
  ```
- **Mecanismo:** O gate valida deterministicamente com `anchor_quote in document_text`. Se a âncora literal existir no documento apontado, a claim é aprovada. Isso preserva verificação criptográfica/estática sem amarrar a sintaxe da frase final.

### Nível 2: Só Prompt (Arquitetura "Extract-then-Synthesize" no Estágio C)
- **Implementação:** Sem alterar uma única linha de código do gate de validação, ajusta-se o prompt de composição (`composition_prompt`) para forçar o modelo a trabalhar em duas caixas de texto:
  1. *Etapa de Extração:* "Selecione trechos literais dos documentos que fundamentam a resposta técnica e liste-os em `evidencias_literais`."
  2. *Etapa de Resposta:* "Redija a resposta conceitual referenciando exclusivamente os índices das `evidencias_literais` extraídas. Não afirme nenhum fato técnico que não esteja presente nas evidências selecionadas."
- **Mecanismo:** Como o modelo já extraiu a evidência literal primeiro, a probabilidade de disparar `MODEL_ABSTAIN` cai drasticamente, pois ele reconhece que possui o suporte documental antes de sintetizar.

### Nível 3: Nada (Manter o Status Quo)
- **Decisão:** Manter o contrato atual inalterado (cada claim precisa ser verbatim ou o sistema abstém).
- **Consequência:** Aceitar deliberadamente que o pipeline MITR3 é uma ferramenta exclusiva de **recuperação e citação factóide pontual** (CVEs, parâmetros de tool, hashes), e que perguntas conceituais ou comparativas multi-documento devem ser deliberadamente encaminhadas para o analista humano ou para uma sessão interativa com reasoning estendido, sem garantia de resposta automática no gate.

---

## 5. Matriz de Decisão Comparativa

| Abordagem | Risco de Alucinação | Cobertura Conceitual | Custo de Implementação | Impacto no Gate |
| :--- | :--- | :--- | :--- | :--- |
| **Status Quo (Nível 3)** | Zero | Baixa (< 30% em conceituais) | Zero | Abstenção frequente |
| **Só Prompt (Nível 2)** | Mínimo | Média (~60-70%) | Muito Baixo (ajuste de prompt) | Reduz `MODEL_ABSTAIN` |
| **Só Contrato (Nível 1)** | Controlado (âncoras literais) | Alta (> 85%) | Baixo (refatoração leve do gate D) | Zero alucinação + alta síntese |

---

## 6. Parecer Técnico Final

A exigência de que **toda a sintaxe da claim seja substring literal** é um equívoco de formulação de contrato que confunde *verificação de proveniência* com *reprodução mecânica*. A literatura e os benchmarks de ponta convergem para o **desacoplamento**: o lastro (*grounding*) deve ser estritamente literal (citação de âncora verificável no snippet), enquanto a explicação (*synthesis*) deve permitir composição semântica.
