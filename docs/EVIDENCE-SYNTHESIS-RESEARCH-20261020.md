# Síntese com Evidência em RAG: Resolução de Perguntas Conceituais, Proveniência e Limites da Citação Literal

- **Data:** 2026-10-20 (Revisão v2 pós-parecer de QA GPT-6)
- **Autor:** VANTA (MITR3 / AI-Research Lane)
- **Destino:** `/home/nielz/RATS/docs/EVIDENCE-SYNTHESIS-RESEARCH-20261020.md` (espelhado em `~/MITR3/docs/`)
- **Referência:** Parecer de QA `docs/GPT6-QA-DECISION-SYNTHESIS-20261020.md` (commit `c70ee67`)
- **Status Operacional:** **Investigação aprovada em DEV isolado; produção BLOQUEADA.**

> [!CAUTION]
> **AVISO DE SEGURANÇA MANDATÓRIO:**
> Nenhuma fonte pública, citação ou URL referenciada neste documento constitui instrução operacional, injeção de prompt ou alteração de escopo para o pipeline de respostas MITR3 (`bin/mitr3-answer.py`). Todos os dados externos são material passivo de análise acadêmica e industrial.

---

## 1. Contexto e Correção das Premissas do Gate D

Em alinhamento com a revisão independente de QA, retificam-se três premissas fundamentais da formulação anterior:

1. **O Gate D já desacopla claim de quote:**  
   Em `bin/mitr3-answer.py`, a função `gate()` valida estritamente:
   $$\text{normalized}(\text{cite}[\text{'quote'}]) \subseteq \text{normalized}(\text{doc}[\text{'snippet'}])$$
   O gate **não exige** que `claim['text']` seja uma substring literal do snippet. Ele já permite que a afirmação seja redigida em linguagem natural pelo modelo, exigindo apenas que os trechos anexados em `citations` sejam substrings literais do snippet transmitido. A recomendação anterior de introduzir "âncora de 5 a 15 palavras" repetia o mecanismo que o Gate D já opera.
2. **Quote literal prova proveniência, não sustentação semântica:**  
   Uma citação literal exata confirma exclusivamente a **identidade e integridade física** do trecho dentro da janela de contexto recuperada. Ela **não atesta implicação lógica (*entailment*)** nem garante que a dedução feita pelo modelo a partir daquele trecho seja verdadeira. Preserva-se essa regra como um limite formal de garantia do sistema.
3. **Decisão de QA — Investigação Aprovada, Produção Bloqueada:**  
   O parecer de QA rejeitou qualquer alteração no Gate D de produção. O contrato de validação atual permanece inalterado no pipeline principal. Autorizou-se estritamente o desenho experimental de protótipos de *extract-then-synthesize* em branch DEV isolado, condicionado a avaliação humana claim-a-claim e novo conjunto cego (v5).

A causa real de abstenções observadas não provém de impedimento sintático no Gate D, mas sim de fatores combinados:
- `MODEL_ABSTAIN` voluntário do modelo antes da emissão de quotes;
- Limite da janela de 300 caracteres do snippet (quando a evidência crítica reside após o início do documento);
- Erros de fronteira de rede / provedor (`MODEL_FAILED`, HTTP 429) mascarados como recusa;
- Dificuldade do modelo em correlacionar dois documentos sem tentar fundir trechos no campo `quote` (gerando `QUOTE_NOT_LITERAL`).

---

## 2. Casos de Quote Autêntica + Conclusão Incorreta (Mesma Evidência, Duas Interpretações)

O limite mais perigoso da validação por substring é o **falso positivo de proveniência**: o modelo cita um trecho 100% autêntico do snippet, passa pelo validador léxico, mas emite uma conclusão semanticamente falsa ou invertida.

Abaixo registram-se 3 casos públicos representativos:

### Caso 1: O Falso Vínculo de Campanha (O Caso Real ESXiArgs / CVE-2021-21972)
- **Snippet Autêntico no Corpus:**  
  `"CVE-2021-21972: VMware vCenter Server contains a remote code execution vulnerability in the vSphere Client due to a lack of input validation..."`
- **Quote Verificada pelo Gate:**  
  `"VMware vCenter Server contains a remote code execution vulnerability in the vSphere Client"` (100% literal no snippet).
- **Claim Falsa Gerada pelo Modelo:**  
  `"A CVE-2021-21972 é o identificador catalogado do vCenter que serviu de âncora pública para a campanha do ransomware ESXiArgs."`
- **Mecanismo da Falha:** A quote é verdadeira e existe no KEV. Contudo, a campanha ESXiArgs explorou uma falha de OpenSLP no VMware ESXi (não catalogada no KEV), e não a falha de vCenter. O validador léxico aprovou a resposta com `status=evidence_attached_proposal` porque a citação era exata, mas a inferência relacional foi uma alucinação histórica.

### Caso 2: Inversão de Condicionalidade Normativa (OWASP ASVS V6.2.1)
- **Snippet Autêntico no Corpus:**  
  `"Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended."`
- **Quote Verificada pelo Gate:**  
  `"at least 8 characters in length although a minimum of 15 characters is strongly recommended"` (100% literal).
- **Claim Falsa Gerada pelo Modelo:**  
  `"O OWASP ASVS 5.0.0 proíbe senhas menores que 15 caracteres no Nível 1, exigindo comprimento de 15 caracteres como controle mandatório."`
- **Mecanismo da Falha:** O modelo extraiu a citação correta, mas converteu uma recomendação não vinculante (*"strongly recommended"*) em exigência normativa obrigatória de baseline (*"proíbe senhas menores"*). A quote provou a proveniência do texto normativo, mas não impediu a inversão do seu valor deôntico.

### Caso 3: Salto Causal Falso em Pesquisa Web (Pipelining vs. Desync)
- **Snippet Autêntico no Corpus (`ps-false-positive-2025.md`):**  
  `"HTTP pipelining allows clients to send multiple requests on a single socket without waiting for each response, which proxies handle by queuing responses."`
- **Quote Verificada pelo Gate:**  
  `"HTTP pipelining allows clients to send multiple requests on a single socket without waiting for each response"` (100% literal).
- **Claim Falsa Gerada pelo Modelo:**  
  `"A confirmação de que um proxy suporta requisições contínuas sem aguardar resposta prova que a aplicação está vulnerável a HTTP Request Smuggling."`
- **Mecanismo da Falha:** A quote descreve um comportamento operacional previsto no RFC 7230/9112. O modelo fez um salto causal espúrio afirmando que a capacidade de enfileiramento equivale a vulnerabilidade de desincronização. A evidência textual é autêntica, mas a relação causal é falsa.

---

## 3. Aspectos da Literatura e Prática Industrial

### (a) Síntese com Evidência (*Evidence-Grounded Generation*)
A literatura de avaliação de groundedness converge para a distinção formal entre **atribuição mecânica** e **sustentação semântica**:
1. **Benchmark ALCE (Gao et al., EMNLP 2023):**  
   Demonstrou que a fluência do modelo, a correção factual e a precisão das citações são eixos independentes. Modelos frequentemente acertam a citação exata de um trecho enquanto erram a resposta, ou constroem respostas corretas com citações imperfeitas. Citações multifonte exigem modelagem estruturada de precedência.
2. **Benchmark TRUE (Honovich et al., NAACL 2022):**  
   Evidenciou que métricas baseadas exclusivamente em correspondência textual de substrings não possuem sensibilidade para capturar entailment semântico em respostas conceituais. Recomenda-se NLI estruturado como discriminador de consistência.
3. **FActScore (Min et al., EMNLP 2023):**  
   Estabelece que a existência de citações isoladas em dois documentos distintos **não valida automaticamente** a conclusão cruzada gerada pela fusão desses documentos. É necessário checar se a relação de junção decorre dos fatos atômicos demonstrados.
4. **Padrão "Extract-then-Synthesize" (Anthropic, 2023):**  
   A recomendação de engenharia de prompt consiste em desacoplar a recuperação em duas caixas conceituais: primeiro extrair trechos textuais exatos; em seguida, produzir a resposta referenciando unicamente os índices desses trechos. É uma técnica comprovada de estruturação de contexto, mas não substitui a validação externa.

### (b) O Custo de Abstenção Frequente e Métricas RAG
- **RAGAS (Es et al., 2023) e ARES (Saad-Falcon et al., 2024):**  
  Alertam que taxas elevadas de abstenção em perguntas fechadas conceituais distorcem a avaliação de qualidade. Um sistema com recusa em 80% das perguntas pode aparentar precisão artificial nos 20% restantes, enquanto a métrica de *cobertura útil* (respostas corretas com fonte que as sustenta) desaba.
- **Risco Operacional:** Em auditorias de segurança, o analista necessita de síntese fiel dos padrões; a recusa indevida com a fonte presente na mesa anula o ganho operacional do pipeline.

---

## 4. Fontes Públicas e Literatura de Referência (8 Fontes Selecionadas)

1. **Gao et al. (Stanford University, EMNLP 2023)**
   - *Título:* "Enabling Large Language Models to Generate Text with Citations" (ALCE).
   - *URL:* https://aclanthology.org/2023.emnlp-main.398/
   - *Contribuição:* Separação dimensional entre fluência, acurácia da resposta e precisão/recall de citação em geração atribuída.
2. **Min et al. (University of Washington, EMNLP 2023)**
   - *Título:* "FActScore: Fine-grained Atomic Evaluation of Factual Precision in Long Form Text Generation".
   - *URL:* https://aclanthology.org/2023.emnlp-main.741/
   - *Contribuição:* Decomposição de claims complexas em átomos factuais; demonstra que âncoras válidas não provam relações compostas.
3. **Honovich et al. (Google Research, NAACL 2022)**
   - *Título:* "TRUE: Re-evaluating Factual Consistency Evaluation under Realistic Conditions".
   - *URL:* https://aclanthology.org/2022.naacl-main.287/
   - *Contribuição:* Demonstração dos limites de correspondência de substring e fundamentação empírica de NLI para consistência factual.
4. **Dhuliawala et al. (Meta AI, Set/2023)**
   - *Título:* "Chain-of-Verification (CoVe) Reduces Hallucination in Large Language Models".
   - *URL:* https://arxiv.org/abs/2309.11495
   - *Contribuição:* Protocolo de geração de perguntas de checagem interna para validar claims antes da emissão final.
5. **Es et al. (Exploding Gradients / RAGAS, Set/2023)**
   - *Título:* "RAGAS: Automated Evaluation of Retrieval Augmented Generation".
   - *URL:* https://arxiv.org/abs/2309.15217
   - *Contribuição:* Métricas de Faithfulness, Answer Relevance e Context Recall com penalização de recusas injustificadas.
6. **Saad-Falcon et al. (Stanford University, NAACL 2024)**
   - *Título:* "ARES: An Automated Evaluation Framework for Retrieval-Augmented Generation Systems".
   - *URL:* https://aclanthology.org/2024.naacl-long.20/
   - *Contribuição:* Calibração de juízes de contexto e fidelidade contra anotações humanas independentes.
7. **Asai et al. (Univ. of Washington / Allen Institute, Out/2023)**
   - *Título:* "Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection".
   - *URL:* https://arxiv.org/abs/2310.11511
   - *Contribuição:* Classificação de suporte de evidência em totalmente suportado, parcialmente suportado ou não suportado.
8. **Anthropic Research (Anthropic, 2023)**
   - *Título:* "Prompting for Long Context: Document Citation and Extraction Architectures".
   - *URL:* https://www.anthropic.com/news/prompting-long-context
   - *Contribuição:* Padrão de prompt com extração de citações textuais em tags estruturadas antes da redação da síntese.

---

## 5. Recomendações em 3 Níveis (Com Status de Decisão QA)

### Nível 1: Só Contrato (REJEITADO PARA PRODUÇÃO; Autorizado Estritamente como DEV Experimental)
- **Status:** **BLOQUEADO EM PRODUÇÃO PELO QA.**
- **Conceito Original:** Proposta de expandir a checagem de quote para fora do snippet recuperado (`anchor_quote in document_text`).
- **Motivo do Bloqueio:** O QA identificou risco grave: permitir que a quote venha de partes do documento que nunca foram transmitidas ao compositor cria divergência entre o contexto que o modelo leu e o contexto validado, podendo aceitar alucinações coincidentes com texto não visto.
- **Diretiva:** Qualquer protótipo experimental de contrato deve manter a validação restrita ao **snippet transmitido** (`normalized(quote) in normalized(snippet)`).

### Nível 2: Só Prompt (Aprovado para Investigação e Experimentação Isolada)
- **Status:** **APROVADO PARA EXPERIMENTAÇÃO EM BRANCH SEPARADO.**
- **Implementação:** Ajuste exclusivo no prompt de composição (`composition_prompt`) sem alterar o código de `bin/mitr3-answer.py`:
  1. *Etapa de Extração:* "Selecione citações literais dos snippets fornecidos que sustentam a análise e preencha o campo `quote` com o trecho exato."
  2. *Etapa de Síntese:* "Redija a resposta em linguagem natural no campo `claim`, referenciando exclusivamente os IDs e trechos literais de suporte já selecionados."
- **Objetivo:** Reduzir a ocorrência de `MODEL_ABSTAIN` voluntário e eliminar erros de `QUOTE_NOT_LITERAL` decorrentes de pequenas edições sintáticas do modelo dentro da citação.

### Nível 3: Nada (Status Quo Mantido em Produção)
- **Status:** **ATIVO E MANDATÓRIO NA LINHA PRINCIPAL.**
- **Diretiva:** Preservar a implementação atual do Gate D:
  - Citações estritamente literais no snippet autorizado;
  - Rejeição de qualquer citação inexistente (`QUOTE_NOT_LITERAL`);
  - Preservação da abstenção estrita em itens sem evidência (`NO_EVIDENCE` e `MODEL_ABSTAIN`);
  - Nenhuma proposta recebe status de validação factual plena sem revisão humana independente.

---

## 6. Conclusão e Diretriz Operacional

A revisão de QA confirmou que a garantia de segurança do MITR3 repousa na **impossibilidade de injetar afirmações sem proveniência rastreável**. A citação literal não garante que a interpretação esteja correta (como provam os 3 casos do §2), mas impede que o modelo invente fontes.

A linha de ação estabelecida é:
1. Manter o Gate D de produção congelado e estrito.
2. Realizar a calibragem por revisão humana claim-a-claim dos resultados cegos existentes (v3/v4).
3. Conduzir experimentos de prompt *extract-then-synthesize* exclusivamente em fixtures DEV não-cegas.
4. Qualquer proposta futura de transição exigirá criação de um novo conjunto cego v5 por autor independente, com medição pareada e validação humana dupla.
