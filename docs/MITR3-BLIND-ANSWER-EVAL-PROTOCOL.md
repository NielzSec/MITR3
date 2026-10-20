# MITR3 — Protocolo de avaliação cega de respostas

**Data:** 2026-10-20 · **Status:** ativo · **Escopo:** medir resposta, não recuperação

## Por que existe

O eval atual (`bin/mitr3-rag-eval.py`) mede o que o sistema **encontra**. Não mede
se a resposta final está correta, nem se as fontes citadas sustentam o que foi
dito. Um sistema pode ter recall@5 de 100% e responder errado com a fonte certa
aberta na mesa.

## Regra que sustenta o resto

**Quem ajusta o mecanismo não escreve o gabarito e não corrige a prova.**

O conjunto é congelado antes da primeira execução. Correção depois da primeira
rodada só entra como `v2` — nunca como edição do `v1`. Sem isso, o número sobe
por ajuste do gabarito, não por melhora do sistema.

## Composição do conjunto

| item | regra |
|---|---|
| tamanho | 20 perguntas (16 com resposta, 4 que exigem abstenção) |
| origem | trabalho real das frentes (Robin/m12, Hermes/lab, Codex/código) |
| autoria | quem viveu o trabalho escreve pergunta **e** resposta |
| escrita | resposta escrita de cabeça, sem abrir o índice |
| congelamento | commit + sha256 do arquivo; data no nome |
| proibido | pergunta derivada de documento do próprio corpus (vira teste de espelho) |

## Formato do item

```json
{
  "id": "blind-<frente>-<nn>",
  "question": "texto exatamente como o analista perguntaria",
  "expected_answer": "2 a 4 frases: o que precisa estar certo",
  "expected_ids": ["CVE-...", "CASE-...", "T1059.001"],
  "forbidden_ids": ["documento que seria erro citar aqui"],
  "abstain": false,
  "author": "robin|hermes|codex",
  "written_at_utc": "2026-10-20T..."
}
```

`abstain: true` significa: a resposta correta é dizer que o corpus não sustenta a
pergunta. Qualquer citação nesses itens conta como erro, mesmo que a fonte exista.

## Métricas

| métrica | definição | meta inicial |
|---|---|---|
| correção da resposta | 0 errada / 1 parcial / 2 correta, por dois revisores humanos | média ≥ 1,5 |
| precisão de citação | citações em `expected_ids` ÷ citações totais | ≥ 0,80 |
| cobertura de fonte | `expected_ids` citados ÷ `expected_ids` | ≥ 0,70 |
| citação proibida | qualquer `forbidden_ids` citado | 0 |
| abstenção correta | 4 itens `abstain:true` sem citação | 4/4 |

Nenhuma dessas notas é dada por LLM. Dois revisores humanos; divergência de 2
pontos vai para um terceiro. O tuner vê apenas o agregado e a lista de falhas
**depois** da rodada.

## O que conta como falha grave

1. Citar fonte que não existe.
2. Citar fonte que existe mas não diz o que a resposta afirma.
3. Responder com confiança em item `abstain:true`.
4. Fundir namespaces: usar aresta ATT&CK como prova de relação CVE/CWE (ou o
   contrário), ou citação do MegaBrain como validação de vínculo local.

## Ligação com o que já existe

- `mitr3-rag-intel.py search` — recuperação (já medida).
- `mitr3-context-bridge.py` — resposta com evidência local + namespace separado.
- `tests/fixtures/intel-relevance-v1.json` — 30 consultas, conjunto **conhecido**;
  serve para regressão, não para atestar qualidade.
- Este protocolo — o único número que pode ser chamado de qualidade de resposta.
