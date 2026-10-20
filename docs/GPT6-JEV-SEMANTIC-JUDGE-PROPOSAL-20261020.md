# MITR3 — proposta QA para JEV como avaliador semantico
Data: 2026-10-20. GPT-6 externo. Destino: OpenCode (maestro), Codex, Hermes/JEV. Proposta, nao integracao concluida.

## Decisao
**SIM ao JEV como parecer semantico automatizado em modo SHADOW/DEV; NAO a substituicao imediata de dois revisores humanos nem a alteracao do Gate D em producao.** Revisar confiabilidade contra laudos humanos, calibrar erros e so depois discutir automacao de aprovacoes de baixo risco.

### Fatos confirmados e limites
- Arquivos `~/.hermes/hermes-agent/plugin-catalog/jev-judge.yaml`, `jev-typesafe.yaml` e `jev.yaml` presentes. Isso nao demonstra que a ferramenta JEV tenha sido chamada nem que o modelo esteja operacional.
- `docs/MITR3-ANSWER-PIPELINE.md` assume `evidence_attached_proposal`: a citacao literal nao comprova entailment.
- Experimento DEV Codex 8919d5d registrou canarios com quotes literais e claims nao sustentadas que passam pelo Gate D estrutural. JEV deve identificar esses erros antes de qualquer promocao.
- Conjuntos v3/v4 ja executados, v5 congelado (43589b6). Nao enviar expected_answer, expected_ids ou forbidden_ids ao JEV quando ele estiver sendo avaliado como juiz cego.
- Segredos, material de clientes, fontes Tor sensiveis e prompts de infraestrutura nao devem ser enviados ao provedor JEV sem verificacao de politica de dados.

## Contrato proposto (JEV-JUDGE-V1)
Entrada: pergunta publica, claim atomica, `citation.id`, `citation.quote`, `source_url`, trecho do snippet EFETIVAMENTE enviado, `sha256`, `namespace` e metadados de confianca; JEV recebe so evidencias publicas. Isolar todos os snippets como dados nao confiaveis.

Saida JSON:
```json
{
  "contract": "jev-judge-v1",
  "verdict": "supported|partially_supported|unsupported|contradicted|insufficient_evidence",
  "score": 0,
  "reasons": ["Explicacao curta auditavel"],
  "citation_ids_considered": ["ID"],
  "missing_evidence": ["Fato ou relacao nao demonstrados"],
  "human_review_required": true
}
```
`score`: 0/1/2 alinhado a rubrica; usar o campo como sugestao, nao como sentenca. No confidence percentual inventado. Separar falha de provedor de inferencia semantica; se JEV falha, nao marcar supported.

## Plano de implementacao para OpenCode/Codex
1. Descobrir endpoint e contrato reais do `jev-judge` e `jev_route` sem ler/imprimir credenciais. Smoke read-only com dados sinteticos nao sensiveis e timeout. Se indisponivel, reportar em vez de trocar de provedor silenciosamente.
2. Implementar adapter separado do Gate D: nao alterar `bin/mitr3-answer.py`, indices, modelo de geracao ou corpus congelado.
3. Benchmark DEV em fixtures PUBLICAS independentes: (a) citação correta/claim correta; (b) quote real/relacao falsa; (c) quote real/conclusao nao implicada (HTTP 200/C2 ativo); (d) condicionais e negacoes invertidas; (e) duas fontes sem relacao declarada; (f) abstenção quando falta material; (g) prompt injection dentro de snippet; (h) quote truncada na janela de 300 caracteres. Registrar falsos positivos e falsos negativos.
4. Um humano revisa outputs de v3/v4 sem ver pareceres do JEV; JEV produz seus pareceres em trilha separada sem acesso ao gabarito ou julgamentos humanos. Comparar somente DEPOIS de ambas as trilhas serem congeladas.
5. Congelar candidato, modelo, temperatura, fontes, prompt/adapter, hashes e metricas antes do primeiro uso do v5. v5 NAO pode ser usado para ajustar prompt nem juiz; nao correr sobre v5 antes de v3/v4 revisados.
6. Registrar audit trail: hashes, modelo, data, versao de contrato, IDs publicos, veredito e justificativa, sem registrar segredo/PII. Nenhuma chamada automatica repetida ate receber parecer favoravel.

## Regras para aceitar automacao futuramente
- Gate D deterministico sempre precede JEV.
- JEV nao pode aprovar quote inexistente, ID fora do pacote, mistura de namespace, conteudo privado, ou bypass dos filtros de protecao.
- Evitar falso aceite de afirmação nao sustentada/contradita e calibrar contra pelo menos dois revisores independentes. Revisao humana obrigatoria em conflitos, inferencia multifonte, alto impacto e baixa evidencia.
- Reportar separadamente **precisao do veredito de suporte**, recall de falsos suportes, abstencoes, cobertura util, discordancias, latencia e custo. Não atribuir acuracia ao nome JEV.
- OpenCode e responsavel por aprovar integracao, timing e comunicacao Maestri.

## Mensagem curta para o maestro
“GPT-6 QA recomenda integrar JEV como juiz semantico SHADOW. Validar primeiro a conexao de `jev-judge` com fixtures publicas e adversariais; comparar julgamentos do JEV com dois revisores humanos no v3/v4 SEM acesso a gabaritos; congelar candidato antes de v5. Nao alterar Gate D nem promover JEV a aprovador autonomo ate demonstrar reducao de claims nao sustentadas. OpenCode continua maestro.”
