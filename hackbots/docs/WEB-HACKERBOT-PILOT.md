# MITR3 — Web Hackerbot / piloto de evidência diferencial v0.1

**Estado:** OFFLINE_METADATA_QA_ONLY. Sem Web Hackerbot LLM, sem novo acesso
de rede, sem alteração de políticas de missão e sem execução autônoma.

## Primeiro caso confirmado pelo operador — PortSwigger
- Academy: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data.
- Instância estritamente autorizada usada pelo operador: `0a75003b0446b842825188c9008a00a4.web-security-academy.net`.
- Execução HTTP manual por GPT-6 em 23/10/2026; `GET /`, baseline e **um** PoC.
- Categoria `Gifts`: 3 IDs, HTTP 200; filtro manipulado: 20 IDs, HTTP 200.
  17 produtos adicionais; conjunto original inteiro presente no PoC.
- **O operador confirmou que a Academy marcou o laboratório como resolvido**.
  Esse fato é declaração do operador, sem consulta à API da conta ou captura autenticada.
- Referência da observação anterior:
  `reviews/gpt/portswigger-sqli-manual-20261023/REPORT.md`.
  As respostas HTML completas não foram salvas, apenas seus digests e contagens.

## Entregue nesta etapa: QA determinístico (não agente)
`hackbots/tools/web_evidence.py`: avaliador **offline** de um JSON de
observação manual. Nenhuma requisição HTTP, execução de payload ou shell.
Exige `schema_version=1`, dois estágios `baseline,poc`, status,
contagem de bytes, SHA256 declarado, produtos sem duplicatas e campos
estritos. Inconclusivo se status não 200 ou conjuntos não monotônicos.
Rejeita hash idêntico em observações com conjuntos contraditórios,
symlinks, hardlinks e JSON de chaves duplicadas.

A fixture é
`hackbots/examples/web/portswigger-sqli-manual-20261023.json`.
**O resultado valida somente a coerência dos metadados declarados**.
Não recompõe respostas, não verifica SHA256 de HTTP contra bytes ausentes,
não distingue sozinho manipulação de dados de outros comportamentos e
não demonstra que um modelo fez a descoberta.

Rodar, sem rede:
```sh
cd ~/MITR3
python3 -m hackbots.tools.web_evidence hackbots/examples/web/portswigger-sqli-manual-20261023.json
python3 -m unittest discover -s hackbots/tests -p test_web_evidence.py -v
```

O resultado esperado tem `additional_id_count=17`,
`baseline_subset_of_poc=true` e
`evidence_state=DIFFERENTIAL_RECORDED_NOT_AUTHENTICATED`.
Sempre `trace_gate=NOT_RUN`, `behavioral_gate=NOT_RUN`,
`independent_review=NOT_RUN`, `promotable=false`.

## Próximas etapas do primeiro Web Hackerbot
1. **QA do oráculo**: segundo revisor confere a especificação, o operador
   confirma a versão do laboratório e aprova corpus sem segredos.
2. **Fixtures de respostas sintéticas byte-a-byte**: incluir caso positivo,
   mudança sem SQLi, HTTP 4xx, conjunto não monotônico, resposta dinâmica
   e caso sem evidência suficiente; definir oráculo externo fixado.
3. **Especialista narrow-scope**: habilidade de diferenciar baseline e
   resposta manipulada em artefatos locais, sem chamar HTTP nem iniciar Docker.
   Ferramentas permitidas: `read_interval`, `submit_result`.
4. **Medir**: acerto factual, falsos positivos/negativos, cobertura, tempo,
   tokens, justificativa e referências. Primeiro ensaio em laboratório offline.
5. **Gate operacional**: F01 / identidade/custódia e revisão independente
   antes de vincular ao Maestro Morfeus ou habilitar testes HTTP por agente.

Não reutilizar esta observação como benchmark de exploração real independente
sem coletar artefatos completos em um futuro laboratório explicitamente autorizado.


## B1 / v0.2 — benchmark de corpos sintéticos

Namespace separado: `hackbots.tools.web_benchmark`, fixtures HTTP inteiras e suíte
`hackbots/examples/web/fixtures/suite-v2.json`. Leitor limitado rejeita links e
recalcula SHA256 dos bytes HTTP inteiros, Content-Length e IDs pelo perfil HTML
controlado; não confia em product_ids declarados. O formato manual v0.1 permanece
inalterado. Execute com --suite-sha256 previamente revisado.

15 casos incluem diferencial, identidade, HTTP 403, falta de IDs, não monotonicidade,
HTML/UTF-8 inválidos, duplicatas, mutação/hash incorreto, excesso de tamanho e texto
de prompt injection inerte. Links/FIFO/limites também são testados em temporários.
O resultado máximo é BENCHMARK_READY_FOR_INDEPENDENT_REVIEW, nunca Hackerbot
operacional, prova de SQLi ou behavioral_gate PASS. Integração Skill Evaluator NOT_RUN:
o [pacote do time](TEAM-PACK.md) agora fornece candidata Specter com auditoria
estrutural; ainda faltam suíte revisada com mapeamento Exx/Mxx e ensaio real da skill.

Detalhes, baseline divergente, testes e limitações:
`reviews/codex/hackerbots-b1-20261024T032927Z/WEB-BENCHMARK.md`. F01 continua OPEN.
