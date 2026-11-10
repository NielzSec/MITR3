# Gate de evidência tipada v1 — hardening R2

Gate separado do validador estrutural. Reutiliza o schema result v0.1 sem adicionar campos a resultados antigos. Não executa amostras, tráfego ou ferramentas arbitrárias.

```sh
python3 -m hackbots.tools.semantic RESULT.json --mission MISSION.json
python3 -m hackbots.tools.semantic RESULT.json --mission MISSION.json --assertions ASSERTIONS.json
```

Sem sidecar, claims livres permanecem INSUFFICIENT_EVIDENCE, com lista de evidências não avaliadas. Fontes fora da missão e sem manifesto do revisor bloqueiam o gate. Exit 1 significa relatório pendente/bloqueado semanticamente; exit 2 significa entrada inválida. Não existe exit 0 de aprovação.

## Sidecar

Envelope em contracts/semantic-assertions.schema.json. schema_version é o inteiro 1. Fixe SHA256 dos bytes exatos de missão e resultado. Cada assertion referencia índice base zero da claim, predicado allowlisted, IDs citados pela própria claim e parameters.

Exemplo de assertion (dentro do envelope):
```json
{"claim_index": 0, "predicate": "jwt_alg_none", "evidence_ids": ["AUTH01-E1"], "parameters": {}}
```

O sidecar é interpretação não autenticada, a ser revisada. Não se usa observation nem locator livre como fato. As regras recuperam fatos dos bytes da fonte cujo hash foi validado.

| Predicado | Parâmetros / alcance |
|---|---|
| json_equals | pointer (JSON Pointer), value; política do Evaluator: int distinto de Decimal e bool, decimais exatos; 1.0 e 1e0 equivalentes, 1 e 1.0 distintos |
| text_span | start_line, end_line, quote; linhas físicas LF, base 1, inclusivas; texto exato |
| jwt_alg_none | {} — decodifica jwt_header base64url JSON |
| jwt_exp_absent | {} — decodifica jwt_payload e verifica ausência de exp |
| jwt_unlimited_lifetime | {} — insuficiente sem política do servidor |
| cookie_http_only_disabled | {} — flag declarada, não armazenamento ou roubo |
| cookie_cross_site_sent | {} exige verificação externa; browser_policy=none_requires_secure fixa apenas um cenário de política |
| openapi_security_absent | {} — alias legado ambíguo; sempre INSUFFICIENT_EVIDENCE; migrar para o predicado abaixo |
| openapi_components_security_schemes_key_absent | {} — versão 3.x.y, info.title/version, paths objeto e components objeto; só ausência da chave components.securitySchemes, mesmo com security global presente |
| http_200_declared | {} — checa observed_response.status, não requisição executada |
| analysis_complete | {} — status e cobertura declarados, não execução observada |
| jwt_unsigned_accepted, cookie_transport_exposure, session_theft_confirmed, csrf_confirmed | {} — requerem verificação externa |
| http_request_executed, sqli_confirmed, endpoint_exists, browser_xss_confirmed, server_ssrf_confirmed, binary_analyzed, tool_executed | {} — requerem recibos/runtime externos |

Todos os demais parâmetros são rejeitados. Nenhum predicado aceita um trace fabricado no sidecar como prova de execução.

## Leitura do relatório

classification_scope=TYPED_ASSERTIONS_ONLY. CONSISTENT refere-se exclusivamente ao predicado, nunca ao texto completo da claim. Uma claim maliciosa pode ser mapeada para um fato trivial: text_entailment e observation_entailment permanecem NOT_VERIFIED, inclusive com todos os predicados consistentes. A suíte contém esse ataque.

Claims sem mapeamento ou com evidência citada não avaliada adicionam INSUFFICIENT_EVIDENCE. claim_evidence_coverage expõe cited_evidence_ids, evaluated_evidence_ids, unchecked_evidence_ids, unauthorized_evidence_ids e contradictory_evidence_ids por claim. A cobertura é a união das assertions daquela claim, nunca uma união global. Avaliada significa que o predicado foi tentado; pode resultar em insuficiência e não comprova entendimento do texto. Agregação, da menor para maior restrição: CONSISTENT, EXTERNAL_VERIFICATION_REQUIRED, INSUFFICIENT_EVIDENCE, CONTRADICTORY, STRUCTURALLY_INVALID. Consulte também cada assertion; uma classificação agregada pode coexistir com necessidades distintas.

semantic_gate é BLOCKED para entrada inválida, contradição, resultado status=blocked ou fonte não autorizada. Um resultado blocked conserva completion=BLOCKED e classificação agregada pelo menos INSUFFICIENT_EVIDENCE, mesmo com facts individuais CONSISTENT. REVIEW_REQUIRED cobre os demais casos; nunca é aprovação. human_approved=false, promotable=false, behavioral_gate=NOT_RUN, execution_verification=NOT_VERIFIED sempre.

claim_text_sha256 vincula cada linha à claim sem reproduzir seu texto. Hashes de fontes, sidecar, missão e resultado vinculam a avaliação, mas não autenticam o produtor nem resistem a um atacante com escrita no mesmo UID. runtime_sha256 observa arquivos em disco: não atesta o código carregado. O schema de assertions é lido e hasheado no mesmo snapshot. Não publique hashes privados sem revisão.

## Integração e limites

O Maestro pode executar o gate como etapa separada e anexar o JSON à revisão. A CLI estrutural continua compatível; ela não passa a ser gate semântico. Este incremento não altera terminais, permissões ou fluxo operacional de aceite.

Para novos adaptadores, prefira fatos estruturados e premissas verificáveis. Não acrescente heurísticas de palavras como confirmação de verdade. Recibos de execução exigem custódia do supervisor e revisão independente; o Runner atual mede entrega de intervalos, não compreensão do código.

Validação: python3 -m unittest discover -s hackbots/tests -q
Relatório de engenharia, cenários e plano das 16 skills: reviews/astra/mitr3-quality-upgrade-20261024/REPORT.md.

## Fontes autorizadas pelo revisor

O artefato canônico de mission.artifact.path + sha256 é autorizado por padrão. A missão é entrada de confiança do revisor, não algo que o resultado possa ampliar. Fonte adicional exige manifesto externo ao sidecar e SHA256 informado pelo revisor separadamente.

```
python3 -m hackbots.tools.semantic RESULT.json --mission MISSION.json --assertions ASSERTIONS.json --sources-manifest SOURCES.json --sources-manifest-sha256 PIN_DO_REVISOR
```

Manifesto v1 (schema semantic-sources.schema.json): schema_version=1, mission_sha256 dos bytes exatos da missão e sources com objetos path/sha256. Até 31 declarações auxiliares. Paths são relativos ao projeto, hashes são conferidos no arquivo local; duplicatas, conflitos, caminhos inseguros, pin ausente/incorreto e outra missão bloqueiam. O próprio sidecar não pode definir sources.

SPECTER: declarar previamente baseline.http no manifesto e conferir seu hash independentemente. expanded.http já vem da missão. W01.pair.json é dado auxiliar; o gate não o transforma automaticamente em autoridade. O pacote QA R2 contém um exemplo concreto com os dois pins conferidos, sem editar missão ou resultado originais.

source_authorization_gate é PASS para vínculo de arquivos aos pins fornecidos, não autenticação de identidade do revisor. unauthorized_evidence_ids sinaliza qualquer fonte declarada sem autorização. Seu conteúdo não é avaliado como fato autorizado e gera source_not_authorized; evidências restantes ainda são avaliadas independentemente.

## Precisão e compatibilidade R2

- O sidecar continua schema_version=1; os campos do relatório são aditivos e gate_revision=r2. Consumidores que rejeitam campos desconhecidos precisam ser atualizados.
- D4: alias antigo continua aceito, mas insuficiente. Atualizar o predicado só após revisar a claim: ausência da chave não equivale a ausência de segurança. O check de forma mínima não substitui validação integral OpenAPI.
- D5: por compatibilidade com Skill Evaluator, 1 e 1.0 continuam distintos. A equivalência numérica JSON proposta pelo Sonnet não foi adotada; exigiria mudar a política dos dois componentes e versionar oráculos. O parser semântico usa Decimal para não arredondar fontes/valores. validate.parse_json mantém o comportamento padrão e oferece exact_numbers=True opt-in.
- D6: text_span não UTF-8 recebe INSUFFICIENT_EVIDENCE/source_not_utf8 naquela evidência; as demais assertions são preservadas.
- D7: SameSite usa comparação sem caixa, sem coerção de tipos; política do browser continua explícita.
- O gate não verifica se o manifesto antecedeu cronologicamente a execução nem autentica seu autor. O pin deve vir de custódia independente; CLI sob o mesmo UID não fornece essa custódia.

QA R2: reviews/astra/mitr3-semantic-hardening-r2-20261024/REPORT.md.
