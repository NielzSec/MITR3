# Runner congelável baseline/candidato — 2026-10-20

Implementa `CANDIDATE-FREEZE-SPEC-20261020.md` (e8177f0), em branch isolada
`codex-candidate-run-dev-20261020`, baseada nesse commit. **Nenhuma execução do
v5 foi feita nesta entrega; nenhum gabarito v5 foi aberto ou decodificado.**
O runner não decide promoção, não calcula métricas de gabarito e não altera
`mitr3-answer.py`, Gate D, prompts de produção, busca, corpus ou conjuntos.

## Arms e interface

`bin/mitr3-candidate-run.py SET --arm baseline|candidate --output NOVO.json`
usa o mesmo modelo por padrão: `dahl/deepseek-ai/DeepSeek-V4-Flash-0731`.
Workers 4, timeout total por tentativa 90 s, uma repetição exclusivamente para
`MODEL_TIMEOUT`/`MODEL_FAILED`. Ambos os braços têm a mesma interface pública,
a mesma ordem de itens na saída e o mesmo orçamento por tentativa. Cada
repetição reinicia o pipeline inteiro, como no runner cego.

- **baseline:** delega diretamente a `mitr3-blind-run.call_answer(question,
  model, timeout)`. Portanto executa exatamente o subprocesso existente:
  `python bin/mitr3-answer.py QUESTION --json --model MODEL`, com os mesmos
  limites, tratamento de erros e limpeza do grupo de processos.
- **candidate:** usa `plan_prompt`, `model_call`, `plan_gate` e
  `evidence_package(queries, 5, False)` do mesmo `mitr3-answer.py`. A extração
  retorna exclusivamente `{"extracts":[{"id":string,"quote":string}]}`,
  até oito pares. Cada par é verificado pelo Gate D existente, com uma claim
  neutra `Source passage.`; rejeitados não entram no envelope de extrações.
  Se nenhum par sobreviver, recusa com `NO_VERIFIED_EXTRACTS`, sem síntese.
  A síntese usa exatamente o prompt do modo `required` do experimento
  8919d5d, copiado com a função de extração, sem carregar suas fixtures.
  Somente `required` é chamado pelo runner. A composição resultante, sem
  reparos, passa pelo mesmo `gate(composed, original_package)` de produção.

O pacote original permanece no prompt de síntese, como no experimento; pares
validados são auxiliares de recuperação, não vereditos de entailment. Nenhuma
quote ausente é preenchida e nenhum resultado rejeitado é promovido por fallback.
Os envelopes escapam tags dentro dos dados e declaram evidência não confiável.
O transporte é exatamente `answer.model_call`, inclusive `--agent plan`, seu
limite interno de 120 s e eventual `MITR3_MODEL_CMD`. O limite externo de 90 s
encerra o grupo de processos completo, também no candidato. Temperatura e
limites de geração são herdados, sem parâmetros adicionais. Os dois braços
precisam usar o mesmo ambiente/configuração; um override é registrado apenas
por presença e SHA256, nunca pelo comando bruto potencialmente sensível.

## Projeção de dados e privacidade

O carregador exige dez objetos com IDs únicos e perguntas válidas. Ele decodifica
apenas os valores `id` e `question`. Demais valores são saltados por um lexer
JSON com validação sintática e limite de profundidade, sem `json.loads` nesses
valores e sem construir objetos de gabarito. Nomes de campos são reconhecidos
para projetar o objeto; seus valores ignorados nunca entram nos prompts,
relatórios ou métricas. O arquivo bruto necessariamente é lido para computar o
SHA256 de bytes congelado, o que não interpreta seu gabarito. Limite: 8 MB.

O relatório preserva `at_utc/set/sha256/model/pass/rows` e acrescenta arm,
commit, hashes, configuração e totais. Por item: ID, abstenção, código de erro
permitido, número de claims, IDs públicos de citações, tentativas/latências,
categoria e metadados de etapas. Não guarda pergunta, prompt, resposta, quote,
URL privada ou corpo de documento. Saída do worker é reprojetada por allowlist;
erros não reconhecidos viram código fixo. Relatórios são reservados antes das
chamadas com criação exclusiva, modo 0600; nunca sobrescrevem arquivos nem
escrevem no diretório de evals. Uma falha pode deixar um arquivo reservado vazio;
usar outro nome após investigar, nunca reutilizar um relatório congelado.

No candidato, etapas incluem contagem de queries/documentos/extrações,
comprimentos de snippets, hash do pacote e contagem de quotes literais.
`quote_count` conta campos quote string presentes na composição e
`literal_quote_count` conta os que existem na janela original, mesmo se o
Gate D rejeitar o resultado. Essas contagens não reparam ou aprovam a resposta.
No baseline a chamada é opaca: pacote e contagens de quotes são `null`/
`unobserved_baseline`, sem inventar observações nem instrumentar produção.
`nonempty` indica presença de texto, **não suficiência semântica**.

Categorias separam `answered_gate`, `MODEL_ABSTAIN` (`abstained`), falhas
operacionais (`failed`) e recusas estruturais (`blocked`), mantendo o erro exato.
`forbidden_ids_hits`, controles negativos, sustentação semântica e critérios
C1–C4 precisam de adjudicação externa posterior: calculá-los neste runner
exigiria acessar rótulos que ele não recebe. Não confundir contagem de respostas
aceitas pelo gate com resposta semanticamente correta.

## Comandos congelados para execução futura autorizada

**Não executados nesta tarefa.** Primeiro obter a assinatura de Kai na spec e
na adjudicação. `--operator-approved` apenas atesta essas assinaturas; não as
valida automaticamente. Congelar este commit, conferir hashes abaixo e manter
máquina, sessão, índice, ambiente e configuração iguais, sem ajustes entre arms.
O SHA do conjunto abaixo é copiado da spec, sem consultar o arquivo v5.

```sh
# Registrar antes da execução e usar o mesmo checkout nos dois arms:
git rev-parse HEAD
sha256sum bin/mitr3-answer.py bin/mitr3-blind-run.py bin/mitr3-candidate-run.py

# 1. Baseline primeiro, somente após assinatura:
python3 bin/mitr3-candidate-run.py evals/blind/blind-answers-robin-v5.json \
  --arm baseline --model dahl/deepseek-ai/DeepSeek-V4-Flash-0731 \
  --workers 4 --timeout 90 --pass 1 --operator-approved \
  --expected-set-sha256 550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84 \
  --output reports/candidate-v5-baseline-run1.json

# 2. Candidato depois, sem alteração intermediária:
python3 bin/mitr3-candidate-run.py evals/blind/blind-answers-robin-v5.json \
  --arm candidate --model dahl/deepseek-ai/DeepSeek-V4-Flash-0731 \
  --workers 4 --timeout 90 --pass 1 --operator-approved \
  --expected-set-sha256 550793412774fb1daadba220290c1ba5f56797b5748797c4ba135526a4c67c84 \
  --output reports/candidate-v5-candidate-run1.json
```

O hash de entrada é conferido antes das chamadas e novamente ao carregar o
lote, evitando que troca do arquivo após reserva inicie um lote divergente.
Hashes dos artefatos são conferidos antes e depois; divergência invalida o
relatório. Não há seleção automática do v5, chamada de juiz ou leitura de gabarito.
O commit candidato final é o commit único desta branch, registrado por
`git rev-parse HEAD` nos relatórios futuros; a tabela abaixo congela conteúdo,
sem criar referência circular ao próprio hash de commit.

## SHA256 congelados

| Artefato | SHA256 |
|---|---|
| `bin/mitr3-answer.py` | `4ba78d9a0b57e6bfaad6524e95cd81d266f2ba071eeaba61ad8551ed114c29ab` |
| `bin/mitr3-blind-run.py` | `15a4e823822fd3d67739b2b03d1b7c3fc92739bda43798a2e1c2430288aacd3c` |
| `bin/mitr3-candidate-run.py` | `fa83aa477ef7ecfa081bb503626e509426242c4777f95e6839c6e09788f117c6` |
| `bin/mitr3-context-bridge.py` | `e89ed65620fccf1c4eb05fa38e7b1cdb33c201bcdbdfcdb6bf3a142118c1d9f4` |
| `bin/mitr3-rag-intel.py` | `57bac3d59f414b16817b3a93e5981638ce9988254bfdcf57dc789897f2deb5d6` |
| `docs/CANDIDATE-FREEZE-SPEC-20261020.md` | `ef5ec791003abc6f927ca7389fd19f83ccd1efe1269b3bc76af0ceec555fd402` |
| `extraction_prompt_source` | `1633414e63ceee150bc3be6889a6a5fd2bf9580e0eb37cec2413615588073537` |
| `required_synthesis_prompt` | `2f65d7b18a240a0428b17b0df7983b97b2ebdc5ed589bd78d33028b6b457a4b8` |
| `state/mitr3-intel.sqlite3` | `1dac5585c70328d864290fcc2b30bd1257fed245c33923ff05cd52cc2a09066a` |
| `state/mitr3-attack.sqlite3` | `60827b12fdbc09923ec1f4a3ec9c6bd0f88c6bba8ba3c8694fcc317f3d92c866` |
| `knowledge/reference-datasets/cache/manifest.json` | `3a5d108d10d678fbe5542cffe38a673177fb2f0af476694468e905ab35b3d23a` |
| `knowledge/reference-datasets/cache/enterprise-attack-manifest.json` | `92160406053997f9bc1ed269e3628b6d56e393e8aa7ed7ae78d603047b79de67` |
| `tests/test_candidate_run.py` | `7b14e6aa52e0b10a222572040c20c442cc299e814e55f0dd4d151a80801a3e3d` |

`extraction_prompt_source` é o SHA256 UTF-8 de `inspect.getsource(extraction_prompt)`.
`required_synthesis_prompt` é o SHA256 UTF-8 de `synth_prompt('', [], [], 'required')`,
instância canônica sem dados. Os índices/manifests são caches públicos locais;
se seus hashes mudarem, a comparação precisa de novo freeze antes de qualquer run.

## Validação DEV

**200 testes verdes**, incluindo 23 novos, com ResourceWarning como erro:

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests
```

Testes próprios usam perguntas sintéticas temporárias, `model_fn`/recuperação
mockados e subprocessos Python locais, sem rede. Cobrem paridade de resultado,
plano e recuperação, delegação exata do baseline, projeção que faz o decoder
falhar se receber valor de gabarito, extrações inválidas/ausentes, quote final
inventada, namespace, schema obrigatório, abstenção, ausência de evidência,
paralelismo, timeout/limpeza, retry, proteção de saída, consentimento/hash e
remoção de texto bruto de workers. Não se executou modelo real, v5, conjunto
cego ou benchmark semântico nesta entrega. Não há resultado de comparação
baseline/candidato; essa medição continua reservada ao operador.
