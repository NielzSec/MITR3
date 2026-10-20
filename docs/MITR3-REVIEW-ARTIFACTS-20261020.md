# Artefatos privados de revisão pareada — 2026-10-20

Correção DEV do NO-GO `GPT6-V5-PRE-RUN-NOGO-20261020.md` (cd64217, sha
`28675085…`). Branch final **codex-review-artifacts-final-20261020**, criada
diretamente de **f1c68e7**, com um único commit. O commit concorrente f4ab1ee,
feito na branch anterior, foi preservado; nenhuma história foi reescrita.
Não se executou o v5, não se leu seu gabarito e não se alteraram produção,
Gate D, prompts, busca, corpus, índices, conjuntos ou relatórios congelados.

## Captura nos dois braços

Ambos passam pelo worker do runner. O baseline executa a função original
`answer()` numa instância de módulo exclusiva, com observadores do retorno de
`evidence_package`, da entrada do gate e de seu resultado. Os observadores não
alteram prompts, argumentos ou resultados do gate. A chamada opaca anterior a
`BLIND.call_answer()` foi substituída porque descartava esse material. O teste
compara o resultado baseline observado com `answer()` sem observadores. O
candidato mantém a mesma extração e síntese `required` da base f1c68e7.
Transporte, modelo, timeout externo de 90 s, limpeza do grupo de processos e
um retry somente para MODEL_TIMEOUT/MODEL_FAILED permanecem.

Por item, braço e tentativa, o escrow registra ID, pergunta, modelo,
`claim.text`, `citations[{id,quote}]`, pacote efetivo com snippet, source_url,
namespace, SHA256 de origem e provas estruturadas quando presentes; hash do
pacote, etapas às quais foi enviado, veredito/código do gate e estado terminal.
Claims rejeitadas também são preservadas. Não guarda prompts completos,
comandos de configuração, stdout bruto nem propriedades arbitrárias do modelo.
O carregador continua decodificando somente id/question do conjunto; campos de
gabarito, rubrica e seus valores não entram em nenhum artefato de revisão.

Antes de uma chamada de extração/composição, já existe checkpoint durável com
o pacote. Timeout deixa o trecho transmitido revisável e distingue falha de
transporte de gate não alcançado ou interrompido. Cada tentativa tem arquivo
próprio. Resposta marcada como sucesso sem material de revisão provoca falha;
não há promoção sem escrow.

## Armazenamento e verificação

`bin/mitr3-review-artifacts.py` implementa armazenamento e verificador offline.
Diretório de execução novo, **0700**, fora de qualquer árvore Git; arquivos
novos **0600**, inclusive manifesto. Caminhos dentro do Git, mesmo ignorados,
e symlinks são recusados. Os arquivos externos não podem ser adicionados ao
Git deste workspace; o proprietário continua responsável por não copiá-los
manualmente para o repositório. Publicação atômica usa hard link exclusivo,
sem substituir destino. Diretórios e saídas existentes não são reutilizados.

Padrão: pasta UUID em `~/.local/share/mitr3/v5-review/`. Recomenda-se fornecer
`--private-dir` com nome novo conhecido pelo operador. O relatório público
continua metadata-only, com hash do arquivo privado e do pacote por tentativa,
flag de redaction e hash do manifesto no topo; não publica o caminho privado,
perguntas, claims, quotes, snippets ou URLs privadas.

`manifest.json` contém nome e SHA256 de cada outro arquivo da pasta; seu
próprio hash é ancorado no relatório público. O verificador exige proprietário,
permissões, arquivos regulares, inventário exato, hashes válidos, ausência de
chaves de gabarito, hash do pacote e correspondência entre item/braço públicos
e privados. Em composições aceitas exige claim, citação, snippet e literalidade
na janela. Temporários incompletos de uma interrupção também são privados e
inventariados, sem serem tratados como respostas finais.

Hash do pacote: SHA256 de JSON UTF-8 com `sort_keys=True`,
`ensure_ascii=False`, separadores `(',', ':')` e newline final. Hash de arquivo:
SHA256 de seus bytes efetivos. O verificador não revalida a fonte original pelo
SHA herdado do pacote, nem prova entailment; comprova integridade e estrutura.

## Minimização e política de compartilhamento

Somente os campos descritos são persistidos. Padrões explícitos de email,
telefone, chaves, passwords, tokens, autorização e marcadores de redaction são
substituídos por `[REDACTED:LOCAL_POLICY]` antes de escrever. Um registro assim
leva `redacted=true`, hash do pacote original e hash separado do pacote
armazenado; o conteúdo removido não é retido. O verificador retorna
`review_ready=false`: não declara reconstrução exata nem permite considerar o
registro pronto para revisão semântica integral.

O detector é defesa adicional, não classificador universal de PII/segredos.
O operador deve manter a política de fontes públicas e verificar dados antes
de compartilhá-los. Não enviar clientes, alvos privados, material Tor, segredos
ou PII a terceiros. O escrow é local, sem envio automático a JEV, sem backup
criptografado e sem limpeza automática. Não publicar arquivos privados em Git,
logs, tickets ou prompts. Retenção e acesso são responsabilidade do operador.

## Demonstração DEV e comandos reais

Fixture própria pública: `tests/fixtures/review-artifacts-dev-v1.json`. Duas
composições simuladas, cada uma nos dois braços: observação HTTP 200 correta;
e conclusão de C2 ativo com a mesma quote real, apesar de o snippet declarar
que o canal não foi testado. Ambas passam pelo gate estrutural e ficam
revisáveis depois; isso demonstra a necessidade de C2, não aprovação semântica.
Recuperação e modelo são mocks; nenhum modelo real ou rede é necessário.

```sh
# Usar nomes NOVOS para repetir; nada é sobrescrito:
python3 bin/mitr3-candidate-run.py --dev-review-demo \
  --private-dir "$HOME/.local/share/mitr3/v5-review/dev-escrow-NOVO" \
  --output reports/review-artifacts-dev-NOVO.json

# SHA256 copiado de private_manifest_sha256 no novo relatório:
python3 bin/mitr3-review-artifacts.py \
  "$HOME/.local/share/mitr3/v5-review/dev-escrow-NOVO" \
  --manifest-sha256 SHA256_DO_MANIFESTO \
  --public-report reports/review-artifacts-dev-NOVO.json
```

Execução entregue: `reports/review-artifacts-dev-20261020.json`, escrow em
`~/.local/share/mitr3/v5-review/dev-escrow-20261020-qa-f1c68e7/`.
Resultado conferido: **4 registros finais, 26 arquivos de checkpoints/finais
mais manifesto, zero redactions, verified=true e review_ready=true**.
Manifesto: `16a9a17da565ef5471bdc645791c7ad96256ad88ae85c7b65bc137df8884c9c3`.
Os dois revisores poderão recuperar claim/citação/snippet e distinguir o
canário falso do fato observado; esta entrega não executou parecer JEV nem
adjudicação humana. O relatório identifica explicitamente transporte mockado.

Em execução futura autorizada, adicionar `--private-dir PASTA_EXTERNA_NOVA`
a cada braço, em pastas distintas, mantendo aprovação do operador e SHA do
conjunto. Não há comando de execução do v5 neste documento. Planejamento não
determinístico pode gerar pacotes diferentes entre braços; seus hashes
separados permitem auditar esse fator de confusão.

## Revisão sem contaminação e novo freeze

Dois revisores independentes acessam apenas o escrow sem gabarito e verificam
o manifesto contra o hash público. Um parecer JEV futuro exige política de
dados públicos e autorização de compartilhamento; não recebe rubrica, gabarito
ou notas humanas. Não há juiz acionado automaticamente pelo runner.

C3 (controles negativos e IDs proibidos) exige fase externa posterior por
avaliador autorizado: associação por ID somente depois de congelados os
pareceres semânticos. Os rótulos não entram no runner, escrow, modelo ou juiz.
Não se implementou nem executou leitor de gabarito nesta tarefa.

São necessários novo freeze PRE-RUN e autorização humana antes de qualquer
rodada v5. O hash antigo do runner fica superado por esta implementação; os
hashes de prompts, produção, spec e conjunto não são alterados pelo patch.
Este documento não constitui GO nem promoção de produção.

## Validação e hashes

**218 testes verdes**, incluindo 18 novos testes de escrow. Cobrem ambos os
braços, pós-leitura, ausência de gabarito, integridade, permissões, proibição de
Git, ausência de sobrescrita, redaction, claims barradas preservadas, erro de
modelo, protocolo pai/worker com mocks e timeout com duas tentativas (um retry).
O teste baseline passou de delegação opaca para equivalência com `answer()`.

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests
```

A suíte também passou com audit hook recusando aberturas do arquivo v5 no
processo de testes; os novos filhos executam apenas scripts mockados e fixture
DEV. Não foram impressos corpos privados. A tabela congela conteúdo, sem
referência circular ao hash do commit que contém este documento.

| Artefato | SHA256 |
|---|---|
| `bin/mitr3-answer.py` | `4ba78d9a0b57e6bfaad6524e95cd81d266f2ba071eeaba61ad8551ed114c29ab` |
| `bin/mitr3-blind-run.py` | `15a4e823822fd3d67739b2b03d1b7c3fc92739bda43798a2e1c2430288aacd3c` |
| `bin/mitr3-candidate-run.py` | `cf2578791e2a11e3d4bc0165b72cd29d60dc841da32fc73e89a9ab8f61d4fac3` |
| `bin/mitr3-context-bridge.py` | `e89ed65620fccf1c4eb05fa38e7b1cdb33c201bcdbdfcdb6bf3a142118c1d9f4` |
| `bin/mitr3-rag-intel.py` | `57bac3d59f414b16817b3a93e5981638ce9988254bfdcf57dc789897f2deb5d6` |
| `docs/CANDIDATE-FREEZE-SPEC-20261020.md` | `ef5ec791003abc6f927ca7389fd19f83ccd1efe1269b3bc76af0ceec555fd402` |
| `bin/mitr3-review-artifacts.py` | `f62ce0208151869b96355324484811f55a6e942a9dcf70d045d1c33881e18d54` |
| `tests/fixtures/review-artifacts-dev-v1.json` | `86f498ad7dd2f182cc73ca433164e906c7f2b6d629197b862b1d6068d61309ad` |
| `extraction_prompt_source` | `1633414e63ceee150bc3be6889a6a5fd2bf9580e0eb37cec2413615588073537` |
| `required_synthesis_prompt` | `2f65d7b18a240a0428b17b0df7983b97b2ebdc5ed589bd78d33028b6b457a4b8` |
| `state/mitr3-intel.sqlite3` | `1dac5585c70328d864290fcc2b30bd1257fed245c33923ff05cd52cc2a09066a` |
| `state/mitr3-attack.sqlite3` | `60827b12fdbc09923ec1f4a3ec9c6bd0f88c6bba8ba3c8694fcc317f3d92c866` |
| `knowledge/reference-datasets/cache/manifest.json` | `3a5d108d10d678fbe5542cffe38a673177fb2f0af476694468e905ab35b3d23a` |
| `knowledge/reference-datasets/cache/enterprise-attack-manifest.json` | `92160406053997f9bc1ed269e3628b6d56e393e8aa7ed7ae78d603047b79de67` |
| `tests/test_candidate_run.py` | `bcfac939f83702f3d61e16babad69455f32473ae5389536def45d5108a90fcd4` |
| `tests/test_review_artifacts.py` | `628cfefac577db5d6eca3b6a7b438d5c40b198ff533f379cb2c4f5261e44f8b7` |
| `reports/review-artifacts-dev-20261020.json` | `f59a4d8cd1b5ebd4b31e5d95a59765a6b2f6346f505596a8722d682ab18d1e4d` |
