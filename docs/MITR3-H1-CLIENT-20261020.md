# HackerOne: cliente somente leitura — 2026-10-20

Branch isolada `codex-h1-readonly-20261020`, base `1bb2bd3`.
`bin/mitr3-h1.py` consulta programas, detalhes, escopos estruturados e exclusões;
compara snapshots locais e valida/gera relatórios locais. **Submissão não existe**:
nenhum endpoint de criação/alteração de relatório, upload ou report intent.
A tarefa não fez consulta autenticada nem leu o token real; não testou ativos
MercadoLibre, não acessou evidências privadas e não alterou produção ou RAG.

## API e credenciais

A [documentação oficial HackerOne](https://api.hackerone.com/hacker-resources/)
especifica autenticação HTTP Basic com usuário de API e token e endpoints GET
em `/v1/hackers/programs`, `/{handle}`, `/{handle}/structured_scopes` e
`/{handle}/scope_exclusions`. Só esses caminhos no host HTTPS exato
`api.hackerone.com` são permitidos pelo cliente.

Token exclusivamente em `~/.local/share/mitr3/h1/token`, arquivo regular do
usuário, **0600**, fora do Git, sem symlink. Não há argumento CLI de segredo,
valor hardcoded, cópia do token, descoberta de credenciais ou impressão de
headers. Formatos aceitos no mesmo arquivo já existente:

- token bruto + `MITR3_H1_USERNAME` com o usuário de API;
- `usuario:token`;
- objeto JSON com exatamente `username` e `token`.

O cliente não escolhe nem inventa usuário. Apenas o primeiro formato exige
variável de ambiente; não colocar o token na variável. Nunca incluir o arquivo
real em Git, prompts, fixtures, comandos ou logs. Os testes usam valores
explicitamente sintéticos em diretórios temporários e não abrem o arquivo real.

Sem redirects, nem mesmo no mesmo host. Paginação aceita exclusivamente links
para o mesmo caminho/host e parâmetros numéricos de paginação; não segue URLs
de ativos, relatórios ou terceiros. Proxies de ambiente são desabilitados;
TLS permanece com verificação padrão. Timeout 15 s, até 20 páginas, limite de
2 MB por resposta, 10 MB de JSON agregado e 5.000 registros. Nenhum retry de
rede: 429 encerra a chamada e informa Retry-After numérico quando disponível,
sem reenviar. Erros exibem apenas códigos fixos, sem corpo remoto ou segredo.
Uma resposta que ecoe o token ou o Authorization é recusada.

## Consultas e armazenamento privado

```sh
# Somente se o arquivo contém token bruto; este valor é usuário, não token:
export MITR3_H1_USERNAME=SEU_USUARIO_DE_API

python3 bin/mitr3-h1.py programs \
  --output "$HOME/.local/share/mitr3/h1/client/programs-NOVO.json"
python3 bin/mitr3-h1.py program mercadolibre \
  --output "$HOME/.local/share/mitr3/h1/client/program-NOVO.json"
python3 bin/mitr3-h1.py scopes mercadolibre \
  --output "$HOME/.local/share/mitr3/h1/client/scopes-NOVO.json"
python3 bin/mitr3-h1.py exclusions mercadolibre \
  --output "$HOME/.local/share/mitr3/h1/client/exclusions-NOVO.json"
```

Esses são comandos de uso futuro, **não executados na entrega**. A API pode
retornar programas privados: snapshots e diffs exigem saída fora de qualquer
árvore Git, inclusive diretórios ignorados, em pasta do usuário 0700 e arquivo
novo 0600. Symlinks e sobrescrita são recusados. O stdout contém apenas
status, contagens e hashes; o usuário consulta os dados completos no arquivo
privado. Conteúdo remoto é dado não confiável, nunca instrução ou autorização.
Não há indexação, envio ao MegaBrain/JEV/LLM nem publicação de conteúdo.

Snapshot `mitr3-h1-snapshot-v1`: tipo de recurso, programa, endpoint, UTC,
SHA256 dos bytes de cada página, dados da API e SHA256 do snapshot sem o próprio
campo `sha256`. Scopes incluem também `scope_sha256`, calculado sobre registros
ordenados por ID, removendo duplicatas idênticas e recusando conflitos. Hashes
canônicos usam JSON UTF-8, chaves ordenadas, `ensure_ascii=False`, separadores
`(',', ':')`, sem newline. `file_sha256` verifica os bytes do arquivo completo,
que inclui newline final. São compromissos de integridade, não assinaturas de
origem; as respostas vêm da conexão TLS com a API.

```sh
python3 bin/mitr3-h1.py diff \
  "$HOME/.local/share/mitr3/h1/client/scopes-ANTES.json" \
  "$HOME/.local/share/mitr3/h1/client/scopes-DEPOIS.json" \
  --output "$HOME/.local/share/mitr3/h1/client/diff-NOVO.json"
```

O diff exige snapshots de scopes válidos do mesmo programa, recalcula seus
hashes e retorna adicionados/removidos/alterados por ID com antes/depois.
Instruções, elegibilidade, severidade e demais atributos participam da comparação;
metadados temporais de cada registro também podem aparecer como alteração.
Ordem e duplicatas idênticas não criam mudanças de escopo. Mudança de ID aparece
como remoção/adição, sem inferir equivalência. Traz hashes dos snapshots, dos
escopos normalizados e do diff. Não se interpreta ativo novo como autorização
para testar: as regras e os portões continuam vinculantes.

## Template e validação

```sh
# Template vazio não é finding nem passa na validação:
python3 bin/mitr3-h1.py template --program mercadolibre \
  --output "$HOME/.local/share/mitr3/h1/client/report-NOVO.json"

python3 bin/mitr3-h1.py validate \
  "$HOME/.local/share/mitr3/h1/client/report-PREENCHIDO.json" \
  --scope "$HOME/.local/share/mitr3/h1/client/scopes-ATUAL.json"
```

Template sem `--output` vai ao stdout: só possui campos vazios, sem alvo real
ou credenciais. O validador só lê arquivos locais, nunca consulta API ou token.
Exit status: 0 válido; 2 relatório inválido; 1 falha operacional. Não imprime
texto do relatório: retorna lista de códigos, score calculado e
`submission_implemented=false`.

Campos obrigatórios: programa; título/resumo; ativo com identificador, tipo,
endpoint e método documentado; weakness; precondições; passos; resultado
esperado/observado; impacto; uso de test users; CVSS/justificativa; hashes de
política/escopo; pelo menos uma evidência com rótulo, UTC, hash, flag de redaction,
request e response. Chaves desconhecidas são recusadas. Método no relatório é
metadado da evidência; o cliente HTTP da ferramenta continua exclusivamente GET.

O [padrão FIRST CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
fundamenta a validação de métricas, duplicatas e cálculo Base com Roundup do
Apêndice A. Aceita as oito métricas Base em qualquer ordem e valida valores
opcionais temporais/ambientais; `base_score` é sempre o score **Base**, não o
score temporal/ambiental. Não calcula esses dois scores adicionais. Recusa
versões diferentes e divergência entre vetor e Base informado. A regra local
de MercadoLibre, documentada na spec H1-0, exige PR:H quando `test_users=true`;
o validador a aplica explicitamente, sem presumir privilégios em outros casos.

`redacted=true` é obrigatório e insuficiente sozinho: busca headers de
Authorization/Cookie/Set-Cookie/API key não redigidos, tokens/sessões/senhas,
JWTs, emails e telefones detectáveis. Headers sensíveis devem ter o valor
inteiro substituído por `[REDACTED]` ou `[REDACTED:ROTULO]`. O hash da evidência
precisa corresponder ao JSON canônico `{"request":...,"response":...}` **já
redigido**, não ao corpo privado original. O detector não comprova ausência
universal de PII/segredos: requer revisão apropriada, não evidenciação automática.

Com `--scope`, verifica hash, programa e correspondência exata de identificador
e tipo com ativo declarado elegível para submission. Não expande wildcards nem
prova que um endpoint/ação concreta está autorizado; isso pertence à análise
de política. Sem `--scope`, não afirma pertencimento a escopo. Os hashes de
política documentam referência; a ferramenta não interpreta a política textual.
`valid=true` significa consistência estrutural, não exploit reproduzido,
impacto demonstrado, elegibilidade da conta ou aprovação QA/JEV. Respeita a
emenda `H1-QA-JEV-GATES-AMENDMENT-20261020.md`, sem substituir seus portões.

## Testes e limites medidos

Fixtures públicas próprias em `tests/fixtures/h1/`, exclusivamente domínios
`.example.test`. A evidência HTTP 200 e o vetor 9.8 são controles de validação;
**não sustentam uma vulnerabilidade ou severidade real**. Testes com opener e
credenciais mockados: GET, rotas, paginação, host/redirect, limites, 429,
segredo ecoado, formatos/permissões de token, diff/dedup/tamper, campos, CVSS,
regra PR:H, redaction/hash de evidência, vínculo opcional de escopo,
privacidade, criação exclusiva e inexistência de submit. Nenhuma rede em testes.

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests
```

Resultado final e SHA256 dos artefatos registrados abaixo. Nenhum arquivo de produção ou conjunto cego foi alterado; nenhum token ou
artefato real do engajamento foi aberto por esta entrega. A suíte existente pode ler suas próprias fixtures de regressão;
os testes novos usam somente o diretório H1 sintético.

**247 testes verdes**, incluindo 27 testes H1 novos; ResourceWarning tratado como erro.

| Artefato | SHA256 |
|---|---|
| `bin/mitr3-h1.py` | `8c8bc5eb60e2a44aa0a70acf34f2cf714373ebb2e19a29bea245096c5a3ed000` |
| `tests/test_h1.py` | `54bfe8ed86a4e85395f7be07cc665449860b729367a8e932f7b286c11b3b3e2c` |
| `tests/fixtures/h1/programs.json` | `521dfb70c7f0593c1867c2803304c8a23fb3f1897e06b6f7f6ba0be466b7a192` |
| `tests/fixtures/h1/report.json` | `3654491c5cde38aeeb511469c0729e22fe3ea1116889f52c417406c6e4cd8f50` |
| `tests/fixtures/h1/scopes-after.json` | `027f1af4f6bb8eeee45095d0ced897fee0fcf207df7be96fdfbc41a3de3d3314` |
| `tests/fixtures/h1/scopes-before.json` | `c39eb9524d00b570a9b7c3c07a4673e26fb62598f046a4508f4671f4056b33f4` |
| Template JSON canônico vazio | `1ef8c6fd5ed9c47b34c4fc8a2f61d81a13f497abe013a3fa8e73740819b3b9f1` |
