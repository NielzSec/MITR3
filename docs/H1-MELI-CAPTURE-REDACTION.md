# H1 MercadoLibre — segurança de capturas e proposta de redaction

Auditoria local em 2026-10-20T21:20:11.956589+00:00. Escopo limitado
aos dois arquivos indicados pelo operador. Nenhuma requisição a hosts MELI,
login, teste de token, resolução de ativo ou validação de chave foi executada.
Os arquivos originais não foram alterados, movidos ou excluídos. Este documento
contém apenas nomes de campos, contagens, hashes de arquivos e recomendações;
nenhum valor de cookie, token, identificador, chave ou email é reproduzido.

## Inventário e integridade

| Arquivo | Bytes | Modo | SHA256 dos bytes |
|---|---:|---|---|
| `apisec-capture-2026-10-20T20-54-29.json` | 2953462 | 0600 | `c34cc3f6359b304dc7f98cfe9514f220d0a925023ea85ec65c4eb82e6bac0473` |
| `findsomething_lista.mercadolivre.com.br_2026-10-20T20-44-32.json` | 438093 | 0600 | `c670ae77c324561d187959e436b8a0c342008f0bdaa3a8f21258413e8523a651` |

Ambos estão fisicamente dentro do checkout, mas **não versionados**. Estar
ignorado não equivale a estar fora da árvore de trabalho nem impede `git add -f`.
A proposta é guardar originais em diretório privado realmente externo ao Git.

## Captura APIsec

168 registros de requisição; os 168 contêm campo sensível/pseudônimo. Contagens
são ocorrências em campos não vazios e podem se sobrepor; não devem ser somadas
como número de credenciais distintas. Nomes de campos são apresentados com sua
grafia conhecida; nenhuma chave dinâmica é publicada.

| Categoria | Contagem | Campos ou localização |
|---|---:|---|
| Headers de cookie de requisição | 168 | `requestHeaders.Cookie` |
| Pares nome/valor de Cookie de requisição | 2.790 | `requestHeaders.Cookie` |
| Headers Set-Cookie de resposta | 149 | `responseHeaders.set-cookie` |
| Pares com nome sugerindo sessão/autenticação | 444 | `Cookie`, `set-cookie`; não prova de sessão autenticada |
| Pares de cookie com nome CSRF/XSRF | 165 | `Cookie` |
| Header CSRF | 94 | `requestHeaders.x-csrf-token` |
| Header XSRF | 56 | `requestHeaders.X-XSRF-TOKEN` |
| JWT com header JSON/alg reconhecível | 33 ocorrências; 1 distinto | `requestHeaders.Cookie` |
| Identificador declarado no JWT | 33 ocorrências | claim `sub`; nenhuma identidade resolvida |
| Identificadores de dispositivo | 337 | `x-d2id`, `x-request-device-id` em headers |
| Identificador de sessão estruturado | 1 | `requestBody.meliSessionId` |
| Campo de sessão embutido em texto | 3 | `responseBody.session_id` |
| Correlação/trace | 126 | `requestHeaders.traceparent` |
| Identificador de caller | 2 | `requestHeaders.x-caller-id` |
| Identificador de tracking | 1 | `requestHeaders.x-tracking-id` |
| Emails plausíveis pelo padrão | 0 | — |
| Telefones internacionais/nacionais pelo padrão | 0 | — |
| CPF/CNPJ formatados pelo padrão | 0 | — |

Não se verificou assinatura/validade de JWT, vigência de sessão, privilégios ou
identidade da conta. Cookies de analytics e pseudônimos também devem ser
minimizados, sem serem apresentados automaticamente como credenciais válidas.
Zeros de PII não comprovam ausência universal: nomes, endereços livres, formatos
não cobertos, dados codificados e conteúdo binário podem escapar aos padrões.

## Export FindSomething

| Categoria | Contagem | Campos ou localização sanitizada |
|---|---:|---|
| Candidato de chave de API | 6 ocorrências; 1 distinto | `data.ai.<dynamic_key>`, `data.secret[]`, `data.source.<dynamic_key>` |
| Candidatos de email | 93 ocorrências; 22 distintos | `data.<dynamic_key>[]`, `data.ai.<dynamic_key>`, `data.source.<dynamic_key>`, `data.url[]` |
| Nome de campo CSRF em texto/código | 3 | `data.ai.<dynamic_key>.csrftoken`, `data.secret[].csrftoken`, `data.source.<dynamic_key>.csrftoken` |
| JWTs pelo padrão | 0 | — |
| Headers Cookie/Set-Cookie estruturados | 0 | — |
| Telefones internacionais/nacionais pelo padrão | 0 | — |
| CPF/CNPJ formatados pelo padrão | 0 | — |

A exportação usa conteúdo encontrado como **chave de objeto**, além de guardá-lo
em valores. Portanto não basta redigir os valores: chaves dinâmicas também
precisam ser removidas ou substituídas por pseudônimos locais opacos.
O candidato de chave tem sintaxe de chave client-side; presença em JavaScript
não comprova segredo, permissões excessivas ou exploração. Nenhuma chamada
foi feita para testá-lo. Os emails são candidatos sintáticos: podem incluir
contatos públicos, exemplos e terceiros. Não se identificou titularidade.
As três ocorrências de nome CSRF podem ser código/definições, não tokens ativos.

## Git: cobertura confirmada e limites

`git check-ignore -v` confirmou no worktree:

| Arquivo | Regra | Índice/arquivos rastreados | Commits por caminho, refs/reflogs |
|---|---|---|---:|
| APIsec | `apisec-capture-*.json` | ausente | 0 |
| FindSomething | `findsomething_*.json` | ausente | 0 |

**Ressalva importante:** as duas regras não aparecem no `.gitignore` do HEAD
nem no índice. Elas fazem parte de uma alteração de `.gitignore` já existente
antes desta auditoria, que foi preservada. A cobertura é local e ainda não
está versionada; outro checkout não herdará essa proteção até revisão e commit
dessas regras. Não foi feito commit, staging ou alteração do ignore nesta tarefa.

Checagens locais adicionais, sem imprimir conteúdo Git:

- 446 blobs examinados, 7301514 bytes, incluindo objetos alcançáveis e
  não alcançáveis presentes no object store; refs locais e reflogs considerados.
- Hash Git de cada arquivo exato ausente do object store e do índice.
- 77 candidatos de conteúdo comparados em memória: JWT, cookies, CSRF/sessão,
  identificadores, chave e emails com comprimento mínimo e diversidade de
  caracteres. **Zero blobs com correspondência literal** desses candidatos.
- Repositório local não shallow; nenhum histórico remoto foi consultado.

Conclusão delimitada: **não foram encontrados os dois arquivos, suas cópias
byte a byte ou esses candidatos literais no índice/histórico/objetos Git locais
examinados**. Isso não prova ausência em clones remotos, objetos já coletados
por GC, backups, logs, transcrições, conteúdo comprimido/transformado ou cópias
parciais não cobertas pelos 77 padrões. `.gitignore` não remove conteúdo já
versionado; aqui, os dois caminhos e blobs exatos estavam ausentes.

## Proposta de redaction

1. Guardar os originais imutáveis em
   `~/.local/share/mitr3/h1/mercadolibre/captures/`, pasta 0700, arquivos 0600,
   com inventário privado de hashes e responsável. A mudança é proposta,
   não executada; evitar duplicações em cloud sync, Git ou índices.
2. Criar derivados novos, sem sobrescrever originais. Substituir inteiramente
   `Cookie`, `set-cookie`, `x-csrf-token`, `X-XSRF-TOKEN`, eventual
   `Authorization` e identificadores de sessão/dispositivo/caller/tracking por
   marcadores de redaction. Não deixar prefixos/sufixos de tokens ou JWTs.
3. Redigir identificadores em `requestBody`, `responseBody`, URLs, querystrings,
   `Referer`, HTML e código embutido; conservar só o mínimo necessário à
   hipótese. Se for necessário correlacionar eventos, usar rótulos locais por
   execução, nunca identificadores reais nem hash público de valor sensível.
4. No FindSomething, remover conteúdo bruto de `data.secret`, `data.ai` e
   `data.source` que não seja necessário; substituir chaves dinâmicas por
   rótulos opacos e redigir candidatos de chave/email também em arrays e URLs.
   Não enviar a exportação integral a modelos ou serviços externos.
5. Verificar o derivado novamente, incluindo chaves, valores e corpos embutidos;
   registrar hash dos bytes finais e nomes de campos removidos. Não substituir
   hash do original pelo do derivado. Avaliar compartilhamento somente depois
   da revisão adequada de sigilo e necessidade.
6. Caso o operador confirme que alguma sessão/chave sensível foi exposta fora
   do armazenamento privado, considerar invalidação pelo canal autorizado.
   Esta auditoria não realiza logout, rotação, revogação ou teste remoto.

## Proposta de retenção

Valores abaixo são recomendação para decisão do responsável, não política já
aprovada do programa e não rotina de exclusão executada:

- **Originais com tokens/PII:** até 7 dias ou término da revisão necessária,
  buscando o prazo mais curto; extensão apenas justificada no caso privado.
- **Derivados efetivamente redigidos:** até 90 dias para revisão/reprodução,
  reavaliando necessidade e regras do programa antes de compartilhar.
- **Metadados mínimos, hashes e este laudo sem valores:** até 180 dias ou prazo
  de auditoria aplicável; eliminar quando a finalidade terminar.
- Restringir proprietário/leitores, incluir backups na decisão e não prometer
  apagamento seguro apenas por remover um arquivo em SSD ou storage sincronizado.

## Registro de limitação operacional

O inventário preliminar tratou uma chave dinâmica como nome de campo e deixou
um candidato de chave aparecer no diagnóstico desta sessão. A saída foi
corrigida para allowlist e `<dynamic_key>`; o valor não é repetido nem incluído
neste documento. Considerar a transcrição preliminar material restrito, não
copiá-la para Git/relatórios públicos e avaliar exposição conforme a política.
Não há evidência de commit desse candidato na varredura local descrita acima.

A auditoria usa parse JSON local, padrões sintáticos, inspeção local do header
de JWT e comparação literal de bytes Git. Não é DLP completo nem parecer de
explorabilidade. Nenhuma operação de rede foi usada nesta tarefa.
