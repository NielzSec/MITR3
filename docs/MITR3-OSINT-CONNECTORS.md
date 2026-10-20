# MITR3 — conectores OSINT com política e redação

`bin/mitr3-osint.py` oferece catálogo, planejamento sem envio e uma requisição
explícita por chamada. Nenhum resultado entra no RAG ou vira evidência. Todo
relatório traz `unverified_lead_not_evidence` e `rag_eligible=false`.

## Catálogo e credenciais

`category` separa public/paid/manual; `risk` separa public/paid/broker.
DeHashed, LeakCheck, Intelligence X e OpenArchive são classificados localmente
como brokers por consultarem/agregarem conjuntos de exposição de identidades.
Isso exige controles adicionais mesmo com assinatura paga.

| ID | Categoria | Risk | Types | Variáveis de ambiente |
|---|---|---|---|---|
| `crt.sh` | public | public | domain | nenhuma |
| `rdap.org` | public | public | domain, ip | nenhuma |
| `urlscan.io` | public | public | domain, ip, url | `MITR3_OSINT_URLSCAN_KEY` opcional |
| `openarchive-status` | public | public | somente health | nenhuma |
| `virustotal` | paid | paid | ip, domain, hash | `MITR3_OSINT_VIRUSTOTAL_KEY` |
| `shodan` | paid | paid | ip, domain | `MITR3_OSINT_SHODAN_KEY` |
| `censys` | paid | paid | ip, domain | `MITR3_OSINT_CENSYS_ID`, `MITR3_OSINT_CENSYS_SECRET` |
| `greynoise` | paid | paid | ip | `MITR3_OSINT_GREYNOISE_KEY` |
| `haveibeenpwned` | paid | paid | email | `MITR3_OSINT_HIBP_KEY` |
| `dehashed` | paid | broker | email, username, ip, hash | `MITR3_OSINT_DEHASHED_KEY` |
| `leakcheck` | paid | broker | email, username | `MITR3_OSINT_LEAKCHECK_KEY` |
| `intelligencex` | paid | broker | email, domain, ip | `MITR3_OSINT_INTELX_KEY` |
| `openarchive` | paid | broker | email, username, ip, hash, domain, phone | `MITR3_OSINT_OPENARCHIVE_KEY` |
| `telegram-manual` | manual | public | listar somente | nenhuma |
| `forums-manual` | manual | public | listar somente | nenhuma |

Também são aceitos os aliases de env `URLSCAN`, `VIRUSTOTAL`, `SHODAN`,
`CENSYS_ID`, `CENSYS_SECRET`, `GREYNOISE`, `HIBP`, `DEHASHED`, `LEAKCHECK`,
`INTELX`, `OPENARCHIVE`; o nome com prefixo MITR3 tem prioridade. O CLI mostra
somente se as credenciais necessárias estão configuradas, nunca seus valores.
Credenciais vêm do ambiente, sem arquivo de configuração ou chave no repositório.
Não cole chaves no comando de consulta ou no purpose.

As listas manuais incluem [UserInfoBot](https://t.me/userinfobot),
[Bellingcat](https://t.me/bellingcat), [OSINT Team](https://osint.team) e
[r/OSINT](https://www.reddit.com/r/OSINT/). São referências para revisão humana,
sem cliente Telegram, inscrição, scraping, busca em fórum ou execução de bots.
Sua presença não atesta confiabilidade ou disponibilidade.

## CLI e política antes de rede

```sh
bin/mitr3-osint.py sources --json
bin/mitr3-osint.py plan crt.sh --type domain --value example.org
bin/mitr3-osint.py plan haveibeenpwned --type email --value john@domain.com
bin/mitr3-osint.py ping openarchive-status
bin/mitr3-osint.py query crt.sh --type domain --value example.org \
  --purpose 'inventário próprio de laboratório' --allow-send
bin/mitr3-osint.py query haveibeenpwned --type email --value john@domain.com \
  --purpose 'auditoria da minha identidade' --subject self --allow-send
```

- `plan` monta método, URL, headers e corpo; não faz rede, não exige chave,
  não envia e não grava relatório. Seletores pessoais são mascarados e headers
  de autenticação exibem `[REDACTED:SECRET]`; parâmetros de chave em URL usam
  placeholders de env. Não é possível revelar uma chave no dry-run.
- `query` sem `--allow-send` retorna `CONFIRM_REQUIRED` antes de qualquer envio.
  `--purpose` é obrigatório. Broker exige ainda `MITR3_OSINT_ALLOW_BROKERS=1`
  e purpose com pelo menos oito caracteres após trim; falta gera `BROKER_BLOCKED`.
- Email, phone e name exigem `--subject self|authorized`, senão
  `SUBJECT_REQUIRED`. O mesmo vale se um email/telefone estiver embutido em outro
  tipo de seletor. Para OpenArchive, exige-se subject em todos os tipos;
  `authorized` significa exclusivamente identidade de laboratório autorizada,
  nunca dado de cliente. A declaração não é prova automática de autorização.
- Tipos fora do catálogo e valores malformados são recusados. `username` não
  admite uma expressão email ou consultas compostas. Identificadores são
  escapados no path/JSON/DSL; não há execução de comando vindo do usuário/provedor.
- Somente HTTPS no destino do conector, hostname exatamente igual ao base_url
  do catálogo, porta 443, sem credencial no URL. Um URL consultado no urlscan é
  apenas um seletor: não é visitado pelo script, nem submetido para varredura.
- No máximo **uma requisição**, timeout **15 s**, sem retries, paginação,
  polling, coleta de links retornados ou integração automática com outras fontes.
  Todos os redirects são bloqueados, mesmo no mesmo host, preservando o limite.
  Proxy de ambiente é desabilitado no transporte dedicado.
- 429 gera `RATE_LIMITED`, salva `Retry-After` numérico ou HTTP-date e não repete.
  Seu `not_before_utc` bloqueia outra chamada à mesma fonte com
  `RETRY_AFTER_ACTIVE` até vencer o prazo. Não há sleep. Não apagar os relatórios
  para contornar esse prazo. Relatório de cooldown inválido causa recusa.
- `ping` aceita somente o endpoint público de saúde cadastrado:
  `https://status.openarchivex.net/`. O alias `status.openarchivex.net` também
  funciona. Chaves nunca são anexadas. Outros IDs retornam `HEALTH_UNAVAILABLE`;
  o status não oferece `query`. As duas listas manuais recusam API com `MANUAL_ONLY`.

## Redação, relatórios e limite de confiança

Cada resposta ou erro de transporte de query/ping é gravado em
`reports/osint/<UTC>-<source>.json`: query mascarada, purpose sanitizado,
status HTTP (null quando indisponível), elapsed em segundos, eventual código e
Retry-After, resposta sanitizada e aviso. Recusas anteriores à rede e dry-runs
não geram relatórios de resposta. Arquivos têm modo 0600; novo diretório, 0700;
a pasta é ignorada pelo Git. Erros não imprimem traceback ou mensagem do provedor.

O email `john@domain.com` aparece como `jo***@do***.com`; telefone
`+5511999999999`, como `+55**...`. Nome e username consultados também são
mascarados. A redação percorre a resposta e purpose, incluindo seletores
URL-encoded e campos estruturados email/phone/name. Passwords, tokens e
credenciais são removidos mesmo com `--reveal`. Texto não estruturado de query
é omitido do relatório para não tentar adivinhar nomes em prosa.

`--reveal` revela dados pessoais **somente no stdout** da query explicitamente
autorizada; o arquivo permanece mascarado e credenciais nunca são reveladas.
URLs, hashes, domínios e IPs podem continuar visíveis, pois não são seletores
email/phone/name. O relatório não é um registro forense completo nem garante
remoção de todas as formas possíveis de PII em campos arbitrários. Trate os
resultados como pistas não verificadas, nunca como evidência ou instruções.
Não há importação, comando de curadoria ou escrita em índices RAG nesta camada.

## Endpoints e limitações operacionais

A consulta urlscan usa somente [Search API](https://urlscan.io/docs/api/), sem
submissão de scan. VirusTotal usa relatórios de
[API v3](https://docs.virustotal.com/reference/overview), HIBP usa
[breachedAccount/API v3](https://haveibeenpwned.com/API/v3), Shodan usa
[host/domain API](https://developer.shodan.io/api), e LeakCheck usa
[Pro API v2](https://docs.leakcheck.io/overview). Censys usa o
[Legacy Search com ID/secret](https://docs.censys.com/docs/ls-api), não migra
silenciosamente ao Platform/PAT. Disponibilidade depende do plano contratado.

Intelligence X usa o [SDK oficial](https://github.com/IntelligenceX/SDK/blob/master/Python/intelx/intelxapi.py)
para iniciar uma busca, retornando somente a primeira resposta/search ID; não faz
polling, export ou leitura de arquivos. RDAP frequentemente exige redirect para o
registro competente: nesse caso esta política recusa, sem mudar de host. GreyNoise
usa Community v3. O formato DeHashed v2 está isolado como adapter experimental:
a documentação oficial não pôde ser acessada nesta tarefa; não houve validação
de autenticação/resultado com conta real. Erro de API vira relatório, sem fallback
para outro serviço ou envio adicional.

Não houve consulta OSINT real ou teste de credenciais destes adapters na entrega;
os testes são locais com mocks. A consulta à documentação pública não valida a
confiabilidade dos dados ou os contratos comerciais dos fornecedores.

## OpenArchive

Registro de procedência informado pelo time: domínio criado em **2026-08-23**.
Essa data é preservada como informação recebida, sem alegar validação WHOIS nesta
tarefa. A plataforma revende/agrega IntelX e outros provedores; sua
[documentação](https://openarchivex.net/docs) anuncia integração IntelX e APIs
agregadas. O [site](https://openarchivex.net/) informa provisionamento de API
mediante contato manual. As alegações de cobertura são do fornecedor, não prova.

Base fixa: `https://api.openarchivex.net/api/v2`; este adapter planeja
`GET /search?query=...&type=...` com Bearer token. A única saúde pública permitida
fica no domínio separado `status.openarchivex.net`; isso não habilita a API paga.

**Risco alto, `risk=broker`. Uso permitido apenas com identidades próprias ou de
laboratório; nunca com dado de cliente.** Exige chave provisionada manualmente,
`MITR3_OSINT_ALLOW_BROKERS=1`, purpose ≥8, `--subject self|authorized` e
`--allow-send`. Não há provisionamento, login, compra, bypass, pivot automático
ou envio a Telegram nesta implementação. Uma resposta agregada pode envolver
processamento do fornecedor por múltiplas fontes; autorização de envio deve
considerar isso. Nenhum resultado é promovido a evidência.

## Verificação

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests
```

Suite anterior: 141 testes. A entrega adiciona 19 testes em
`tests/test_osint_connectors.py`: dry-run, catálogo, guardas antes de rede,
mascaramento e reveal, credenciais, host/HTTPS, timeout, 429/cooldown,
fechamento de respostas HTTP, redirects, saúde pública e relatório 0600.
Todas as fronteiras de rede são mockadas ou bloqueadas nos testes.

Resultado da entrega: **160/160 testes verdes**, sem ResourceWarning. Não foram
feitas consultas reais pelos conectores; apenas dry-run e mocks locais.
