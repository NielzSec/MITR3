# MITR3 JS Reverse Lab v0.2.0

Ferramenta local para importar JavaScript público de HAR autorizado, recuperar
`sourcesContent` publicado e analisar candidatos textuais de imports e chamadas
GSAP/ScrollTrigger. Não executa JavaScript. Validada como candidata offline;
**não há GO global de release pela checklist**.

## Uso offline

Na raiz de `~/MITR3`, com Python 3.10+, Linux, bubblewrap e libseccomp já instalados:

```bash
python3 bin/mitr3-js-lab.py import-har \
  tests/fixtures/js-lab/demo.har.json \
  --scope tests/fixtures/js-lab/scope.example.json \
  --out /tmp/mitr3-js-demo-UNICO --maps

python3 bin/mitr3-js-lab.py verify /tmp/mitr3-js-demo-UNICO/evidence
```

O destino precisa ser novo. O exemplo é inteiramente sintético, usa
`fixture.invalid`, gera quatro artefatos e não faz requisições de rede. Os três
candidatos GSAP incluem ocorrências no bundle e na fonte recuperada; não são três
animações comprovadas. O resultado fica em `OUT/evidence/`:

```text
raw/           HTML/JS/maps preservados, arquivos 0400
derived/       fontes extraídas, arquivos 0400
manifest.json  runtime, run_id, UTC, política, limites, relações, hashes e lacunas
audit.jsonl    eventos privados com fsync e cadeia SHA256
report.txt     contagens e limitações, sem trechos de código
SHA256SUMS     hashes de todos os arquivos do pacote
```

Diretórios externos são 0700; `raw`/`derived` tornam-se 0500 após a conclusão.
Isso reduz alterações acidentais; não é WORM, assinatura ou proteção contra o
mesmo usuário alterar permissões e reescrever todos os hashes. Para comprovar
custódia, conserve os selos em uma referência confiável fora do pacote.

## Escopo e dados

O contrato JSON exige `case_id`, `operator`, `expires_at` com timezone,
`allowed_origins` e `allowed_paths` por origem. `allow_source_maps` é falso por
padrão e precisa ser verdadeiro para `--maps`. `retention_days` tem padrão sete.
O exemplo em `tests/fixtures/js-lab/scope.example.json` só autoriza a fixture,
nunca sites de terceiros. Não reutilize uma declaração sintética como contrato.

Origens incluem esquema HTTPS, hostname ASCII e porta efetiva exata. Paths são
prefixos de segmentos; `/assets/` não autoriza `/assets-fake/`. Encodings ambíguos,
travessia `..`, credenciais em userinfo e queries com nomes conhecidos de segredo
são negados. Cada CDN precisa de origem/caminhos próprios.

HAR: até 64 MiB e 1.024 entradas; somente GET 200 em escopo e com corpo JS
identificado por MIME ou extensão compatível. Maps JSON são lidos por referência
de um script. Entradas com cookies/auth/postData/headers associados a segredos são
recusadas. O HAR é copiado somente para entrada temporária privada e removido ao
fim; o pacote guarda seu hash. A remoção não é apagamento forense em SSD/backups.

Corpos, HTML e maps podem conter dados pessoais, chaves ou código proprietário.
São **privados e não revisados**, não sanitizados. Queries/fragments são omitidos
dos metadados; paths permanecem privados. Relatório/stdout só trazem contagens,
códigos de motivo e nomes gerados. Não enviar brutos a IA/MegaBrain, não publicar
código proprietário e não confundir string `apiKey` com credencial ativa. Use
somente captura pública, sem sessão, revisada pelo operador. Dados incidentais
exigem quarentena e decisão do operador; a CLI não faz triagem semântica completa.

## Contenção verificada

O launcher inicia Python isolado com `bwrap`, mounts RO de runtime e insumos selecionados, ambiente limpo,
stdin nulo e sem descritores de rede herdados. A home/perfis/SSH não são montados;
root, `/tmp`, `/proc`, código e entradas são somente leitura. Somente o destino
novo de saída é gravável. O bootstrap confiável instala limites e libseccomp
**antes de ler o HAR**.

O filtro tem ação padrão EPERM e permite apenas syscalls necessárias de arquivos,
memória, sinais e saída. Socket/socketpair/connect/bind, exec, clone, setns e
io_uring não estão na allowlist. Usa-se `--share-net` porque o ambiente bloqueou
criação de namespace de rede; **não é namespace de rede isolado**. A proteção
offline vem do filtro efetivo, testado com controle positivo AF_UNIX/socketpair,
EPERM após carregamento e incremento de `Seccomp_filters`. AF_INET/AF_INET6 já
eram negados pelo sandbox externo: seu controle positivo é inconclusivo aqui.

Limites OS: 384 MiB de espaço virtual, 30 s de CPU, 64 MiB por arquivo gravado
(inclusive logs temporários), 64 FDs e nenhum novo processo. Supervisor externo
aplica prazo da política + cinco segundos, mata/recolhe o grupo se excedido e
recusa saídas excessivas. Falha de bwrap/filtro nunca cai para parsing no host.

Padrões de aplicativo: 4 MiB por artefato, 32 MiB agregados de corpos consumidos
**mais** artefatos gravados, 256 artefatos, 120 s de processamento e JSON com no
máximo 64 níveis. Cotas e hard limits se complementam. **Não foi demonstrada
quota global de filesystem contra um worker comprometido**; RLIMIT_FSIZE é por
arquivo. Esse P0 permanece pendente, mesmo com quotas de aplicativo e saída
limitada aos mounts da execução.

Antes de aceitar o pacote, o supervisor verifica schema, política original,
hash do HAR original, modos permitidos, cotas, tipos/nomes, relação entre arquivos,
SHA256 e cadeia completa do audit. Não confia no PASS ou nos limites que o worker
declarar sozinho. O comando `verify` verifica integridade local; sua saída PASS
não aprova escopo, autenticidade do código nem release.

Retornos: `0` concluído dentro dos limites da v0.2; `1` parcial com lacunas;
`2` falha/BLOCKED. Sem pacote íntegro, não há conclusão. Interrupção durante
commit de audit/artefato impede selagem posterior do pacote incompleto.

## Aquisição e capacidades futuras

`collect` permanece disponível na ajuda, mas **nega execução online** com
`independent-egress-not-certified`. Não há flag unsafe. A biblioteca interna de
aquisição e seus testes simulados não são interface operacional aprovada. Para
habilitar coleta são necessários egress independente e E2E TCP/HTTPS de
laboratório. A permissão do operador para desenvolver a ferramenta não identifica
um alvo autorizado de terceiro.

Source maps: valida schema de versão, fontes, names, mappings, campos opcionais,
offsets e seções embutidas; preserva índices de origem sem usar nomes como paths.
Não decodifica VLQ nem valida todos os detalhes semânticos ECMA ou busca fontes
ausentes ou seções externas. Fontes publicadas podem divergir do bundle.

Imports/GSAP são heurísticas textuais, podem incluir comentários/strings e omitir
aliases, seletores, parâmetros e chunks calculados. Não são AST ou execução.
AST, beautifier, Webcrack/Wakaru e browser estão fora desta candidata. Nenhuma
dependência foi instalada automaticamente. Integrações REA/MegaBrain/Chrome
Guarded precisam de tarefa e gates próprios; não houve alteração desses serviços.

## Verificação, autorização e evidências

```bash
python3 -m unittest discover -s tests -p 'test_js_lab*.py' -v
```

Há 48 testes: 22 principais, sete de contrato/criptografia TLS em MemoryBIO,
oito QA anteriores e 11 de sandbox/integração/verificador independentes. A suíte
contém execução real do launcher offline e watchdog, A/B do filtro, canário fora
dos mounts, adulteração rehashed, quotas e regressões. TLS em MemoryBIO verifica
criptografia/hostname com certificado sintético; não é E2E de TCP nem do fetcher.
TCP e getsockopt foram recusados pelo ambiente; não há scraping real.

Autorização humana: “voce tem toda a minha permissão”, nesta conversa, para esta
tarefa local. Plano revisado antes do ciclo M6 e resultados posteriores separados:

- [SPEC, autorização e plano](js-lab/SPEC-PLAN-CHECKLIST-V1.md).
- [Revisão técnica do plano](js-lab/QA-PLAN-CHECKLIST-V1.md).
- [QA independente v0.2](js-lab/QA-OFFLINE-V0.2.md).
- [Matriz de conformidade e limitações](js-lab/CHECKLIST-MATRIX.md).
- Snapshot privado `js-lab/baseline-draft-20261022/`: rascunho anterior à checklist.

O `collect_js.py` original de seis testes citado no `check.md` não foi localizado;
o snapshot preservado **não é declarado equivalente** a esse artefato. O parecer
JEV final não foi obtido: controle automático recusou a chamada com política
`never`. Preflight shadow anterior não substitui QA ou decisão de release.

Referências de formato/método: [ECMA-426](https://tc39.es/ecma426/),
[Chrome source maps](https://developer.chrome.com/docs/devtools/javascript/source-maps),
[OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[libseccomp](https://github.com/seccomp/libseccomp) e
[bubblewrap](https://github.com/containers/bubblewrap). Nenhum código de terceiros
foi coletado para redistribuição; licença/autoria de futuros materiais devem ser
revistas por execução. Consulta em 2026-10-22.
