# Execution Runner v0.1 — Rodadas 2–7 (integração offline sintética)

Consulta preparatória por frames: `query.py` aceita apenas `inspect` e `summary`,
sem comandos ou missões. Contrato e plano de separação de UIDs em
[`../docs/CUSTODY-QUERY.md`](../docs/CUSTODY-QUERY.md).
Estado: **LOCAL_QUERY_PROTOTYPE / NOT_DEPLOYED / F01_OPEN**.

Estado: **OFFLINE_E2E_CANDIDATE_REVIEW**. Policies, protocol, broker, snapshot,
store, sandbox Bubblewrap e worker determinístico funcionam integrados em fixture
sintética local. Há orquestração, transporte IPC, trace de leituras mediadas e
comparação determinística de saída com resultado independente.
**Não é um runner de Hackerbots autônomos.** A cadeia ainda exige revisão
independente de custódia, testes adversariais amplos e autorização humana.
Nenhum gate comportamental de skills foi aprovado.

## Estado atual e fronteira de confiança

As seções por rodada abaixo registram a evolução histórica; frases sobre componentes
futuros descrevem aquela rodada. Hoje existem runner, broker, snapshot, stores de
sessões e falhas, sandbox, verificador de cobertura e CLI de inspeção. Não existe
adaptador operacional do Morfeus nem custódia protegida de outro processo do mesmo UID.

`inspect` valida hashes locais e parte do envelope; não reexecuta o verificador nem
autentica a execução. `complete` significa sessão persistida. Novas sessões têm
`SESSION_RECORDED`; o resultado final local fica em `outcome.json` vinculado ao
manifesto. Ausência de outcome, inclusive por crash, permanece pendência, nunca sucesso.
O runner bloqueia >10.000 linhas antes de lançar e trace >1 MB antes da persistência
da sessão; falhas de verificação posteriores produzem outcome BLOCKED se o store
estiver gravável. Registros antigos não são reescritos. Não usar a consulta como autorização.
O manifesto registra hashes dos arquivos de módulos lidos na persistência, não um
atestado de que todos esses bytes correspondem aos módulos carregados na execução.
`staged_worker_sha256` registra separadamente os bytes que o runner forneceu ao staging;
é `null` na persistência direta de broker sem worker e não autentica o lançamento.

Arquivos 0600 e diretórios 0700 protegem contra outros usuários sem privilégios, não
contra agentes ou processos hostis com UID `nielz`. O staging ainda usa pathname para
o bind do bwrap: processo externo com o mesmo UID pode substituí-lo após a validação.
Para integração, separar a identidade do supervisor e a instalação/custódia da
identidade do agente; não entregar shell genérico na identidade confiável.
Nenhuma alteração de usuários ou serviço persistente é feita pelos comandos deste piloto.

O selftest cobre os controles listados em sua resposta; testes adicionais da suíte
exercitam memória, PIDs, sockets e encerramento. `CPUQuota` limita taxa agregada de CPU,
não orçamento absoluto; o prazo do broker começa após doctor/selftest, e cleanup pode
acrescentar tempo. `/usr` inteiro fica legível/executável, sem filtro seccomp próprio;
`/dev` contém o ambiente de dispositivos do bwrap. Não é uma VM nem prova contra falha de kernel.

## Usar e testar

A partir da raiz MITR3:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/runner/tests -v
```

Importações: `hackbots.runner.policies` e `hackbots.runner.protocol`.
`resolve_policy(overrides)` valida campos, tipos, valores finitos e tetos; limites
inválidos são recusados, nunca ajustados silenciosamente. A construção direta de
`Policy` passa pelas mesmas validações. `HARD_MAX` é imutável.

`encode_frame(msg, max_bytes)` produz uint32 big-endian + JSON UTF-8.
`FrameReader(fd, max_bytes).read(deadline)` recebe deadline absoluto de
`time.monotonic()`, mantém o mesmo prazo durante header e payload, aceita EOF limpo
somente entre frames e torna a sessão inutilizável após timeout/violação. Requer
pipe com um único leitor exclusivo. O chamador é responsável por fechar os FDs.
Nenhum método deste módulo inicia processos ou executa a fixture.
No Linux, a espera usa `poll()` para suportar descritores válidos com número
1024 ou superior; o deadline monotônico continua abrangendo header e payload.

`RequestParser(policy).parse(msg)` é a interface de sessão e limita a quantidade
de IDs, rejeita reutilização inclusive após solicitação recusada e bloqueia a sessão
após erro fatal. `parse_request(msg, policy)` é somente o validador sem estado e não
substitui a interface de sessão. IDs não são compartilhados entre sessões.

Mensagens aceitas: `v: 1`, `type: request`, `request_id` ASCII com 1..32 caracteres,
`operation: read_interval` com `start/end`, ou `submit_result` com `result` objeto.
Chaves extras são fatais. Inteiros booleanos, intervalos vazios/negativos e leituras
acima do limite são rejeitados. O broker futuro deve conferir `end <= snapshot.size`.

Frames de entrada: 65.536 bytes; saída: 131.072 bytes. Resultado: 32.768 bytes UTF-8
compactos, profundidade máxima 8 (raiz=0). O envelope aceita um nível extra.
JSON duplicado, NaN, Infinity, UTF-8 inválido e surrogates são fatais.
Decimais recebidos são preservados por `Decimal`, como no Evaluator existente; o
encoder do protocolo emite tokens numéricos exatos, sem convertê-los para float ou
string JSON. O broker/RunStore futuro deve reutilizar essa serialização ao persistir
resultados, em vez de converter `Decimal` para float.
O payload validado é copiado para impedir mutação posterior pelo chamador.

## Ajustes à arquitetura recebida

- Fixture e orçamento cumulativo usam **1.000.000** e **16.000.000 bytes** para
  corresponder ao Execution Verifier atual, não 1/16 MiB.
- Resultado máximo desta rodada permanece 32.768 bytes, cabendo com envelope no
  frame de 65.536 bytes. Não permitir 64 KiB de resultado dentro de frame de 64 KiB.
- Eventos `requested`, `mediated` e `delivered` precisam ser separados pelo broker.
  Somente resposta totalmente escrita pode gerar `delivered`; isso comprova entrega
  ao canal, não consumo/compreensão. Escritas no pipe também precisarão de deadline.
- Rejeições recuperáveis serão contadas pelo broker (até 3; quarta fatal), com no
  máximo uma repetição para resultado inválido. O parser não implementa esse estado.
- Um worker de arquivo único não pode importar um protocolo que não foi montado:
  decidir explicitamente entre worker standalone e bundle mínimo fixado por hash.
- O verificador atual exige caminho sob MITR3. O adaptador futuro deve verificar uma
  cópia privada do snapshot, nunca substituir os bytes avaliados pelo original reaberto.
- `coverage_gate: NOT_APPLICABLE` para arquivo vazio deve ser preservado na integração.
- Não presumir worker PID 1: confirmar o processo supervisor e a árvore real do bwrap.
- Falta de limites obrigatórios bloqueia por padrão. Nenhum fallback sem cgroup foi
  implementado nem habilitado nesta rodada.
- Selftest do sandbox agora implementado. A futura integração deve vincular
  resultado do selftest ao código/configuração, runtime, limites e ambiente atuais;
  um PASS antigo ou só a versão do bwrap não são autorização contínua.

## Próximas rodadas

Implementar broker/snapshot e escrita IPC limitada; depois sandbox/doctor/selftest
no Arch, custódia de runs, encerramento da árvore e adaptador do verificador.
Os componentes futuros devem manter `human_approved=false`, `promotable=false` e
separar comparação de saída, cobertura declarada, instrumentação e revisão humana.
Ver contrato em `../docs/EXECUTION-VERIFIER.md`. Não há promoção automática.

## Rodada 3 — Snapshot, Trusted Tool Broker e Trace Collector (offline)

Estado: **BROKER_PROTOTYPE_ONLY**. Nenhum worker é iniciado aqui; `sandbox_gate=NOT_RUN`,
`trace_authenticity=NOT_VERIFIED`, `behavioral_gate=NOT_RUN` e `promotable=false`.

Arquivos: `snapshot.py`, `broker.py`, `trace_store.py` e
`tests/test_broker.py` e `tests/test_trace_matrix.py`. Preservados os arquivos da Rodada 2.

**Snapshot.** `load_snapshot(relative, sha256, policy)` lê apenas fixtures locais
sintéticas nas raízes `hackbots/examples/`,
`hackbots/skill-builder/examples/evaluator/` ou
`hackbots/runner/tests/fixtures/`. Usa `O_NOFOLLOW` em cada componente,
`fstat`, rejeição a hardlinks (`st_nlink != 1`), teto de 1.000.000 bytes,
SHA256 externo e copia os bytes imutáveis
para a memória do componente confiável. Não envia caminho de host ao worker.
Uma alteração posterior do arquivo não muda o snapshot; a integração futura
deve passar uma cópia privada desses mesmos bytes ao Execution Verifier.

**Broker.** `BrokerSession(snapshot, policy)` aceita mensagens já decodificadas
pelo `FrameReader` existente. Por sessão, aceita somente `read_interval` e
`submit_result`; IDs únicos, 3 rejeições recuperáveis e a quarta fatal,
eventos e bytes cumulativos limitados; submissão final encerra a sessão.
O broker escreve respostas por `write_frame` com pipe não bloqueante,
`poll()` e deadline monotônico. Se houver timeout, pipe quebrado ou escrita
parcial, a sessão falha e nenhum novo evento `delivered` é creditado.
**Nunca** confiar em `Pending.framed` ou eventos declarados pelo worker.
O broker deve ser instanciado somente no processo supervisor confiável.

**Contabilidade.** O `journal` distingue `requested`, `mediated`,
`delivered`, `rejected` e `delivery_failed`; o trace legado de
`execution_verifier.py` contém apenas leituras completamente enviadas ao
canal, com `seq/start/end/sha256`. Um evento entregue demonstra envio ao
buffer do canal, **não** que o worker leu, analisou ou compreendeu esses bytes.
O registro em memória não possui custódia isolada enquanto não houver runner.

**Arquivo privado opcional.** `trace_store.persist(session)` requer sessão
finalizada sem falhas e grava `trace.json`, `result.json`, `journal.json` e `manifest.json`
em `hackbots/private/runs/<random-id>/`, diretórios modo 0700 e arquivos
0600, sem sobrescrever. O diretório `hackbots/private/` está ignorado pelo Git.
O manifesto é gravado por último e inclui SHA256 de cada arquivo e dos módulos
atuais, úteis para detectar divergências, mas sem autenticação externa.
Esses arquivos são confidenciais e podem conter saídas sensíveis fornecidas
pelo worker; não compartilhar nem tratá-los como evidência autenticada.
Persistência por enquanto ocorre **somente após** a sessão completa; falhas
do processo antes dela perdem o registro em memória e não produzem prova
completa. Nenhum runner/sandbox/autenticação de trace foi habilitado.

**Testar localmente, sem agentes nem APIs:**

```sh
cd ~/MITR3
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/runner/tests -q
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/skill-builder/tests -q
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/tests -q
```

A suíte do broker inclui uma comparação ponta a ponta entre trace mediado e
`execution_verifier.py` para uma fixture sintética. `coverage_gate=PASS`
não altera `behavioral_gate=NOT_RUN`.

**Manifesto e matriz de cobertura.** O manifesto também registra `artifact_sha256`,
`artifact_bytes`, `persisted_at` (UTC) e `policy_configured`: limites
**configurados**, não prova de limite aplicado em runtime. Falhas ao criar ou
validar diretórios privados (symlink, modo inseguro) saem como `BrokerError`,
sem escrever fora de `hackbots/private/`. `tests/test_trace_matrix.py` executa
o `execution_verifier.py` real sobre traces produzidos pelo broker: linha ou byte
omitido (FAIL), sobreposição e releituras (PASS), CRLF, última linha sem LF,
UTF-8 multibyte dividido entre intervalos e arquivo vazio. Para arquivo vazio o
broker rejeita qualquer leitura e o verificador retorna `NOT_APPLICABLE` com código
de saída 1 (ele só sai com 0 quando `coverage_gate=PASS`). Traces duplicados,
fora de ordem, com hash inválido, contagem divergente, JSON truncado ou pin errado
resultam em `BLOCKED` (código 2), nunca em PASS. Limitação conhecida: uma sessão com
falha ou timeout não é persistida; a gravação de execuções incompletas fica para o
runner (Rodada 5).

**Próximo portão:** Bubblewrap/cgroups, processos limitados, custódia isolada,
IPC real do worker, cancelamento/timeout da árvore e testes negativos de rede,
filesystem e FDs. Sem esses controles, não promover gates nem executar agentes.


## Rodada 4 — Sandbox Bubblewrap + cgroups (offline, não é Runner E2E)

Implementação: `sandbox.py` e `tests/test_sandbox.py`. Os diagnósticos
**executam apenas probes sintéticos confinados**, não o analisador JavaScript
nem qualquer agente/LLM.

Comandos reprodutíveis, executados **como usuário regular nielz**:

```sh
cd ~/MITR3
python3 -m hackbots.runner.sandbox doctor
python3 -m hackbots.runner.sandbox selftest
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/runner/tests -q
```

`doctor` confere executáveis, flags, serviço systemd de usuário, limites
de memória, swap, tarefas e **CPUQuota=100%**. Agora verifica diretamente
`cpu.max`: quota finita, positiva e no máximo um núcleo. Limite ausente
significa BLOCKED, **não** execução sem cgroup ou fallback inseguro.
`selftest` executa tentativas de leitura/escrita no host, acesso à rede
do host, socket Unix, nested userns, ambiente com chaves-canarinho,
permissões, quota de /tmp, árvore de processos, limites de memória/pids,
encerramento e ausência de resíduos.

Isolamento: `systemd-run --user --scope` com cgroup, `prlimit` local,
Bubblewrap com namespaces separados, `--clearenv`, capacidades removidas,
root read-only, somente `/usr` e o script temporário expostos para o
worker, `/tmp` com quota. Falha de qualquer componente bloqueia o
processo, sem fallback para ambiente host. Não executar o sandbox como root.

**Prova local em 2026-10-23:** doctor READY_FOR_REVIEW (cgroup/memória,
swap, pids e CPU presentes); selftest SELFTEST_OK (13 controles PASS).
Runner: 74 testes PASS no total, 1 SKIP por FD máximo 1024 no usuário
`nielz`; skill-builder 64 PASS; hackbots 27 PASS. O SKIP não é PASS.

**Limites:** isolamento Linux não é VM; probe não testa o worker real
ou a custódia dos traces no processo confiável. A quota mede CPU no
cgroup; `max_total_bytes` e IPC continuam exigindo Runner E2E.
`trace_authenticity=NOT_VERIFIED`, `behavioral_gate=NOT_RUN`,
`output_gate=NOT_RUN`, `human_approved=false`, `promotable=false`.

**Próximo gate:** ligar worker determinístico ao Broker por IPC, verificar
snapshot e traces via verifier sobre **exatamente os mesmos bytes**,
guardar resultado privado, reexecutar selftest/fail-closed e revisar
operações de processo/timeout/kill-tree. Não habilitar outros agentes.

## Rodada 5 — Primeiro worker integrado (offline, sem LLM)

Arquivos novos: `runner.py`, `workers/deterministic_js.py`, `tests/test_runner.py`.
O executor é estritamente de fixture sintética: carrega snapshot com SHA256
previamente fixado, roda `doctor` e `selftest` novos a cada missão, prepara
somente o worker standalone sob Bubblewrap/cgroups, oferece IPC de frames JSON,
mede no broker a entrega dos intervalos, exige saída limpa e confirma ausência
de processos remanescentes antes de persistir o resultado privado.

O worker lê apenas por `read_interval`, calcula hash, bytes e linhas físicas.
Ele não executa JavaScript, não extrai rotas, não usa rede, shell ou agentes.
Após `submit_result`, o supervisor verifica o encerramento limpo e rejeita
stdout adicional não mediado.

O store salva `snapshot.bin` (arquivo privado 0600), `trace.json`,
`journal.json`, `result.json` e `manifest.json` em diretório 0700, sem
sobrescrita, além de hashes dos módulos do runner, sandbox e worker.
O supervisor executa o **Execution Verifier já existente** em processo separado
contra os bytes do `snapshot.bin` persistido. Depois compara a saída
com o oráculo local determinístico, com tipos estritos (bool != inteiro).
Essas comparações são separadas de `output_gate` do Skill Evaluator, ainda NOT_RUN.

```sh
cd ~/MITR3
# Somente para fixture SINTÉTICA conhecida, como usuário normal nielz.
sha256sum hackbots/examples/sample.js
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.runner doctor
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.runner selftest
# REVIEWED_SHA256 deve vir de um registro independente e previamente aprovado.
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.runner run \
  --fixture hackbots/examples/sample.js --artifact-sha256 "$REVIEWED_SHA256"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/runner/tests -q
```

Nenhum comando de missão aceita comando arbitrário, caminho externo ou
worker selecionável. O valor `artifact-sha256` deve ser fixado pelo revisor
independentemente; calculá-lo junto ao run não prova aprovação externa.

Saída positiva da fixture existente: estado `REVIEW`, `sandbox_gate=SELFTEST_OK`,
`trace_gate=PASS`, `coverage_gate=PASS`, `deterministic_oracle=PASS`;
`trace_authenticity=NOT_VERIFIED`, `behavioral_gate=NOT_RUN`,
`output_gate=NOT_RUN`, `independent_review=NOT_RUN`,
`human_approved=false`, `promotable=false`.

Limites importantes: a escrita completa no canal IPC não prova consumo pelo
worker. O hash local não autentica contra processos hostis com mesmo UID;
o runner não é VM e não impede compromissos de kernel. Falhas e timeouts do
worker hoje são bloqueados e encerrados, mas traces de sessões incompletas não
são persistidos como cadeia de custódia auditável. A aceitação da skill ainda
exige Skill Evaluator com suíte fixada fora do controle do agente e revisão humana.
Não conectar Morfeus a outros alvos ou ferramentas enquanto o gate operacional
permanecer pendente.

**Conformidade da implementação:** checada com `docs/SCOPE.md`,
`hackbots/docs/EXECUTION-VERIFIER.md`, o padrão Bubblewrap de namespace/montagem
e `--die-with-parent` (manual Arch), e limites `CPUQuota/MemoryMax/TasksMax`
da documentação `systemd.resource-control`. A camada IPC usa escrita que trata
retornos parciais conforme documentação Python `os.write`.

## Rodada 6 — Evidências privadas de falhas e timeouts (sem promoção)

**Novo:** `failure_store.py` e `tests/test_failure_store.py`. O supervisor
agora grava tentativas **incompletas** ocorridas depois que uma sessão Broker
é criada, exclusivamente em `hackbots/private/failures/<id>/`.
Esse caminho fica fora do Git e não pode ser utilizado como run aprovado.

O arquivo `manifest.json` é persistido **por último**. Antes dele, o store
grava `partial-trace.json`, `journal.json` e `snapshot.bin`; não há
`result.json` nem `trace.json` de sucesso. Em qualquer falha/timeout,
`trace_gate=NOT_VERIFIED`, `coverage_gate=NOT_RUN`,
`behavioral_gate=NOT_RUN`, `promotable=false` e
`human_approved=false`. O evento `delivered` registra apenas bytes
escritos completamente no canal. Não significa análise feita pelo worker.

A persistência usa diretórios `0700`, arquivos `0600`, flags
`O_EXCL|O_NOFOLLOW`, SHA256 dos artefatos, `fsync` e motivo/estágio
somente de enums confiáveis. A mensagem bruta de exceção não é persistida:
poderia conter dados sensíveis controlados pelo worker. Um timeout real e
um worker enviando IPC malformado foram exercitados em laboratório.

**Limitações relevantes:** a guarda de falhas começa após a sessão ter sido
inicializada; erros de `doctor`, `selftest`, pin inválido ou falhas no
armazenamento podem ocorrer sem manifesto. Crash abrupto do supervisor
também pode interromper a gravação: a ausência do manifesto indica custódia
incompleta. Os hashes não autenticam um processo hostil com o mesmo UID.
Se a limpeza do sandbox falhar, o registro deixa
`sandbox_cleanup=NOT_VERIFIED`; nenhuma inferência de isolamento aprovado.
Registros privados de falha são confidenciais e não devem ir para prompts
ou repositórios.

**Documentação usada para esta etapa:** Python `os.open(dir_fd)`,
`O_NOFOLLOW`, `O_EXCL`, `os.fsync`
(https://docs.python.org/3/library/os.html);
Bubblewrap `--die-with-parent` e namespaces
(https://man.archlinux.org/man/bwrap.1.en);
systemd `TasksMax`, `MemoryMax`, `CPUQuota`
(https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
A execução continuará limitada a fixtures sintéticas e worker offline,
sem conexão automática ao Morfeus.

**Próximo portão:** revisão independente e handoff de **leitura apenas**
para o Morfeus, com oráculos/pins externos e estados honestos;
não atribuir a ele ferramentas para executar comandos arbitrários.

## Rodada 7 — Leitura restrita de evidências (metadados apenas)

Implementado `inspect.py` e `tests/test_inspect.py`, sem conectar agentes
automaticamente. A consulta devolve **somente** status enumerados,
contagens, ID opaco previamente informado e integridade dos arquivos locais;
**não devolve** dados do snapshot, nomes de rotas, argumentos, conteúdo de
resultados, logs, mensagens de exceção, SHA256 de dados privados ou instruções
encontradas nos traces.

Comandos para operador autorizado (UID `nielz`):
```sh
cd ~/MITR3
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.inspect summary --kind complete
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.inspect summary --kind failed
# Use um ID opaco de uma execução específica que você já conhece:
PYTHONDONTWRITEBYTECODE=1 python3 -m hackbots.runner.inspect inspect --kind complete --run-id "$RUN_ID"
```

`summary` reporta total de diretórios, até 25 registros amostrados
(max configurável 100), consistentes, bloqueados e não verificados.
A amostra usa IDs opacos em ordem lexicográfica, **não é uma timeline**
nem garante exaustividade. O comando `inspect` valida ID hexadecimal
estrito de 32 caracteres, diretórios 0700, arquivos regulares 0600,
propriedade do usuário, ausência de links, conjunto exato de arquivos
e SHA256 de todos os artefatos. Rejeita JSON duplicado e tentativas
de promover `behavioral_gate` ou `promotable`.
Em erro, devolve código 2 e diagnóstico genérico, sem ecoar entradas.

`runner.py` também passou a carregar código do worker por arquivo aberto
com `O_NOFOLLOW` e `dir_fd`, validando tipo, proprietário, modo,
link count, tamanho e identidade dos bytes antes/depois da leitura. Isso
elimina a corrida anterior `lstat(path)` + `read_text(path)`;
**não** impede que processos hostis com controle do mesmo UID alterem
o restante da instalação.

**Importante:** esta CLI é somente de leitura, mas **não constitui**
isolamento de permissões se Morfeus/Antigravity tiverem acesso genérico
ao shell ou à pasta `hackbots/private`. Para uma integração real, entregar
apenas o comando estritamente parametrizado por um broker de menor privilégio.
Não habilitar shell irrestrito, rede, execução de skills nem promoções.
Dados de ferramentas/modelos continuam não confiáveis, mesmo quando
estruturados. Consulta nunca equivale a aprovação humana.

Referências confrontadas: OWASP AI Agent Security/MCP Security (least
privilege, validação e fronteiras entre agentes);
Python `os.open`, `dir_fd` e `fstat` (controle de symlinks/custódia);
Bubblewrap e systemd cgroups conforme auditorias das Rodadas 4–6.

Estado: **READY_FOR_INDEPENDENT_REVIEW**, não produção;
`trace_authenticity=NOT_VERIFIED`, `behavioral_gate=NOT_RUN`,
`human_approved=false`, `promotable=false`. Sem chamadas LLM
ou alterações em configurações do Morfeus/Antigravity.

## Continuação da auditoria Astra — F04: outcome imutável e limites do verificador

**Estado do código:** F04 corrigido no protótipo local, aguardando revisão
independente das novas alterações e ainda bloqueado pelo F01 (same-UID).

Uma chamada `trace_store.persist` grava agora `state=SESSION_RECORDED`,
significando **apenas sessão do Broker gravada**. Não implica verificação nem
saída correta. Os manifests históricos `state=REVIEW` permanecem intocados
e a consulta os apresenta como `RECORDED_SESSION_AWAITING_OUTCOME` quando
não existe `outcome.json`.

Depois da persistência, o supervisor executa o verifier e o oráculo.
O novo `outcome_store.py` grava uma única vez `outcome.json` sob 0600,
vinculado ao SHA256 de `manifest.json` e ao ID opaco do run. Seus estados
estritos são `VERIFIED` (verifier e oráculo locais consistentes),
`FAILED` (saída divergente) e `BLOCKED` (verifier/resultado indisponível).
O outcome **não** aprova skills: `output_gate=NOT_RUN`,
`trace_authenticity=NOT_VERIFIED`, `behavioral_gate=NOT_RUN`,
`human_approved=false`, `promotable=false`. `VERIFIED` é
**consistência local**, não autenticidade nem aceite operacional.

O runner impede entrada com mais de 10.000 linhas físicas LF antes de lançar
worker e recusa um trace JSON de mais de 1.000.000 bytes antes de criar uma
sessão completa. Esta segunda recusa produz registro parcial em `failures/`
quando possível. Falhas do verifier **depois** da persistência produzem
`outcome.json` com `BLOCKED`; ausência de outcome sempre significa
**sem resultado final verificável**, inclusive em crash antes da gravação.
O inspector aceita ambos formatos, confere ligação/hash/modo/ausência de
sobrescrita, sinaliza `NOT_RECORDED` nos antigos e não revela dados brutos.

**Limitações:** hashes locais continuam manipuláveis por processo malicioso
no mesmo UID do supervisor; `outcome.json` não resolve o P0. Sucesso local
não confirma consumo/compreensão semântica dos bytes pelo worker.
Limites compartilhados com `execution_verifier.py` exigem regressão após
alteração de versões. Persistência interrompida pode deixar outcome ausente.
Não ligar shell ou execução automática do Morfeus antes da segregação de
identidades e da revisão independente.

Fontes técnicas: Python 3.14 `os.open`, `dir_fd`, `O_NOFOLLOW`,
`O_EXCL`, `os.fsync` (https://docs.python.org/3/library/os.html);
NIST SP 800-209 (segregação de acesso e proteção de logs);
`reviews/astra/hackbots-full-audit-20261024T013252Z/SECURITY-FINDINGS.md`.
