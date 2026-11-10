# Execution Verifier — protótipo offline e contrato do runner

Estado: **OFFLINE_PROTOTYPE / SYNTHETIC_RUNNER_AVAILABLE**. O verificador de consistência
e cobertura está implementado; o [runner sintético](../runner/README.md) possui isolamento
e IPC instrumentado. Autenticidade contra processos do mesmo UID e gate comportamental
continuam não verificados. Escopo inicial: uma fixture JavaScript sintética
local; sem rede, amostras externas, APIs pagas ou execução do JavaScript recebido.

## O que cada componente pode afirmar

| Componente | Afirmação permitida |
| --- | --- |
| Builder | Geração estrutural e consistência de hashes |
| Evaluator atual | Igualdade de JSON com os oráculos e regressões |
| Inventário independente | Unidades esperadas segundo uma regra explícita e versionada |
| Runner sintético atual | Intervalos escritos integralmente pelo broker no canal IPC |
| Verifier offline atual | Consistência e cobertura declarada dos registros fornecidos |
| Revisor / JEV | Parecer sobre evidências e conclusões, sem substituir aceite humano |

`hackbots/tools/js_inventory.py` usa regex. Não identifica todas as funções, blocos,
chamadas ou caminhos de execução JavaScript. Não usá-lo como oráculo de cobertura
semântica nem derivar o denominador das próprias referências encontradas pelo worker.

## Contrato do ensaio completo (custódia externa ainda pendente)

1. O revisor fixa os bytes da fixture, da metodologia, da skill e da suíte por SHA256.
   Guarda o digest da suíte fora do espaço gravável do worker.
2. Um inventariador independente enumera **todas as linhas físicas** da fixture,
   inclusive comentários e linhas vazias. Para esta versão, linha é o trecho de bytes
   até LF inclusive; o trecho final sem LF também conta. Arquivo vazio tem zero unidades.
   IDs derivam de hash do arquivo, número da linha e intervalo de bytes. Isso mede
   leitura de linhas, não compreensão nem cobertura de funções.
3. O runner entrega ao worker somente uma operação de leitura de intervalos e uma
   operação de entrega de resultado. Nenhuma ferramenta arbitrária nem shell da amostra.
   Registra os bytes efetivamente entregues por hash e os intervalos, com sequência
   monotônica, identidade da execução e versão/hash do runtime.
4. O verifier recalcula as unidades a partir da fixture fixada, confere os eventos
   do runner e deriva a união dos intervalos efetivamente entregues. Uma linha só conta
   quando todos os seus bytes estiverem cobertos. Releituras não aumentam o total.
5. O Evaluator compara a saída resultante com os oráculos usando `--suite-sha256`
   fornecido pelo revisor. Saída ausente ou divergente não vira PASS por cobertura total.
6. Revisor independente examina conclusões e limitações. JEV e aprovação humana
   continuam gates separados; o ensaio nunca promove uma skill automaticamente.

## Fronteira de confiança

Um trace escrito pelo agente é uma declaração. Um hash ou encadeamento de hashes
detecta inconsistência, mas não autentica quem produziu o trace. O runner precisa
controlar a produção e custódia dos registros e impedir que o worker altere a fixture,
o inventário, o verificador, os oráculos ou o registro. Pastas distintas sob o mesmo
usuário não fornecem essa garantia. Bubblewrap/cgroups isolam o worker nos probes
locais; não isolam agentes com shell no UID do supervisor. Até existir custódia
independente testada, qualquer protótipo deve declarar `trace_authenticity:
NOT_VERIFIED` e não emitir `behavioral_gate: PASS`.

O relatório separa `trace_gate`, `coverage_gate`, `output_gate`,
`behavioral_gate`, `independent_review` e `human_approved`. Gates não executados
permanecem `NOT_RUN`; aprovação humana permanece `false` e `promotable: false`.
Cobertura vazia deve ser `NOT_APPLICABLE`, nunca prova comportamental vacuamente positiva.
Não registrar código bruto, parâmetros secretos ou prompts sensíveis em logs de handoff.

## Uso do protótipo implementado

Execute a partir de `~/MITR3` com o digest previamente fixado pelo revisor:

```sh
python3 hackbots/skill-builder/execution_verifier.py inventory \
  hackbots/examples/sample.js --artifact-sha256 DIGEST_REVISADO
python3 hackbots/skill-builder/execution_verifier.py verify \
  hackbots/examples/sample.js CAMINHO_TRACE.json --artifact-sha256 DIGEST_REVISADO
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s hackbots/skill-builder/tests -v
```

O trace JSON estrito tem somente `schema_version: 1`, `artifact_sha256`,
`event_count` e `events`. Cada evento tem somente `seq`, `start`, `end`, `sha256`.
`seq` inicia em 1 e cresce sem lacunas; `[start, end)` usa offsets em bytes, com
`sha256` dos bytes dessa faixa. Contagem incorreta, campos extras, booleanos como
inteiros, intervalos vazios/fora do arquivo e hashes divergentes bloqueiam a leitura.
O protótipo não recebe IDs de linha declarados pelo worker: recalcula-os.

São permitidos até 1 MB por arquivo, 10.000 linhas, 10.000 eventos e 16 MB cumulativos
de intervalos verificados (releituras também consomem esse orçamento). Symlinks,
arquivos especiais e JSON ambíguo são rejeitados pelo leitor do Skill Builder.
O inventário inclui comentários e linhas vazias e não revela conteúdo bruto ou
caminho da fixture. Hashes de arquivo e de linha **também são metadados sensíveis**:
este inventário destina-se ao revisor local, não à publicação irrestrita.

`trace_gate: PASS` significa consistência dos eventos fornecidos. `coverage_gate:
PASS` significa que a união dos intervalos cobre todos os bytes de todas as linhas;
releituras não aumentam o denominador. Arquivo vazio retorna `NOT_APPLICABLE`.
Mesmo no PASS, `trace_authenticity: NOT_VERIFIED`, `behavioral_gate: NOT_RUN`,
`output_gate: NOT_RUN`, `human_approved: false` e `promotable: false` são preservados.
O avaliador de saídas permanece uma operação separada: nenhum PASS de cobertura
substitui sua comparação com oráculos.

CLI: código 0 para inventário válido ou cobertura completa; 1 para cobertura
incompleta/não aplicável; 2 para entrada bloqueada. Diagnósticos não reproduzem
argumentos ou conteúdo da fixture. Preserve stdout/stderr em arquivos novos sob
controle do revisor. Os testes usam traces sintéticos escritos à mão, sem claim de
execução real. A autenticidade e truncamentos coordenados de trace não são detectáveis
por este formato quando alguém reescreve também a contagem e os demais campos.

## Critérios de aceite antes de habilitar o ensaio

- Caso positivo com leitura completa e saída correta; negativo com linha omitida.
- Releituras, intervalos parciais, IDs inventados, eventos duplicados/fora de ordem,
  arquivo vazio, CRLF e última linha sem LF não distorcem o denominador.
- Mudança de bytes após inventário, hash incorreto, trace truncado e saída ausente bloqueiam.
- Worker não consegue escrever no inventário, oráculo ou trace; adulteração coordenada
  da suíte e saídas falha contra o digest externo previamente guardado.
- Mesmo com cobertura completa, saída errada falha e regressão é detectada.
- Symlinks, arquivos especiais, excesso de tamanho e entradas inválidas falham sem
  travar nem revelar conteúdo sensível; timeout/erro do runner preserva estado incompleto.
- Fixture com instruções em comentários não concede novas ferramentas; tentativas
  de rede e escrita fora da entrega são bloqueadas pelo runtime e verificadas em teste.
- Revisão independente da implementação e dos oráculos; evidências e SHA256 preservados.

Versionamento: revisar e selecionar explicitamente os arquivos de código, testes,
fixtures sintéticas e documentação para um commit dedicado. O repositório atual tem
alterações alheias a esta entrega; não usar `git add .`, incluir drafts/evidências
sensíveis nem tratar um commit como aprovação operacional.
