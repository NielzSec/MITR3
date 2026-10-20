# Runner paralelo de respostas

```sh
python3 bin/mitr3-blind-run.py /caminho/conjunto.json \
  --model provider/model --workers 4 --timeout 90 --pass 1 \
  --output /caminho/novo-relatorio.json
```

Não escolhe ou executa conjunto automaticamente. Exige dez perguntas com IDs
únicos. A execução é paralela, com 2–4 workers (padrão 4); a ordem das rows segue
a entrada. Cada tentativa executa o CLI de resposta existente, com o mesmo
adapter, stdin fechado, stderr descartado e argv sem shell. O deadline de 90 s
(padrão, configurável até 120 s) cobre a pergunta inteira, não cada subetapa.
Ao vencer, mata o grupo local do processo e recolhe seus pipes. Não garante
cancelamento de uma requisição que o provedor remoto já tenha recebido.

Repete **uma vez**, somente para `MODEL_TIMEOUT` ou `MODEL_FAILED`. Portanto uma
pergunta pode consumir duas tentativas de 90 s; não há promessa de prazo global
90 s para o conjunto. O limite pior é aproximadamente
`ceil(10/workers) * 2 * timeout`, mais overhead. Não repete abstenção, falha de
quote, schema, evidência ou gate.

Formato: `at_utc/set/sha256/model/pass/rows`. `sha256` é dos bytes da entrada;
`pass` é o número da rodada, não nota ou validação. Não calcula métricas contra
gabaritos. As rows guardam somente id, abstain, error, status, claim_count,
citation_ids, elapsed e attempts. Não persistem perguntas, prompts, claims,
quotes, stdout/stderr do modelo, corpos de fonte ou campos expected/forbidden.
IDs citados são limitados aos namespaces públicos do pipeline. O formato de topo
é compatível; as rows são deliberadamente metadados, não um arquivo de respostas
para revisão semântica. Não confundir ausência de claims brutas no relatório com
abstenção do modelo.

O output deve ser novo: abertura exclusiva, modo 0600, sem sobrescrever arquivos
congelados ou symlinks existentes. Não permite output no diretório `evals` nem
sobre a entrada. Dados privados não devem ser usados nesse runner; ambiente de
credenciais não é impresso. Os testes usam somente dez perguntas sintéticas e
processos mock/local, sem rede. Nenhum conjunto cego foi executado na entrega.
