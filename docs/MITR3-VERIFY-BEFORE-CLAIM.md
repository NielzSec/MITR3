# MITR3 — verify-before-claim

Um finding de agente só pode sair como **confirmado** no boletim depois que a
reprodução estiver salva, com id estável, e o registro correspondente estiver
`verified`. O módulo não executa o comando gravado, não abre rede e não decide
que um alvo é vulnerável. Verificar aqui significa: o pacote salvo está
completo e o SHA-256 dos bytes ainda confere.

## Onde isso entra

O boletim deste caminho é o CLI `bin/mitr3-evidence.py report`. A função
`evidence.gate.report` é a mesma decisão para qualquer outro canal. O texto
publicável é só o retorno de `evidence.gate.render_bulletin`: ele cita o id e
as refs dos artefatos (`<id>/output.txt`, `<id>/<nome>`) e não cola a saída
salva.

`tools/mitr3_slack.py` não está nesta árvore pública. Um post futuro nesse
canal usa esse texto, com o mesmo código de saída do CLI.

Estados do registro:

| Estado | Boletim |
| --- | --- |
| id ausente ou registro ilegível | `REJECTED`, `confirmed: false` (saída 3) |
| `claimed`, ou `verified` cujo arquivo não confere mais | `UNVERIFIED LEAD`, `confirmed: false` (saída 2) |
| `verified` com passos ou comando, saída não vazia e hashes intactos | `FINDING CONFIRMED`, `confirmed: true` (saída 0) |
| `rejected` | `REJECTED`, `confirmed: false` (saída 3) |

Salvar a reprodução deixa o registro em `claimed`. O boletim continua
rebaixado até `verify`.

## Ledger

Código em `evidence/`. Dados locais em `state/evidence-store/` (gitignored),
ou no diretório passado em `--store`:

```text
<root>/records/<id>.json
<root>/artifacts/<id>/output.txt
<root>/artifacts/<id>/<artefato>
```

O id é `evd-` mais 20 hex de SHA-256 do JSON canônico
`{"category","target","summary"}` depois de NFKC, espaços colapsados e
casefold. O alvo também perde a barra final. A mesma hipótese devolve o
mesmo id e não cria outro arquivo. Outro alvo ou outro resumo gera outro id.
A primeira reprodução salva fica; uma segunda com bytes diferentes responde
`evidence_conflict` e não troca o pacote.

Campos persistidos: id, categoria, alvo (pode ser vazio), passos, comando,
SHA-256 da saída, refs dos artefatos, timestamps e status
(`claimed` / `verified` / `rejected`).

## Exemplo

```sh
STORE=/tmp/mitr3-evidence
python3 bin/mitr3-evidence.py --store "$STORE" claim \
  --category injection --target lab.example/items \
  --summary "error body differs from the baseline"
```

```json
{"deduped": false, "id": "evd-28531c662779a7c5ff90", "status": "claimed"}
```

```text
UNVERIFIED LEAD evd-28531c662779a7c5ff90
confirmed: false
disposition: downgraded
reason: not_verified
```

Esse `report` sai com código 2. O mesmo texto continua depois de `save`: a
saída já está no disco (`evd-28531c662779a7c5ff90/output.txt`), e o status
ainda é `claimed`.

```sh
python3 bin/mitr3-evidence.py --store "$STORE" save evd-28531c662779a7c5ff90 \
  --step "record the baseline response" \
  --step "record the response that includes the marker" \
  --command "recorded local comparison" \
  --output "marker present in the saved error body"
python3 bin/mitr3-evidence.py --store "$STORE" verify evd-28531c662779a7c5ff90
python3 bin/mitr3-evidence.py --store "$STORE" report evd-28531c662779a7c5ff90
```

```text
FINDING CONFIRMED evd-28531c662779a7c5ff90
confirmed: true
disposition: accepted
artifacts: evd-28531c662779a7c5ff90/output.txt
```

O `report` verificado sai com código 0. Repetir o `claim` com outra caixa ou
com espaços diferentes no mesmo alvo e no mesmo resumo devolve
`"deduped": true` e `evd-28531c662779a7c5ff90`. O boletim não imprime o corpo
salvo em `output.txt`.

## Fora deste gate

Estes caminhos continuam com o contrato que já tinham:

- `bin/mitr3-answer.py` publica `evidence_attached_proposal` (citação de
  catálogo) ou abstenção. Não é boletim de finding confirmado.
- `bin/mitr3-graph-verify.py` é o ledger de caminhos do grafo. O estado mais
  alto que ele grava segue `FEASIBLE_PATH`.
- `hackbots/tools/web_evidence.py` confere metadados diferenciais offline.
- `bin/mitr3-osint.py` continua marcando lead não verificado.
- O harness e o relatório CodeQL continuam sendo triagem estática.

Testes: `python3 -m unittest tests.test_verify_before_claim`.
