# MITR3 — Artefatos privados de revisão (escrow) para a rodada pareada

**Data:** 2026-10-20 · **Autor:** Codex (implementação) · **Maestro:** OpenCode
**Base:** NO-GO do QA `GPT6-V5-PRE-RUN-NOGO-20261020` (sha 28675085) — o runner metadata-only não permitia verificar C2.

## O que muda

O runner pareado passa a manter um **escrow privado e verificável** com o material necessário à revisão semântica, por item e por braço:

- `claim.text`, `citations[{id, quote}]`, snippet efetivamente transmitido (id, title, source, source_url, validation, sha256, namespace, kind), veredito/código do gate e pergunta.
- Diretório **fora do Git**, criado com `0700`, arquivos `0600`, nomes opacos (`<token>-<item>.json`, `<token>-final.json`).
- `manifest.json` com sha256 por artefato; verificação offline por `bin/mitr3-review-artifacts.py`.
- Campos de gabarito (`expected_answer`, `expected_ids`, `forbidden_ids`, `rubric`) **nunca** são decodificados nem persistidos.
- Relatório público continua metadata-only e referencia os artefatos por hash.

## Proteções implementadas

- Recusa de diretório dentro do repositório.
- Escrita exclusiva (sem sobrescrita), permissões verificadas na leitura.
- Scrub de padrões sensíveis (e-mails, chaves, tokens) antes de persistir.
- Manifesto à prova de adulteração: qualquer divergência de hash falha a verificação.

## Prova DEV (QA item 1)

Fixture sintética pública `tests/fixtures/review-artifacts-dev-v1.json`, dois itens por braço:

| Braço | Claim | Evidência | Gate | JEV | GPT QA |
|---|---|---|---|---|---|
| ambos | "The public lab endpoint returned HTTP 200." | "the panel returned HTTP 200. Command channel state was not tested." | accepted | **0.59** (flagged, evidência mínima) | **SUSTENTADA** |
| ambos | "The command and control service is alive." | idem | accepted | **0.07** | **NÃO SUSTENTADA** |

- Escrow verificado: `review_ready=true`, manifesto `16a9a17d…`.
- Revisores conseguem ler claim, citação e snippet dos dois braços; o canário falso é separável do verdadeiro pelas duas trilhas.
- Manifests JEV: `jev_dec_a4ec11d849a44135` (0.59) e `jev_dec_df3668fe9ab64edd` (0.07).

## Comandos

```sh
python3 bin/mitr3-candidate-run.py <set> --arm baseline|candidate \
  --private-dir <fora-do-repo> --model <id> --output <relatorio.json> \
  --expected-set-sha256 <sha> --operator-approved
python3 bin/mitr3-review-artifacts.py --verify <private-dir> --report <relatorio.json>
```

## Limites

- Escrow não corrige composição; preserva também claims rejeitadas pelo gate.
- A verificação prova integridade do artefato, não a verdade da claim.
- Nada disso altera Gate D, prompts de produção ou o conjunto v5.
