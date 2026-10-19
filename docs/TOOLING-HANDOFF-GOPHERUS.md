# HANDOFF — gopherus py2→py3 (lane de ferramentas: Codex / GPT-6.0 / Astra)

Data: 2026-10-19 · Origem: maestro (OpenCode) · Diretriz do Kai: criação/fechamento de ferramentas = modelos topo do time; maestro não fecha ferramenta, coordena e verifica.

## Estado recebido (histórico)
- Item 9/9 da Fase 1 do `docs/ARSENAL.md` (deepseek/Hermes). Os outros 8 já estão vivos e com smoke no host.
- Base Nova: `~/Tools/gopherus` (clone fresh de 2026-10-19, tarunkant/Gopherus).
- **NÃO usar** `~/Tools/gopherus-py2.bak` (cópia com conversão intermediária corrompida — só referência).
- Converter automático já aplicado no clone nova: `print py2 → print()` (11 arquivos) e `raw_input → input`.

## 2 correções recebidas (diagnóstico original)
1. `gopherus/gopherus.py` — `SyntaxError: '(' was never closed` (linha do banner ~28)
   • O print da multi-linha de banner abriu,s com `print(colors.green + """…""" + … + colors.reset)`,
     Fechar com `)` no fim da linha 36 (após `colors.reset`).
2. `gopherus/scripts/PostgreSQL.py` — `TabError: inconsistent use of tabs and spaces` (linha 21)
   • O arquivo é tab-indented; a linha 21 (`return "gopher://127.0.0.1:5432/_%" + "%".join(a)`) está
     com indent de espaços. Corrigir indent para tab (igual ao `a = [...]` da linha 20). Mescla do
     conversor.

## Aceitação
- `for f in ~/Tools/gopherus/*.py ~/Tools/gopherus/scripts/*.py; do python3 -m py_compile "$f"; done` → zero erros.
- Smoke: `printf '' | python3 ~/Tools/gopherus/gopherus.py` → banner + help sem crash.
- Smoke interativo: `python3 gopherus.py --exploit redis` (aceita menu/input sem NameError).
- Wrapper: criar `~/.local/bin/gopherus` (exec python3) e declarar Status "instalado (py3-portado)" na tabela do ARSENAL.
- Commit no `~/MITR3` + selo SHA256SUMS se ARSENAL.md mudar.

## Doutrina (Kai — registrar evidência)
Modelo vencedor: **Codex (GPT-6; variante interna não exposta pela sessão)**.

Prompt vencedor (em restrição): «Fechar banner/parêntese e indentação da linha 21
na base NOVA `~/Tools/gopherus`, ignorar `.bak`; exigir py_compile zero,
smoke banner+help, wrapper local, ARSENAL `instalado (py3-portado)`, re-selo
e commit; registrar modelo/prompt neste handoff.»

ID de evidência: `GOPHERUS-PY3-20261019T185714Z`. Commit de fechamento: localizar pelo título
`fix(gopherus): close fresh-base Python 3 handoff` (contém este registro).

*Handoff segue o padrão MITR3: aqui o maestro projeta, o lane topo fecha. Requisito explícito do Kai: ferramentas são models top-tier (Codex Sol / GPT-6.0 / Astra-tier), e se o modelo segurar, o prompt é forjado, não o item rebaixado.*


## Fechamento — 2026-10-19T18:57:14.821757+00:00

- Base usada: `~/Tools/gopherus`; upstream `90a2fd5799342bbd493966ed95ed2489068ea568`.
- Banner: abertura/fechamento de `print(...)` corrigidos; literal raw remove
  avisos de escape. Shebang alinhado a Python 3.
- PostgreSQL linha 21: `return` usa dois tabs, igual à atribuição da linha 20.
- O smoke revelou um terceiro bloqueio de import: `cPickle` não existe no
  Python 3. Corrigido para `import pickle as cPickle`, preservando os usos.
- `python3 -m py_compile` passou nos **12 arquivos**, exit 0, stderr vazio.
- Sem argumentos: banner + ajuda; `--help`: ajuda; menu `--exploit redis`
  recebeu `smoke` e saiu sem NameError. Todos exit 0 e stderr vazio.
  O menu foi validado sem selecionar geração de payload e sem rede.
- `command -v gopherus`: `~/.local/bin/gopherus`, idêntico ao wrapper
  versionado `bin/mitr3-gopherus.sh`; ambos usam só a base nova.
- Patch completo do upstream até a base nova: `patches/gopherus-py3.patch`
  (contexto zero; aplicar com `git apply --unidiff-zero` no commit upstream registrado).
  Aplicação reconstruída a partir de `git archive HEAD` passou em
  `git apply --unidiff-zero --check`; os 12 SHA256 coincidiram com os arquivos instalados.
- Evidência: `reports/gopherus-smoke-latest.json`; ARSENAL, handoff, wrapper,
  patch e relatório re-selados em `docs/SHA256SUMS` (caminhos relativos a `docs`).

Escopo da aceitação: compilação, banner/ajuda e entrada do menu Redis. Os
outros modos e equivalência de payloads com Python 2 continuam não validados
nesta base; o rótulo py3-portado não amplia a cobertura deste smoke.
