# HANDOFF — gopherus py2→py3 (lane de ferramentas: Codex / GPT-6.0 / Astra)

Data: 2026-10-19 · Origem: maestro (OpenCode) · Diretriz do Kai: criação/fechamento de ferramentas = modelos topo do time; maestro não fecha ferramenta, coordena e verifica.

## Estado
- Item 9/9 da Fase 1 do `docs/ARSENAL.md` (deepseek/Hermes). Os outros 8 já estão vivos e com smoke no host.
- Base Nova: `~/Tools/gopherus` (clone fresh de 2026-10-19, tarunkant/Gopherus).
- **NÃO usar** `~/Tools/gopherus-py2.bak` (cópia com conversão intermediária corrompida — só referência).
- Converter automático já aplicado no clone nova: `print py2 → print()` (11 arquivos) e `raw_input → input`.

## 2 correções residuais (com diagnóstico pronto)
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
Modelo vencedor: ______ · Prompt vencedor (em restrição): ______ · ID/commit: ______

*Handoff segue o padrão MITR3: aqui o maestro projeta, o lane topo fecha. Requisito explícito do Kai: ferramentas são models top-tier (Codex Sol / GPT-6.0 / Astra-tier), e se o modelo segurar, o prompt é forjado, não o item rebaixado.*
