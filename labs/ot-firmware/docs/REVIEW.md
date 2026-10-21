# REVIEW — Defeitos confirmados no fwlab (hardening)

**Status atual (2026-10-21): TODOS os 7 defeitos verificados como FIXED.**
`python3 -m unittest discover -s tests` → 38 testes, 38 OK, 0 `expectedFailure`.
Os asserts de `tests/test_hardening.py` descrevem o comportamento desejado e
hoje passam como testes duros (0 skips, euid 1000). Abaixo, cada item mantém o
registro do defeito e ganha o ponteiro do fix.


---

## H1 — Contenção lexical; symlink pré-existente no destino redireciona escrita

**Sintoma:** se o diretório de destino já contém um symlink cujo alvo fica fora
(`dest/sub -> ../outside`), um membro `sub/evil.txt` do arquivo escreve fora do
destino sem travamento.

**Causa provável:** a checagem de contenção resolve caminhos **lexicamente**
(normalização de string), não **fisicamente** (`os.path.realpath` após cada
escrita). O symlink plantado no destino bypasseia a checagem.

**Impacto:** escape do sandbox de extração via estado preexistente — não exigido
pelo arquivo malicioso, mas explorável se o destino for reutilizado.

**Correção sugerida:** resolver o destino com `realpath` antes de validar o
caminho final de cada membro, ou opcionalmente recusar extrair sobre symlinks
preexistentes dentro da árvore de destino.

---

## H2 — Erros de parse (zip/gzip/tar corrompidos) escapam como traceback

**Sintoma:** arquivos truncados/ilegais fazem `extract()` levantar exceção
(`BadZipFile`, `EOFError`, `ReadError`…) em vez de retornar `{'error': ...}`.

**Causa provável:** os handlers de zip/gzip/tar não envolvem o parse em
try/except; o caminho de erro esperado (retorno com `error`) não cobre falhas de
inicialização do container.

**Impacto:** o pipeline de fila/command da CLI pode quebrar em vez de marcar o
item como erro — transforma arquivo hostil em falha não tratada.

**Correção sugerida:** capturar exceções de parse em cada ramo
(`except Exception as exc: return {"error": f"{kind}: {exc}"}`) preservando o
retorno estruturado; nunca permitir traceback para fora de `extract()`.

---

## H3 — Symlink relativo com `../` aborta o arquivo inteiro

**Sintoma:** um tar com membro-symlink `lib/link -> ../shared/libc.so`
(apontamento relativo **benigno**, fica dentro da árvore após normalização)
aborta a extração; membros seguintes (`keep.txt`) não são extraídos.

**Causa provável:** a checagem de traversal trata qualquer `../` no ligamento
como hostil, sem verificar o alvo **resolvido** final.

**Impacto:** falso positivo — arquivos legítimos (libs linkadas, toolchains)
deixam de extrair; decisão de gestão de exceções deve vir do gate de
contenção, não de um string-match cru.

**Correção sugerida:** para symlinks, resolver o alvo contra o destino do membro
e avaliar a contenção **do resultado**, não do texto do ligamento.

---

## H4a — Membro modo 0100 sobrevive à extração e o `detect()` aninhado levanta

**Sintoma:** um membro com modo `0100` (execute-only) é extraído sem permissão
de leitura; a chamada aninhada de `detect()` no arquivo extraído levanta
`PermissionError` em vez de retornar.

**Causa provável:** a extração restaura o modo do membro antes da leitura de
identificação; `formats.detect()` não tolera arquivo ilegível.

**Impacto:** um tar com um executável ilegível derruba a extração do arquivo
inteiro. (Teste pula quando rodando como root — root lê modo 0100.)

**Correção sugerida:** restaurar permissões **depois** da detecção/nest do
arquivo, ou detectar lendo bytes antes do `chmod`.

---

## H4b — Arquivo ilegível no inventário aborta tudo

**Sintoma:** um arquivo com modo `0000` na árvore inventariada faz
`sha256_file()` levantar `PermissionError`, abortando `inventory()` inteiro (o
assert espera `files == 2`).

**Causa provável:** o hashing não trata `PermissionError` como entrada
"ilegível" registrada — aborta em vez de registrar e seguir.

**Impacto:** um único arquivo protegido invalida o inventário completo.
(Teste pula quando root.)

**Correção sugerida:** capturar `PermissionError` no hashing e registrar a
entrada com `sha256: null` + flag `unreadable`, sem abortar.

---

## H5 — Caminhos conflitantes (arquivo + filho) levantam `FileExistsError`

**Sintoma:** um tar com `a` (arquivo) e depois `a/b` (filho) levanta
`FileExistsError` no `mkdtemp`/escrita do filho, em vez de retornar `{'error':...}`.

**Causa provável:** a criação de diretórios não checa se o prefixo já é um
arquivo; conflito de tipo de path vira exceção não capturada.

**Impacto:** arquivo com grafo de path conflitante quebra a extração fora do
retorno estruturado.

**Correção sugerida:** detectar o conflito arquivo-vs-dir antes de escrever e
retornar erro estruturado (decisão: abortar o membro, não o arquivo inteiro).

---

## H6 — Tar vazio (all-zero) casa com a assinatura `zeroes` antes de `tar`

**Sintoma:** um `.tar` vazio (zero-filled trailer, 1024 zeros) é detectado como o
tipo genérico `zeroes` do `detect()`, não como `tar`.

**Causa provável:** a ordem das assinaturas em `formats.detect()` testa
`zeroes` antes de reconhecer a assinatura/estrutura tar.

**Impacto:** classificação errada — um tar vazio seria classificado como
`zeroes` e o pipeline trataria como "não arquivo". (Impacto baixo, mas quebra o
contrato de classificação e o teste determinístico.)

**Correção sugerida:** testar a assinatura ustar/tar antes do caso `zeroes`, ou
especializar: `zeroes` só quando não há cabeçalho ustar válido em 0.

---

## Resumo — verificados FIXED (2026-10-21)

| ID | Área | Tipo | Sev. | Fix no código | Teste |
|----|------|------|-------|---------------|-------|
| H1 | extração | escape sandbox (estado prévio) | alta | `extract._is_safe_dest` resolve `realpath` de cada componente | `test_preexisting_symlink_in_dest_does_not_escape` |
| H2 | extração | exceção não tratada | média | `extract.extract` envolve handlers em `try/except Exception` → `{'error': ...}` | `test_corrupt_containers_return_error` |
| H3 | extração | falso positivo (funcionalidade) | média | symlink resolvido contra o dir do membro, contenção avaliada do alvo final | `test_relative_symlink_with_dotdot_does_not_abort` |
| H4a | extração | exceção não tratada (perms) | baixa | `formats.detect` tolera ilegível (`type: unreadable`) | `test_execute_only_member_does_not_crash_extract` |
| H4b | inventário | robustez (perms) | baixa | `inventory.sha256_file` captura `PermissionError` → `sha256: null` + `unreadable` | `test_unreadable_file_inventory_does_not_crash` |
| H5 | extração | exceção não tratada (conflito) | média | `_check_path_conflict` detecta filho-sobre-arquivo e retorna erro estruturado | `test_conflicting_member_paths_return_error` |
| H6 | detecção | classificação errada | baixa | `formats.detect` testa magic `ustar` antes de `zeroes` | `test_empty_tar_detected_as_tar` |

Evidência: suíte 38/38, 0 expected failures, 0 skips — modo 0100/0000
exercitado de verdade (euid 1000, não root). Lab selado em commit local.

Nenhum tráfego de rede, nenhuma sonda externa, nenhum binário de terceiro no
cofre — somente o fixture sintético. Este doc é a linha oficial: os 7 defeitos
estão fechados no código e na suíte.
