# Onda 10 — runner oficial: construção e validação offline

Resultado: 84/84 testes PASS (35 runner + 32 harness + 17 staging gate).
Gate real dos nove templates: PASS_STRUCTURAL_ONLY, zero erros e zero chamadas de rede.
Execução isolada por bubblewrap --unshare-net, raiz somente leitura, /tmp descartável.
Os testes do runner também proíbem sockets/DNS e usam somente tokens sintéticos.
Não foram lidos os tokens reais nem executado --live. Inputs estáveis durante os testes.

## Entregas

- bin/mitr3-onda10-exec.py, executável 0755, stdlib, sem dependências novas.
- tests/test_onda10_exec.py: 35 testes, com subcasos adicionais.
- .gitignore: exclusão específica de /reports/onda10_execution/; alterações anteriores preservadas.

Dry-run é padrão e interpola em memória todos os nove templates, validando o gate,
hashes contra mudanças, ORDER_ID=2000015638831799, CRLF/framing e separação A/C/B.
Lê access_token e user_id de /tmp/opencode/token_[ABC].json; exige arquivos regulares
privados do usuário, sem symlinks. Nada imprime ou grava os requests autenticados.
A e B são vinculados aos IDs da SPEC; C deve ter identidade distinta.

--live --suite base (padrão) seleciona C1 → C2 → X1 do pedido base.
--live --suite all seleciona base → shipments → billing_info, cada trio C1 → C2 → X1.
Delay de 1,5 s após cada resposta antes da próxima requisição. Host fixo e TLS padrão
verificado, sem proxy do ambiente, sem redirect ou retry, timeout de 20 s.

Antes de cada envio: valida integralmente o rate ledger, usa a janela de tools/h1_rate_ledger.py,
consulta o teto 60/host/h, verifica paradas recentes e consulta o teto 10 da sessão.
Reserva persistida ANTES do socket. Ledger global recebe nota onda10-C1/C2/X1
(com sufixo de recurso nos sub-recursos); reserva count=1 e resultado count=0
para registrar status sem dupla contagem. Append usa o módulo existente com fsync.
Session ledger e lock impedem duas instâncias simultâneas deste runner; falha/interrupção
após reserva deixa stopped=true e exige reconciliação externa, sem retry automático.

429, WAF/captcha detectado, redirects, 5xx, controles inválidos/403, falha de transporte,
JSON inválido, resposta excessiva ou evidência impossível de gravar interrompem o fluxo.
Candidato também interrompe --suite all para revisão, preservando dados mínimos.

Classificação: controles exigem pedido/atores vinculados, dados não vazios e concordância.
X1 com 403/404 só é NEGATIVE com corpo de negação reconhecido, sem dados do pedido.
X1 com dados privados correspondentes ao baseline e vínculo de pedido/atores é
BOLA_CANDIDATE, inclusive se o status for 403/404; nunca classificar vazamento como seguro.
200 com casca vazia conhecida é NEGATIVE_SHELL. Corpos desconhecidos ou vínculo insuficiente
são INCONCLUSIVE, evitando inferir segurança a partir de HTTP 200/403/404 isolado.

Respostas ficam em reports/onda10_execution/<UTC>/, diretórios 0700, arquivos 0600.
*.body.raw preserva os bytes do corpo retornado por HTTPResponse (framing de transferência
já removido); *.headers.json preserva status, lista ordenada de cabeçalhos e timestamp.
Não é captura literal TLS/wire. summary.json não inclui dados privados/tokens.
SHA256SUMS e SHA256SUMS.sha256 selam os artefatos, inclusive nas paradas controladas.
Raw pode conter PII e deve permanecer privado; somente evidência redigida deve ser compartilhada.

## Operação e limites reais

Uso offline: python3 bin/mitr3-onda10-exec.py [--dry-run] [--suite base|all].
Uso live reservado ao OpenCode após QA/JEV externo: python3 bin/mitr3-onda10-exec.py --live --suite base.
Este trabalho NÃO executa nem concede aprovação QA/JEV operacional. --live é seleção explícita
de modo, não uma assinatura de aprovação; a autorização externa não é autenticada pelo script.
A lane independente de adjudicação QA/JEV permanece separada e pendente para este runner.

Session ledger é persistente: {"count": N, "events": [], "stopped": false} permite
registrar consumo anterior reconciliado (N inclui setup/browser da onda).
Se ausente, começa em zero e contabiliza apenas novas tentativas do runner. Não descobre
tráfego anterior automaticamente: operador deve incorporar setup antes do live, sem resetar
para contornar o teto. Artefatos antigos/ledgers não são apagados pelo runner.
O lock cobre este runner, não outros emissores: exige a disciplina de emissor único/serial
com browser/Burp e demais ferramentas. Não constitui sincronização global do navegador.

Tokens B/C reais tinham modo 0644 na inspeção de metadados: preflight os bloqueará até
permissões privadas serem aplicadas pelo operador. Arquivos reais não foram alterados/lidos.
Token user_id local não comprova sozinho identidade remota, propriedade ou condição test_user;
essas confirmações continuam no gate externo. Nenhum teste live/TLS real foi efetuado.
Sub-recursos usam os envelopes sintéticos conservadores do harness (order_id, buyer, seller
mais shipments/billing_info); formatos reais diferentes interrompem como inconclusivos.
WAF é reconhecimento de sinais conhecidos, não detecção universal de todos os fornecedores.
Resposta acima de 2 MB é interrompida; o artefato contém no máximo os primeiros 2 MB + 1 byte.

## Cobertura e reprodução

Comandos exatos, versão Python e isolamento em commands.json. stdout/stderr/exit de cada
suíte preservados. Testes cobrem nove templates, dry-run sem dispatch, modos incompatíveis,
tokens inválidos/duplicados/symlink/permissões/identidades, CRLF de cada célula,
ordem e delays, suite all, teto global e janela, setup no contador persistente,
ledger corrompido/falha de escrita, concorrência, paradas C1/C2, WAF, 429, 5xx,
redirect, candidate/negação/casca/corpo desconhecido, JSON duplicado, tamanho,
sanitação, evidências privadas e hashes, falha de rede sem replay e transporte TLS simulado.

inputs.sha256.json contém hashes de código, testes, dependências locais, SPEC e templates.
MANIFEST.sha256 sela inputs e este dossiê; MANIFEST.sha256.sha256 sela o manifesto.
Selo de integridade SHA-256 local, não assinatura digital nem aprovação operacional.
