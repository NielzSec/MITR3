# MITR3 — Apoio ao Codex: QA do diagnóstico MCP
Data: 2026-10-19 | GPT-6 externo (via Desktop Commander)
Destinatários: Codex (QA/build) e OpenCode (maestro)
Status: entrega assíncrona, sem mensagem direta pelo Maestri e sem reiniciar processos.

## Objetivo
Aprimorar a confiabilidade do diagnóstico de 7 MCPs desenvolvido pelo Codex:
bin/mitr3-mcp-check.sh. Não editar simultaneamente os arquivos do Codex.
Tratar esta revisão como proposta de patch, com testes reproduzíveis.

## Achados reproduzidos
- CLI OpenCode v2.0.32: opencode mcp list retornou UnexpectedStatus: 500
  nesta sessão. O processo opencode serve --service permanece ativo. Isto indica
  erro na consulta/API do cliente, não prova que todos os servidores estejam down.
- Última execução de mitr3-health.sh --json: 3 problemas de inicialização nos
  smokes separados (rea, chrome-devtools, playwright); apisec-ng e mitr3-nexus
  sobreviveram à janela de 5s.
- MegaBrain respondeu GET HTTP 406 e Context7 GET HTTP 405, classificados como
  boot: pass no script do Codex. Estes códigos podem ser normais quando o
  endpoint MCP exige POST e Accept adequado, mas NÃO provam protocolo funcional.
- process_alive: false é evidência insuficiente para concluir que a conexão
  aberta no cliente esteja indisponível; vários launchers usam npx e mudam argv.
- O health-check soma boot: pass em um indicador de disponibilidade MCP.
  É preciso distinguir uptime do processo, HTTP alcançável, handshake MCP e
  conexão comprovada pelo cliente.

## Entrega implementada, sem alterar o Codex
- reviews/codex/mcp_report_qa.py: reclassifica o JSON de modo conservador,
  não inicia serviços e não envia requisições de rede.
- reviews/codex/tests/test_mcp_report_qa.py: 9 testes unitários aprovados;
  cobrem 405/406 sem handshake, smoke local, falha de launch, client connected,
  problemas de configuração, relatório desatualizado, schema e sanitização.
- reviews/codex/reports/mcp-qa-latest.md + .json: QA sobre a saída observada.
- Execução: python3 ~/MITR3/reviews/codex/mcp_report_qa.py
- Testes: python3 -m unittest discover -s ~/MITR3/reviews/codex/tests -v

### Resultado da última evidência
7 configurados; 0 conexões confirmadas pela CLI nesta captura (a consulta falhou);
2 HTTP alcançáveis sem handshake, 2 launchers estáveis por 5s, 3 launchers
falharam na execução isolada. Não interpretar 0 confirmados como 0 operacionais.

## Sugestão de patch para Codex
1. Na saída, apresentar colunas independentes: status_cliente, boot_local,
   http_reachable, handshake, issues. Não usar "MCP OK" baseado só em boot.
2. Salvar uma classificação "inconclusivo" quando o cliente responder HTTP 500;
   indicar status HTTP/exit sem copiar corpo ou stderr bruto.
3. Para HTTP MCP, validar via POST JSON-RPC initialize, header Accept:
   application/json, text/event-stream; depois notifications/initialized e
   tools/list com session id/version negociados, com timeout controlado.
4. Para stdio, implementar um smoke de initialize/tools/list isolado e
   encerrar apenas o processo filho criado pelo teste, sem matar a sessão.
5. Fazer report timestamped e agregação que preserve unknown, evitando
   falso verde e falso vermelho. Adotar limites de CPU/RAM/timeouts.
6. Usar os 9 testes deste pacote como regressão e solicitar QA independente
   do OpenCode antes de alterar script usado pelo timer do health.

## Não realizado
- Nenhum MCP ativo foi reiniciado.
- Não usei comandos de pentest/rede.
- Não alterei o diagnóstico original do Codex.
- Não tratei GET 405/406 como falha crítica nem como prova de handshake.

Referências:
https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
https://docs.opencode.ai/docs/pt-br/cli/


## Entrega extra: smoke de protocolo MCP stdio (implementada e validada)
- Script: reviews/codex/mcp_stdio_probe.py --server <nome> [--timeout 25]
- Usa exclusivamente um servidor local configurado (tipo local) e explicitamente
  nomeado; inicia um subprocesso isolado; faz JSON-RPC initialize,
  notifications/initialized e tools/list (incluindo paginação); encerra somente
  o grupo de processos criado por esse smoke. Não há tools/call nem comandos
  executados via ferramentas retornadas. Não imprime comandos, URLs ou segredos.
- Teste real: python3 reviews/codex/mcp_stdio_probe.py --server mitr3-nexus
  => PASS, protocol_version=2025-11-25, tools_count=10.
- Testes offline com servidor fictício: handshake OK, paginação, erro RPC,
  stdout inválido, configuração remota recusada, cwd inválido e timeout.
- Pacote total de regressão em reviews/codex/tests: 16 testes PASS.
- Uso seguro: Codex pode adaptar este probe ao mitr3-mcp-check.sh, mas deve
  testar os outros MCPs primeiro em sessão isolada e confirmar custo/memória.
- O endpoint HTTP remoto requer verificação por Streamable HTTP e autenticação,
  que NÃO foi incluída neste probe stdio. Não tratar GET como handshake.
