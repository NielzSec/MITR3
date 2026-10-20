# Handoff — Ampliação do RAG público e inteligência MITR3

Data 2026-10-19. Destinatarios: OpenCode, Codex, Hermes/Gemma4, VANTA e JEV.
Origem: GPT-6 via Desktop Commander; documento local, não notificação Maestri em tempo real.

## Entregas implementadas

- CISA KEV JSON e OWASP ASVS 5.0.0 estruturado e versionado, com hashes e índice SQLite FTS5 local.
- Base de 26 fichas publicas curadas com resumo autoral, autoria, links e status de validação.
- Indexador bin/mitr3-rag-intel.py, atualizador bin/mitr3-rag-intel-refresh.py e fila bin/mitr3-rag-curate.py.
- Sync remoto do catálogo curado concluído: 26 recebidos; 16 legíveis, 10 redigidos pelo filtro de segurança. QA em state/public-rag-mcp-qa.json. **Nao contornar as redacoes.**
- 2.034 arestas explicitas dos feeds e pesquisa por identificador CVE, ASVS, tags ou texto.
- Timer semanal systemd --user para dois feeds oficiais, sem varredura de alvos.
- Testes de regressao do pipeline, recuperação e seguranca. Fonte no guia docs/MITR3-INTELLIGENCE-RAG.md.

## Tarefas por seat

- OpenCode: avaliar esta entrega, coordenar evolucao e manter politica de escopo assinada.
- Codex: revisar metricas, QA do filtro de dados externos e evitar duplicatas; medir citacoes vs fonte primaria.
- Hermes: buscar novos casos publicos com autor e URL; submeter JSON na fila, **sem autoaprovar**.
- VANTA: revisar analises de CTFs RE/forensics/pwn e evidencias em fontes originais.
- JEV: arbitrar confianca e classificar fontes como reportadas, observadas ou reproduzidas; nao inventar relacoes.
- Todos: evitar executar PoCs, scripts ou commands encontrados em fontes publicas.

## Gates e proximos passos

1. Revisar 10 registros do MegaBrain remoto com safe_content redigido.
2. Validar fonte individual de cada novo bug bounty antes de promover (somente disclosed).
3. Criar benchmark de qualidade de respostas com verificacao humana de citacao,
   e só entao considerar reranking vetorial se demonstrar melhora efetiva.
4. Documentar o custo real de consulta e latencia local/remota.
5. Preservar o ambiente Arch; nao executar atualizações massivas durante tarefas da squad.

