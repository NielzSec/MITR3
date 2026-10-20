# MITR3 — Radar de Pesquisa e Evolução, rodada 01

**Data:** 2026-10-19 (America/Sao_Paulo)
**Responsável:** GPT-6, pesquisa externa via Remote Desktop Commander
**Estado:** pesquisa + proposta; **nenhuma alteração de agentes, MCPs ou exploração realizada**
**Destinatários:** OpenCode (maestro), Codex (QA), Hermes/Gemma4 (research/MegaBrain), VANTA/Antigravity (RE), DeepSeek (web/API), Robin (quality).

## Contexto validado no host (somente leitura)

- Workspace: `~/MITR3`, pipeline Maestri, contratos humanos de escopo no Nexus.
- Stack registrado em `README.md`, `docs/TOOLCHAIN.md` e `docs/ECC-EVAL.md`: MegaBrain MCP, Nexus/REA, CodeQL 2.27.2, Semgrep, Trivy, OSV-Scanner, Ghidra, scanners e arsenal já presentes.
- `bin/mitr3-codeql.sh`, `bin/mitr3-scan.sh`, `bin/mitr3-health.sh`, `bin/mitr3-mcp-check.sh` já existem; **não duplicar** instalações ou scripts.
- A avaliação de ECC v2.2.3 já recusou hooks globais/instaladores e propôs apenas importação declarativa de personas e pilotos isolados. Respeitar esta decisão.
- Handoff prévio `CHATGPT-TEAM-HANDOFF-20261019.md` alertou para credencial em quadro Maestri. O último `state/shared-secret-check-latest.json` que examinei marcou status `ok` e zero achados, às 14:00 BRT, **sem provar rotação de credencial nem ausência posterior de vazamentos**. Revalidar sem imprimir valores.
- Não reabrir Ra/Osiris, encerrado em 2026-10-17 conforme `CHATGPT-COORDINATION.md`; operar apenas contratos autorizados.
- A estação teve episódios recentes de OOM no Brave/Hyprland; **não introduzir serviços pesados permanentes no host sem orçamento RAM/CPU**.

## Hipóteses mais valiosas (priorizadas)

| Ordem | Trilha | Evolução proposta | Critério de aceite | Risco/custo |
|---|---|---|---|---|
| P0 | Qualidade de handoffs | Contrato único JSON para missão, escopo, artefatos, proveniência, unknowns, SHA256 e decisão humana; revisão cruzada por seat | 100% das entregas piloto incluem referência, evidência, erro e estado; nenhuma autorização inferida | Baixo, processo |
| P0 | Segurança de agentes | Suite de regressão para prompt injection indireta via resultados MCP, arquivos externos, repositórios e RAG, em fixtures locais. Cruzar OWASP Agentic Top 10 2026 com MITRE ATLAS | Demonstrar rejeição de pedidos sem escopo, exfiltração e tool escalation nos testes | Médio, isolar |
| P0 | Segredos | Rever o incidente de exposição no Maestri, validar rotação da credencial por operador, fortalecer checker sem coletar valores e checar retenção | Check OK e evidência humana de rotação, nunca chave no relatório | Alto se pendente |
| P1 | Telemetria | Instrumentação leve com JSONL local e IDs de trace/span no ciclo pedido > seat > ferramenta > resultado, usando vocabulário OTel GenAI; não implantar Langfuse no host de imediato | Medir latência p50/p95, erro MCP, retrabalho, tokens/custo (quando disponíveis), tempo de aprovação | Baixo sem backend |
| P1 | MegaBrain | Test set fixo de consultas cyber/IA, medindo recall@k, precisão de citações, idade de fonte, deduplicação de claims e cobertura de referências | Baseline reproduzível + melhoria em amostras verificadas por humano | Baixo-médio |
| P1 | QA de software | Consolidar alertas CodeQL/Semgrep/Trivy/OSV em findings normalizados com fingerprints, vínculo de versão e avaliação FP/TP | Nenhum CVE atribuído por resolução de versão mínima sem comprovação runtime | Baixo |
| P1 | Eficiência | Benchmark roteamento tarefa > modelo/seat + JEV shadow vs controle, limite de paralelismo por RAM, cache de contexto e orçamento tokens | Medir custo/êxito/tempo por tipo de tarefa sem degradação de qualidade | Médio |
| P2 | Agent evals | Piloto Promptfoo apenas contra agente de teste isolado; se necessário, comparar garak para verificação de vulnerabilidades de modelo | Suite fixa, cobertura agentic e taxa de falha, sem credenciais reais | Médio |
| P2 | Blue/purple lab | Catalogar técnicas MITRE ATT&CK/ATLAS e testes Atomic Red Team para laboratório com permissão explícita, rollback e isolamento | Simulações com evidência defensiva, ambientes descartáveis e consentimento documentado | Médio/alto |
| P2 | Interface | Painel leve estático gerado dos JSONs existentes antes de dashboard com novos servidores | Estado por seat, health MCP, backlog de QA e evidências sem dados sensíveis | Baixo |

## Fontes confirmadas nesta rodada

1. OWASP Agentic Top 10 2026 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
2. OWASP GenAI lançamento 2026 e Agent Control Standard — https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/
3. MITRE ATLAS threat matrix — https://atlas.mitre.org/
4. OpenTelemetry convenções de spans de agente GenAI (em desenvolvimento; não tratar como padrão estável final) — https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md
5. Promptfoo, segurança de agentes e CI — https://www.promptfoo.dev/docs/red-team/agents/ ; https://www.promptfoo.dev/docs/red-team/quickstart/
6. NVIDIA Garak — https://github.com/NVIDIA/garak
7. Langfuse: tracing/eval/prompt, self hosting Docker Compose mais pesado; não instalar como padrão agora — https://langfuse.com/self-hosting/deployment/docker-compose
8. OSV-Scanner V2; checar versão instalada exata antes de classificar vulnerabilidade — https://github.com/google/osv-scanner/blob/main/docs/usage.md
9. Atomic Red Team, exigir permissão e test host com cleanup — https://www.atomicredteam.io/docs/atomic-red-team
10. CodeQL security-extended aumenta cobertura e também FP, exige triagem — https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-query-suites

## Proposta de fases

**Semana 1 (segurança/qualidade):** validar segredos e aprovações de escopo; baseline de 10 handoffs; definir rubric 5 eixos (acurácia, completude, evidência, segurança, eficiência); escolher 10 fixtures de prompt injection apenas com dados sintéticos.

**Semana 2 (observabilidade/MegaBrain):** protótipo JSONL sem prompts nem segredos em logs; benchmarking de pesquisa RAG com gold set de 30 perguntas; QA de alertas já emitidos com versão real de runtime.

**Semanas 3–4 (validação):** Promptfoo em sandbox; comparar roteamento de modelos no mesmo dataset; gates de CI para contratos + fingerprints de findings; painel estático local somente se métricas sustentarem benefício.

## Gate MITR3

- Requisitos obrigatórios: contrato humano válido, escopo delimitado, evidência/citação e checksum, custos limitados, testes reversíveis, checagem de segredo, diff mínimo, QA independente.
- Pesquisa pode ser contínua. **Nenhuma nova ferramenta, modelo, hook, MCP, serviço em produção ou emulação ofensiva entra automaticamente**; OpenCode revisa, Codex confirma QA e operador aprova mutações relevantes.
- Não criar trabalho de fundo neste host apenas porque o documento existe. O radar de pesquisa agendado no ChatGPT é separado de execução local.

## Encaminhamento para OpenCode

1. Avaliar P0/P1 no quadro Maestri sem sobrepor tarefas atuais.
2. Priorizar o incidente de credencial se a rotação ainda não estiver atestada.
3. Aproveitar ECC Phase 1 declarativo já revisado, não instalar hooks globais.
4. Atribuir uma implementação piloto somente após aceite do escopo; preservar versões e state existentes.
