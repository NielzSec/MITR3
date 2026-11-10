# MITR3 Hackbots — Escolha de executores e custo por API
Status: desenho de piloto em 2026-10-23. Sem chamadas a modelos, sem mudança de segredos, sem integração de agentes ativada.

## Diferença essencial
- **OpenCode e Hermes:** ambos podem chamar provedores externos por API e também outros modos de autenticação. Para o MITR3, tratá-los inicialmente como executores que consomem o orçamento de API.
- **Codex CLI e Antigravity CLI:** recursos complementares no Orca; priorizar logins e limites das próprias CLIs já disponíveis. Não pressupor que assinaturas implicam API ilimitada.
- **Orca:** sessões, worktrees e encaminhamento; a inferência continua sujeita à conta do executor.

## Escolha provisória
OpenCode continua maestro lógico, mas **não** deve delegar a outro modelo por reflexo:
- OpenCode: planejar, selecionar somente UMA micro-skill e eventualmente executar worker web offline com modelo barato.
- Hermes: pesquisa/curadoria RAG via MegaBrain, acionado sob demanda. Não duplicar o mesmo trabalho do OpenCode.
- Codex CLI: revisor independente de código/evidência e validação de testes; resultado é proposta, nunca substitui revisão humana.
- Antigravity CLI: especialista REA/reverse, suporte a análise de navegador, somente tarefas permitidas e pontuais.

## Descoberta feita no host (valores de chaves **nunca** exibidos)
- OpenCode v2.1.2: modelos cadastrados na Dahl — DeepSeek V4 Flash, GLM 5.3 Flash, MiniMax M2.7. O arquivo de configuração não define modelos explícitos para agentes especializados.
- Hermes: provider dahl2, modelo padrão DeepSeek V4 Flash.
- Codex CLI 0.163.0; Antigravity CLI 1.4.6.
- Não foram consultados saldos de API ou preços específicos: nenhuma conclusão sobre qual é mais barato no uso real.

## Piloto econômico
1. Uma missão **offline** com um arquivo JavaScript sintético e contrato local; não requer inferência externa.
2. Quando autorizado: um único worker OpenCode em modo restrito e apenas um revisor Codex CLI; manter Hermes e Antigravity inativos.
3. Depois testar mesma missão com Hermes, escolhendo modelo equivalente, entrada, limite e critérios idênticos para comparação justa.
4. Registrar custo real por tokens / por missão, latência, memória, cobertura, falsos positivos e progresso.
5. Fixar teto por dia/missão no provedor e limitar simultaneidade a dois workers; parada por custo excedido deve ser imposta no gateway/provedor, não por instruções do modelo.

## Segurança
- Escopo e autorização humana: `../../docs/SCOPE.md`, com políticas próprias do Bug Bounty.
- Contratos de tarefas: `../contracts/`; nunca confundir PASS de esquema com achado confirmado.
- Filtrar segredos e dados de terceiros antes de invocar APIs externas.
- Não configurar Ruflo agora; não ativar múltiplos orquestradores nem serviços persistentes.

## Referências
- https://opencode.ai/docs/agents
- https://opencode.ai/docs/providers
- https://hermes-agent.nousresearch.com/docs/user-guide/features/delegation
- https://hermes-agent.nousresearch.com/docs/integrations/providers
- https://www.themaestri.app/pt-br/docs/terminals
