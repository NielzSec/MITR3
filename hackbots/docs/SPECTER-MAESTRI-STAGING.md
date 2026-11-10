# MITR3 — SPECTER / Plano de recrutamento no Maestri (staged)

Estado: **CANDIDATE_ONLY / MODEL_CATALOG_SEEN / NO_RUNTIME / F01_OPEN**.

## Decisão de runtime

- **Morfeus:** OpenCode atual, coordenador no Maestri. Sem mudanças.
- **SPECTER:** segundo terminal **OpenCode** (especialista Web offline);
  usar modelo `opencode/glm-5.3-flash-free` **após** aprovar F01.
- Fallback experimental: `opencode/deepseek-v4.1-flash-free`.
- Ambos apareceram no catálogo `opencode models --standalone`
  em 24/10/2026; disponibilidade e condições podem mudar.
- **Sonnet 5.5 web gratuito:** útil para revisão manual, mas não é
  assinatura Anthropic API ou CLI; não escolher como runtime do SPECTER.
- **Dahl:** modelos `deepseek-ai/DeepSeek-V4-Flash-0731`,
  `MiniMaxAI/MiniMax-M2.7` e `zai-org/GLM-5.3-Flash`
  configurados no OpenCode. Fallback apenas quando uma chave legítima
  e quota aplicável estiverem autorizadas; não rotacionar IP/contas/chaves
  para contornar cotas/limites de avaliação gratuitos.
- **Antigravity/Gemini:** apoio opcional de engenharia reversa, ou revisão
  cruzada do trabalho do Codex, sem compartilhar credenciais privadas.
- **Codex:** engenharia/QA; não certifica independentemente mudanças que fez.

## O que já existe no projeto

- 270 testes B1 (reportados pelo Codex), benchmark Web HTTP sintético
  de 15 casos em `hackbots/examples/web/fixtures/` e
  `hackbots/tools/web_benchmark.py`. Aceite independente **PENDING**.
- Skills disponíveis: Scope Gate, Evidence Review, JS Inventory,
  Mission Intake, Context Pack, Dispatch Contract, Closeout Gate.
- Skill `mitr3-hb-specter` final e método E/M ainda **NÃO VALIDADOS**.
  Skills genéricas anteriores NÃO equivalem à certificação do novo agente.
- F01 ainda **OPEN**, `mitr3-agent`/`mitr3-custodian` inexistentes
  e serviço query não implantado, de acordo com última verificação.
- Perfil V2 proposto: `hackbots/agent-candidates/specter.md`.
  Mantido **fora** dos diretórios auto-descobertos pelo OpenCode.
  Bloqueia todas as ferramentas por padrão e permite apenas leitura de
  arquivos de laboratório; sem shell, rede, escrita ou subagentes.

## Critérios de go/no-go

**G0:** terceiro revisor verifica B1 (15 oráculos, pin externo, diffs)
e F01 corrigido; achados resolvidos ou aceitos pelo operador.

**G1:** usuário autoriza janela de implantação de contas dedicadas;
F01 é instalado em revisão controlada e submetido a testes reais de
negativas de acesso, grupos, socket, import, quotas, rollback. Sem
migrar a conta principal `nielz`.

**G2:** executar OpenCode SPECTER em ambiente **com UID restrito e
isolado**, sem herdar wheel/docker ou credenciais de Morfeus. Configuração
de prompt e permissions não é isolamento suficiente.

**G3:** pin e autorizar orçamento por missão; exemplo inicial para
comparação (não habilitado): 3 casos sintéticos, 1 tentativa/caso,
máximo 6k tokens input/1k output e 30 s/chamada, sem retries.
Se API/provedor não impor o teto, medição e gate de parada externo.

**G4:** perfil candidatado, skills verificadas, modelo escolhido e
revisão de output, então link Morfeus → SPECTER no Maestri. Nada disso
concede acesso ao Docker ou a laboratórios públicos.

## Procedimento *futuro* de adição no Maestri

1. Instalar **cópia revisada** do perfil em
   `.opencode/agents/specter.md` dentro de workspace autorizado (não
   usar o workspace de origem writeable pelo agente com UID nielz).
2. Confirmar OpenCode V2 e a regra de permissions por ferramenta usando
   testes negativos no ambiente isolado. Ver
   https://dev.opencode.ai/v2/docs/agents/ e
   https://dev.opencode.ai/v2/docs/permissions/.
3. No Maestri, manter Morfeus como Maestro. Adicionar um terminal
   OpenCode com nome `SPECTER — Web Evidence`, role para revisão HTTP
   offline, agente selecionado `specter` e workspace/cwd limitado.
4. Conectar Morfeus e SPECTER por nota de missão com escopo e hash.
   Não usar delegação irrestrita ou auto-recrutamento antes do gate.
5. Testar somente fixture sintética W01/W02/W09 e uma negativa
   com acesso negado; aferir completude, falsos positivos e custo.
6. Revisar outputs com avaliador determinístico + outro autor humano
   ou modelo, mantendo aprovação humana separada.

## Próximo passo autorizado já

Permite-se **revisar offline** a proposta de perfil, B1 e F01. Não
instalar contas, serviços, CLI, terminal Maestri, invocar modelo ou
alterar secrets a partir deste documento. O operador deverá aprovar
separadamente a janela de mudança de privilégios.

## Status do trabalho staged (24/10)

Modelo selecionado por consulta de catálogo; perfil candidato criado,
ainda sem carga na configuração ativa. O Maestri permanece somente com
Morfeus. O Sonnet web e o Dahl não foram acionados.

**NÃO CONFUNDIR:** presença de perfil e benchmark =/= Hackerbot ativo.
