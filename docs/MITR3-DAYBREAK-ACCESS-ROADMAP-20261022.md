# MITR3 — Plano de ativação do Daybreak | 2026-10-22

**Status real medido no Arch:** Codex CLI 0.163.0, ChatGPT login ativo; `daybreak = true` já está no nível raiz de `~/.codex/config.toml`. O modo `cli_daybreak` está disponível no binário. **Consulta sem inferência** ao app-server `model/list`: sete modelos, todos com `standard`, zero anúncios `daybreakBlue` ou `daybreakRed`. Isso NÃO confirma provisionamento Daybreak para a conta ou workspace. Não contornar controles de elegibilidade.

## O que falta — pessoa física

1. Usar o MESMO login ChatGPT empregado no Codex e acessar https://chatgpt.com/cyber. Selecionar **Configurar o Daybreak** e verificar elegibilidade do plano.
2. Finalizar **Segurança avançada da conta**, incluindo **pelo menos uma chave física FIDO2**, mais um segundo método de autenticação seguro. Chave de acesso somente por software não atende ao requisito de chave FIDO2 física. Guardar as chaves de recuperação offline: essa mudança pode desconectar todas as sessões e restringe métodos de recuperação.
3. Completar verificação de identidade, seleção das chaves para Daybreak e submissão para aprovação. Requisitos atendidos não garantem aprovação. Daybreak Blue é a modalidade individual inicial; Red exige revisão separada.
4. Após aprovação e propagação, iniciar nova sessão Codex `codex`, ativar/verificar `/daybreak` (comando alterna entre ligado/desligado). O padrão `daybreak=true` já está configurado. Para headless, `codex exec -c daybreak=true "<tarefa de laboratório autorizada>"`.
5. Confirmar o modelo aprovado/selecionado no mesmo login e usar uma atividade própria de código do MITR3 para o teste de comportamento; evitar pedidos a terceiros, pagamentos e scans reais como forma de provar Daybreak. `model/list` pode ser indício de liberação, mas só solicitação real com o modelo e tier aprovados confirma efetividade.

## O que falta — organização/equipe

Formulário oficial: https://openai.com/form/enterprise-trusted-access-for-cyber/

- Organização/aprovador devem atender ao processo de verificação da OpenAI. Não inventar dados empresariais. Para ChatGPT/Codex com login ChatGPT em espaço de trabalho **aprovado**, o administrador Enterprise habilita os tiers elegíveis em Admin Console > Models, por funções/grupos. Daybreak Blue não inclui Red.
- Para uso API, o **owner da organização da API** precisa habilitar o tier aprovado em **projeto não padrão**: Project Settings > General > Daybreak model access. Chaves de API de outros provedores como Dahl/Ollama/DeepSeek/Claude não herdam isso.
- Membros internos autorizados e fluxos internos poderão utilizar acessos aprovados; não repassar sessão/tokens para usuários externos, serviços de terceiros ou aplicativos públicos. Não transformar autorização de uma conta em proxy compartilhado.
- Para projetos API com acesso aprovado, usar Responses API e o parâmetro `access_programs.cyber` quando previsto no modelo/tier. Para app-server Codex, ler `availableAccessPrograms.cyber` em `model/list` e usar `cyberAccessProgram=daybreakBlue|daybreakRed` em `turn/start` somente quando o acesso estiver presente para modelo/conta. O `experimentalApi` da inicialização é necessário neste método.
- Cabe ao VANTA distribuir o estado de provisionamento/owner e manter gates de escopo. Daybreak afeta tratamento de solicitações de cyber em produtos OpenAI; não é extensão para REA, MegaBrain, navegador, Ollama, Hermes ou ferramentas de terceiros.

## Comando de autoverificação sem custo de inferência

```bash
python3 ~/MITR3/bin/mitr3-daybreak-status.py
```

Saída de 22/10/2026: `MODELOS_VISIVEIS=7`, `DAYBREAK_BLUE=0`, `DAYBREAK_RED=0`, `ACESSO_PADRAO=7`. Não copiar tokens ou arquivos `auth.json`; esse verificador NÃO os abre e só consulta o catálogo local do Codex por RPC.

## Papel de cada agente durante a implantação

- **VANTA (maestro):** coletar confirmação de aprovação por conta/workspace e manter o inventário `STANDARD|BLUE|RED` sem segredos; selecionar tarefas internas. Não declarar Daybreak para todos sem isso.
- **Codex/Astra:** versão CLI já compatível. Confirmar tier no catalog/selector; rodar somente tarefas permitidas no mesmo workspace/projeto aprovado.
- **OpenCode:** NÃO ganha acesso Daybreak por possuir ferramenta Codex, SSH ou MCP; integração deve usar via OpenAI API/projeto aprovado, se existente, sem proxy de credenciais.
- **Hermes/Gemma/DeepSeek:** modelos de outros fornecedores não recebem Daybreak. Podem continuar auxiliando a pesquisa e usar o MegaBrain, com JEV/GPT QA e Ponytail.
- **GPT QA:** comparar erros/custos e qualidade em tarefas internas autorizadas, quando acesso estiver funcional; nunca autorizar escopo externo automaticamente.
- **JEV:** continua shadow, audita somente decisões e evidências redigidas, independente do tier Daybreak.

## Resultados esperados

Daybreak NÃO garante aumento de velocidade de 100%, redução de preços, ou remoção de todos os bloqueios. É um programa de acesso confiável para atividades de cyber autorizadas e redução de recusas em modelos/tiers específicos. Mesmo aprovado, continuam as políticas de uso, regras dos programas de bug bounty, escopo, privacidade e autorização.

Fontes oficiais:
- https://help.openai.com/en/articles/20001607-using-daybreak-in-codex-cli
- https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview
- https://help.openai.com/en/articles/20001531-openai-daybreak-set-up-access-for-your-team
- https://help.openai.com/en/articles/20001259-openai-daybreak-common-issues-and-troubleshooting
