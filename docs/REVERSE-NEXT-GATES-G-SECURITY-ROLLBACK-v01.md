# MITR3 — REVERSE NEXT — Esboço dos Gates G-SECURITY e G-ROLLBACK

Versão: 0.1 — Proposta técnica (gerada via Codex Web / ChatGPT, 2026-10-21)
Estado: Aguardando validação contra o masterplan — `docs/MITR3-REVERSE-NEXT-MASTERPLAN-20261021.md`
Regra central: Fail Closed — nenhuma operação de risco avança sem aprovação dos gates.

## 1. Arquitetura de controle

Fluxo proposto:

Leitura integral do masterplan → Inventário do ambiente → G-SECURITY → G-ROLLBACK → Execução controlada → Validação pós-execução → Aprovação final

Os gates são obrigatórios antes de qualquer operação com efeitos persistentes. Falhas críticas interrompem a etapa afetada.

Nenhum agente poderá ignorar, desabilitar ou aprovar unilateralmente os próprios controles.

## 2. G-SECURITY — Segurança operacional

Objetivo: Garantir que a execução dos agentes, ferramentas MCP, scripts e componentes de engenharia reversa permaneça autorizada, rastreável e isolada.

| ID | Verificação obrigatória | Critério |
|----|------------------------|----------|
| SEC-01 | Integridade do ambiente | Detectar alterações preexistentes e processos ativos |
| SEC-02 | Procedência dos repositórios | Confirmar origem autorizada, revisão e hashes |
| SEC-03 | Proteção de credenciais | Impedir exposição de tokens, chaves e variáveis sensíveis |
| SEC-04 | Isolamento operacional | Restringir execução de binários e amostras não confiáveis |
| SEC-05 | Segurança de agentes e MCP | Aplicar privilégios mínimos e lista de ferramentas autorizadas |
| SEC-06 | Controle de dependências | Bloquear instalações, hooks e bootstraps não aprovados |
| SEC-07 | Auditoria | Registrar operações, alterações e resultados sem expor segredos |
| SEC-08 | Autorização e escopo | Confirmar que os alvos e métodos de análise estão autorizados |

Condições de bloqueio imediato:
- Comando destrutivo, tentativa de sobrescrita não autorizada ou alteração fora do escopo.
- Execução de código não confiável diretamente no host.
- Exposição de segredos ou solicitação injustificada de privilégios elevados.
- Modificação inesperada do REA MCP, MegaBrain ou configurações existentes.
- Tentativa de executar hooks, inicializar submódulos ou realizar bootstrap automaticamente.
- Evidência insuficiente para determinar a segurança de uma ação crítica.

Regras especiais: Ghidra e REA MCP devem tratar artefatos analisados como não confiáveis. Laboratórios Native, Android e Firmware começam em modo de inspeção estática. Execuções dinâmicas, instalação em dispositivos e gravações de firmware exigem autorização específica e isolamento adequado.

Saída: PASS, BLOCK ou REVIEW_REQUIRED. O gate somente concede PASS quando todas as verificações obrigatórias estiverem satisfeitas.

## 3. G-ROLLBACK — Recuperação e preservação

Objetivo: Garantir que toda alteração autorizada tenha um procedimento de reversão verificável, sem destruir trabalho preexistente.

| ID | Verificação obrigatória | Critério |
|----|------------------------|----------|
| RB-01 | Baseline | Registrar estado inicial do Git, arquivos, processos e serviços relevantes |
| RB-02 | Snapshot | Criar cópias verificáveis dos elementos sujeitos a alteração |
| RB-03 | Manifesto de mudanças | Identificar arquivos, configurações e recursos que a operação poderá modificar |
| RB-04 | Plano de reversão | Definir restauração específica para cada mudança prevista |
| RB-05 | Ensaio de restauração | Testar o procedimento em ambiente isolado |
| RB-06 | Integridade | Verificar hashes, permissões e conteúdo após restauração |
| RB-07 | Proteção do trabalho existente | Impedir sobrescrita de alterações anteriores ou concorrentes |
| RB-08 | Recuperação operacional | Confirmar retorno dos componentes afetados ao estado esperado |

Operações expressamente proibidas no rollback automático:
- `git reset --hard`
- `git clean -fd` ou variantes destrutivas
- `git stash` automático para esconder alterações
- Exclusão recursiva indiscriminada
- Sobrescrita de configurações preexistentes
- Reinicialização indiscriminada de serviços ou agentes
- Descarte de dados persistentes do MegaBrain/JEV

O rollback deve atuar somente sobre recursos cuja alteração possa ser atribuída à execução atual. Se um arquivo também tiver sido modificado externamente, a restauração automática desse arquivo será bloqueada para reconciliação.

Disparadores de rollback: falha de validação, alteração inesperada, corrupção de artefatos, quebra de integração, violação de segurança ou divergência de integridade.

Ao detectar um disparador, o OpenCode suspende novas mutações. O Codex executa apenas as ações de reversão previamente autorizadas e verificadas. Se a restauração segura não for possível, o ambiente permanece preservado e o problema é escalado para decisão humana.

Saída: READY, BLOCK ou MANUAL_RECOVERY_REQUIRED.

## 4. Responsabilidades dos agentes

| Agente | Responsabilidade |
|--------|------------------|
| OpenCode | Orquestrar gates, validar escopo, autorizar transições e interromper execuções |
| Codex | Implementar verificações, snapshots, testes e procedimentos de restauração |
| DeepSeek | Revisar riscos, superfícies de ataque e vulnerabilidades |
| Antigravity/VANTA RE | Validar os limites operacionais dos laboratórios de engenharia reversa |
| Hermes/Gemma4 | Documentar conhecimento, evidências e lições aprendidas |

Nenhum parecer automatizado substitui a autorização humana exigida para operações de alto risco.

## 5. Contrato mínimo de evidências

Cada execução dos gates deverá produzir um conjunto auditável contendo:
- Identificador da execução e revisão do masterplan.
- Estado inicial e hashes dos artefatos relevantes.
- Resultado de cada verificação de segurança.
- Manifesto de arquivos e recursos autorizados.
- Localização e integridade dos snapshots.
- Resultado do ensaio de rollback.
- Pareceres dos agentes revisores.
- Decisão final e justificativa.

Diretório sugerido para os relatórios: `~/MITR3/docs/evidence/reverse-next/<run-id>/`

As evidências não devem conter credenciais em texto puro. Snapshots sensíveis exigem armazenamento protegido e controle de acesso.

## 6. Critérios de aceitação

- G-SECURITY aprovado: nenhuma alteração fora do escopo, execução não autorizada, exposição de segredos ou violação das políticas de isolamento.
- G-ROLLBACK aprovado: baseline íntegro, snapshots verificáveis, restauração ensaiada com sucesso e preservação demonstrável das alterações preexistentes.
- Liberação conjunta: a etapa seguinte somente poderá iniciar com G-SECURITY = PASS e G-ROLLBACK = READY.
- Após a execução, os dois gates serão novamente avaliados quanto a mudanças inesperadas, integridade e recuperabilidade.

## 7. Casos mínimos de teste

1. Detectar repositório com alterações não commitadas e preservar seu conteúdo.
2. Bloquear uma tentativa de alteração fora dos diretórios autorizados.
3. Rejeitar a execução automática de hooks ou bootstrap de dependências.
4. Detectar um segredo em logs sem copiá-lo para o relatório.
5. Simular falha de integração do REA MCP e validar a recuperação.
6. Simular falha em uma integração shadow do MegaBrain/JEV sem afetar dados anteriores.
7. Verificar que o rollback não sobrescreve arquivos alterados por outros processos.
8. Bloquear a próxima fase quando uma evidência obrigatória estiver ausente.

## 8. Condição para implementação

Este esboço deverá ser confrontado com o masterplan completo. Somente depois da aprovação do desenho o Codex poderá implementar os validadores e scripts.

A validação inicial deverá operar em modo read-only/dry-run, sem instalação de dependências, modificação de configurações ou reinicialização de serviços.

Princípio final: preservar primeiro, verificar antes de executar e restaurar somente aquilo que a execução comprovadamente modificou.
