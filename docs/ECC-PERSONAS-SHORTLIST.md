# ECC Fase 1 — Curadoria Declarativa de Personas e Skills (MITR3)

- **Fonte:** Catálogo ECC v2.2.3 (`/tmp/opencode/ecc-eval`)
- **Status:** Curadoria Declarativa (Somente leitura / Zero instalação / Sem hooks)
- **Data:** 2026-10-19
- **Objetivo:** Mapear componentes de alto valor do ECC para os seats operacionais do MITR3 (Robin, Codex, VANTA, Gemma4), adaptando conceitos de governança aos nossos padrões (Boards Maestri, Selos de Qualidade, Evidências Criptográficas e SARIF).

---

## 1. Matriz de Mapeamento: Seat → ECC → MITR3

| Seat MITR3 | Origem ECC (Persona / Skill) | Adaptação Proposta (Termos MITR3) | Por Que Vale |
| :--- | :--- | :--- | :--- |
| **Robin**<br>*(Deep / Strategic)* | • `agents/agent-evaluator.md`<br>• `agents/planner.md`<br>• `skills/verification-loop/`<br>• `skills/eval-harness/` | • Conversão da rubrica de 5 eixos (Accuracy, Completeness, Clarity, Actionability, Conciseness) em critério formal para concessão do **Selo de Validação**.<br>• Vinculação dos outputs aos cards do **Board Maestri** com checagem obrigatória de evidências antes de fechar tarefas.<br>• Exclusão total de comandos mutáveis no bash de verificação. | Elimina aprovações vagas e subjetivas em tarefas complexas. Força o modelo a citar evidências rastreáveis (hashes, saídas de comandos, logs) para cada critério avaliado. |
| **Codex**<br>*(Build / QA)* | • `agents/tdd-guide.md`<br>• `agents/build-error-resolver.md`<br>• `agents/pr-test-analyzer.md`<br>• `skills/tdd-workflow/`<br>• `skills/e2e-testing/` | • Enforçamento do padrão TDD: teste de regressão antes do patch, diff cirúrgico mínimo.<br>• Geração de relatório com **Selo de QA** formal anexado à documentação de execução (`RUNBOOK.md`, `CODEX-ARSENAL-QA`).<br>• Bloqueio explícito de flags de evasão (`--no-verify`, skips não auditados). | Garante reprodutibilidade absoluta no arsenal de ferramentas MITR3, prevenindo que fixes rápidos quebrem contratos existentes no lab. |
| **VANTA**<br>*(RE / Low-Level)* | • `agents/security-reviewer.md`<br>• `agents/silent-failure-hunter.md`<br>• `agents/code-explorer.md`<br>• `skills/agent-security-hardening/`<br>• `skills/change-impact/` | • Mapeamento direto para regras **CodeQL/SARIF**, CWEs e boundaries nativos auditados pelo **REA MCP**.<br>• O `silent-failure-hunter` é adaptado para auditar swallow de erros em rotinas de descompactação, parsing binário e chamadas de sistema.<br>• Tracing de execução correlacionado com call graphs do REA e hash SHA-256 do binário alvo. | Identifica falhas críticas em código de baixo nível e PoCs que falham silenciosamente ou mascaram exceções através de fallbacks frágeis. |
| **Gemma4**<br>*(Research / MegaBrain)* | • `agents/docs-lookup.md`<br>• `agents/rag-pipeline-reviewer.md`<br>• `agents/spec-miner.md`<br>• `skills/api-design/`<br>• `skills/strategic-compact/` | • Substituição do Context7 genérico pelo ecossistema **MegaBrain MCP** (`knowledge_search`, `rag_context`, `evidence_read`).<br>• Mineração de especificações (spec-miner) em bases legadas e fontes de inteligência/OSINT com persistência de links e metadados no repositório de evidências.<br>• Avaliação de relevância de recuperação (RAGAS) sem vazamento de escopo. | Transforma pesquisas dispersas em ingestão estruturada de conhecimento com evidência e citação determinística dentro do ecossistema MegaBrain. |

---

## 2. Detalhamento por Seat

### 2.1 Robin (Deep / Strategic / Quality Gate)
- **Persona Base:** `agent-evaluator`
- **Adaptação:** O prompt original do ECC possui uma rubrica rígida onde notas < 5 exigem citação de evidência (`+ [Evidence: ...]`, `→ [Improvement: ...]`). No MITR3, adaptamos essa estrutura para gerar o sumário executivo em Markdown nos cards do board. Nenhuma entrega recebe o **Selo de Validação** se houver eixos com nota ≤ 2.
- **Skill Associada:** `verification-loop` — execução iterativa de checagem contra a especificação inicial, encerrando a sessão somente quando a evidência for satisfeita.

### 2.2 Codex (Build & QA Specialist)
- **Persona Base:** `tdd-guide` & `build-error-resolver`
- **Adaptação:** Foco exclusivo em código limpo, cobertura de testes e resolução de quebras de compilação/dependências com diffs atômicos. O prompt proíbe refatorações não solicitadas durante a correção de bugs. O output alimenta o pipeline com evidência de testes passando (`pytest`, `unittest`).
- **Skill Associada:** `tdd-workflow` — ciclo Red-Green-Refactor documentado no log de QA.

### 2.3 VANTA (Reverse Engineering & Security Hardening)
- **Persona Base:** `silent-failure-hunter` & `security-reviewer`
- **Adaptação:** Foco na análise de resistência e resiliência de binários e scripts do arsenal. O `silent-failure-hunter` caça blocos `except: pass`, logs em severidade incorreta e fallbacks cegos. O `security-reviewer` valida se entradas externas estão blindadas contra injeção de comandos, traversal e manipulação de memória, alinhado aos relatórios SARIF gerados pelo CodeQL.
- **Skill Associada:** `agent-security-hardening` — isolamento de permissões e prevenção de injeção indireta em ferramentas e agentes.

### 2.4 Gemma4 (Intelligence & Research Specialist)
- **Persona Base:** `docs-lookup` & `spec-miner`
- **Adaptação:** Ao invés de usar resolvers MCP genéricos externos do ecossistema ECC, Gemma4 consome diretamente as interfaces do **MegaBrain MCP** (`knowledge_search`, `rag_context`) e **Chrome DevTools** para coletar dados primários de pesquisa, minerar especificações de protocolos e manter os playbooks de OSINT/Darkweb atualizados com checagem de integridade.
- **Skill Associada:** `strategic-compact` — sumarização densa de sessões e extração de lições aprendidas para a base de conhecimento permanente.

---

## 3. Configuração Proposta (Patch Ilustrativo `.opencode/opencode.json`)

> [!WARNING]
> **CONFIGURAÇÃO PROPOSTA COMO EXEMPLO — NÃO APLICAR DIRETAMENTE NO AMBIENTE**
> O snippet abaixo demonstra como as 4 personas curadas seriam integradas de forma 100% declarativa, como subagentes isolados, consumindo prompts estáticos em arquivo texto e com ferramentas restritas por seat. Nenhum hook ou runtime dinâmico é acionado.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "agent": {
    "robin-evaluator": {
      "description": "Robin — Avaliador de qualidade e auditor de evidências em 5 eixos para concessão de Selos",
      "mode": "subagent",
      "prompt": "{file:prompts/agents/robin-evaluator.txt}",
      "tools": {
        "read": true,
        "bash": true,
        "write": false,
        "edit": false
      }
    },
    "codex-tdd-builder": {
      "description": "Codex — Especialista em TDD, build e correções de erros com diffs atômicos",
      "mode": "subagent",
      "prompt": "{file:prompts/agents/codex-tdd-builder.txt}",
      "tools": {
        "read": true,
        "bash": true,
        "write": true,
        "edit": true
      }
    },
    "vanta-failure-hunter": {
      "description": "VANTA — Auditor de integridade de baixo nível, detecção de fallbacks silenciosos e boundaries nativos",
      "mode": "subagent",
      "prompt": "{file:prompts/agents/vanta-failure-hunter.txt}",
      "tools": {
        "read": true,
        "bash": true,
        "write": false,
        "edit": false
      }
    },
    "gemma4-intel-researcher": {
      "description": "Gemma4 — Pesquisador de documentação, inteligência e mineração de especificações via MegaBrain",
      "mode": "subagent",
      "prompt": "{file:prompts/agents/gemma4-intel-researcher.txt}",
      "tools": {
        "read": true,
        "bash": true,
        "write": false,
        "edit": false
      }
    }
  },
  "permission": {
    "mcp__megabrain__*": "allow",
    "mcp__rea__*": "allow",
    "bash": "ask"
  }
}
```

---

## 4. Diretrizes de Governança MITR3 para Fase 1

1. **Apenas Texto Puro:** Toda persona ou skill adotada é convertida em arquivo estático Markdown (`.md`) ou texto (`.txt`), livre de dependências Node/Python de runtime do ECC.
2. **Auditoria de Prompt:** Todo prompt importado passa por sanitização prévia para remover referências a comandos `/` ou ferramentas de terceiros inexistentes no MITR3.
3. **Escopo Local de Projeto:** Configurações de teste devem residir exclusivamente dentro do repositório em teste (`.opencode/` local), preservando o ambiente global intacto.
