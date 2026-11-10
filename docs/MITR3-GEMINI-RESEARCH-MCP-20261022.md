# MITR3 — Gemini Research MCP | Implementação e Handoff (2026-10-22)

**Estado: INTEGRAÇÃO MCP INSTALADA / INFERÊNCIA REAL AINDA NÃO VERIFICADA.**
**Maestro:** VANTA / Antigravity · **Build/QA:** GPT-6
**Escopo:** pesquisa em segurança de código, laboratório, engenharia reversa e CTF sob autorização. Sem alteração dos provedores Dahl/Dahl3, MegaBrain ou outros MCPs.

## O que foi implementado

### Código e documentação

- Servidor local Python stdlib: `bin/mitr3-gemini-research-mcp.py` (MCP stdio JSON-RPC, sem instalar bibliotecas).
- Testes offline: `tests/test_gemini_research_mcp.py` — **30/30 PASS**.
- Skill compartilhada: `skills/mitr3-gemini-research/SKILL.md`, linkada nos diretórios de skills dos quatro agentes.

### Quatro clientes integrados

| Cliente | Entrada MCP `gemini-research` | Prova |
|---|---|---|
| OpenCode | `~/.config/opencode/opencode.json`: server local, executável Python fixo | JSON validado, 14 MCPs, provedores Dahl/Dahl3 preservados, backup 0600 |
| Codex | `~/.codex/config.toml`: stdio local | `codex mcp get gemini-research` confirmou enabled |
| Hermes | `~/.hermes/config.yaml`: stdio local | `hermes mcp test gemini-research` confirmou **conectado**, 3 tools; CLI salvou 3/3 |
| Antigravity | `agy mcp add gemini-research ...` | CLI confirmou adição; carga em sessão nova não foi aferida |

**Atenção:** as configurações foram alteradas enquanto vários agentes tinham sessões ativas. Essas sessões não foram encerradas nem reiniciadas. Nova sessão ou reload pode ser necessário; nenhum modelo remoto foi alterado diretamente.

### Ferramentas disponíveis

1. `gemini_research_status`: readiness local e presença de chave, sem chamadas ao Google ou tokens.
2. `gemini_research_models`: catálogo por GET HTTPS, sem tokens de inferência.
3. `gemini_research_generate`: uma inferência por vez, com orçamento, logs de metadados e escolha de perfil.

### Filtro por requisição (não global)

Para `profile="authorized_research"`, o servidor envia **apenas**:

```json
"safetySettings": [
  {
    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
    "threshold": "BLOCK_NONE"
  }
]
```

Para `profile="standard"` não envia `safetySettings` e respeita os defaults. Google permite limiares por requisição via `models.generateContent` no Gemini Developer API. O modelo pode rejeitar a configuração; o gateway NÃO reenvia com filtros mais amplos nem finge sucesso. O Google mantém outras proteções do provedor e pode revisar aplicações com filtros permissivos. Para interações `Interactions API` mais novas, parâmetros diferem; esta integração usa explicitamente a interface `generateContent`.

## Modelos e controle de custos

Modelos na allowlist:
- `gemini-3.5-flash-lite` **padrão econômico** (ID estável documentado pelo Google);
- `gemini-3.6-flash`;
- `gemini-3.8-flash`.

Limites locais por processo: entrada <=6.000 caracteres, saída solicitada <=2.048 tokens/chamada, até 5 chamadas/sessão e 4.096 tokens de saída reservados/sessão. **Há também teto global de 12 reservas de geração por dia UTC**, compartilhado entre processos/agentes mediante audit com lock de arquivo. Falha de auditoria ou cota impede a chamada. O modelo não recebe ferramentas de execução. A execução de inferência só ocorre com `gemini_research_generate` explícito. O MCP não implanta configurações de faturamento no Google Cloud; **quota e custos efetivos dependem do projeto/conta**.

O endpoint HTTPS é fixo: `https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent`, com TLS validado e redirects rejeitados. Cada inferência deve possuir `case_id` formatado `MITR3-...`. O log `~/.local/state/mitr3/gemini-research/audit.jsonl` só contém data, case, modelo, perfil, resultado e metadados de tokens. Nenhum prompt, corpo de resposta ou segredo será registrado pelo gateway.

## Credenciais — ainda não comprovadas

**A presença de nomes de variáveis de ambiente nos processos de agentes não demonstra que existe uma chave válida para este serviço.** Não foram extraídas ou copiadas credenciais de outros processos. O MCP lê somente seu próprio ambiente e, se não houver chave, usa opcionalmente `~/.config/mitr3/gemini-api-key`, exigindo dono igual ao processo e permissão 0600.

Se ainda for necessário fornecer uma chave do Google AI Studio, usar terminal **interativo** como usuário nielz (não colocar no chat):

```bash
install -d -m 0700 ~/.config/mitr3
umask 077
read -r -s -p "Gemini API key (oculta): " MITR3_GEMINI_KEY
printf '\n'
printf '%s' "$MITR3_GEMINI_KEY" > ~/.config/mitr3/gemini-api-key
unset MITR3_GEMINI_KEY
chmod 0600 ~/.config/mitr3/gemini-api-key
```

Checagem sem inferência:

```bash
python3 ~/MITR3/bin/mitr3-gemini-research-mcp.py status
python3 ~/MITR3/bin/mitr3-gemini-research-mcp.py models
```

Primeiro verifica configuração; segundo autentica via GET sem geração. Depois usar `gemini_research_generate` em **tarefa sintética** com 64–128 tokens e case `MITR3-OFFLINE-QA` para validar compatibilidade do `BLOCK_NONE` e faturamento, desde que orçamento/conta estejam em ordem. NÃO enviar testes diretamente a alvos de terceiros.

Se surgir `API_KEY_NOT_CONFIGURED`, instalar chave com permissão 0600. `401/403` indicam credencial/permissão; `400` com perfil autorizado pode ser o modelo rejeitando `BLOCK_NONE`; `429` indica quota. O código não alterna automaticamente fornecedor ou modelo.

## Handoff ao VANTA

- Antigravity: procurar `gemini-research` no catálogo de ferramentas em nova sessão; usar `gemini_research_status` primeiro.
- Codex: verificar `codex mcp get gemini-research`.
- Hermes: `hermes mcp test gemini-research`; nova sessão ou `/reload-mcp`.
- OpenCode: MCP registrado; abrir nova sessão, preservar o OpenCode original e os outros 13 MCPs.
- MegaBrain: indexar este documento após QA, sem chaves, prompts de projetos privados ou log raw.
- JEV e GPT QA: continuam independentes; não usar `BLOCK_NONE` como justificativa para burlar scope ou gates.

## Rollback seguro e parcial

**OpenCode:** remover exclusivamente `mcp.servers["gemini-research"]` do JSON atual (backup privado `~/.config/opencode/.secrets/opencode.before-gemini-research-<timestamp>.json`). Não restaurar o arquivo antigo integralmente, pois outros agentes podem ter feito mudanças simultâneas.

**Codex:** `codex mcp remove gemini-research` (backup privado prévia em `~/.codex/.mitr3-backups/`).

**Hermes:** `hermes mcp remove gemini-research` (backup em `~/.hermes/.mitr3-backups/`).

**Antigravity:** `agy mcp remove gemini-research`.

**Skills:** retirar apenas symlinks `mitr3-gemini-research` que apontam para `~/MITR3/skills/mitr3-gemini-research`; nunca apagar outros arquivos do time.

## Limites de afirmação / fontes oficiais

- `BLOCK_NONE` altera filtro ajustável de uma categoria; **não é acesso irrestrito** nem remove políticas do Google ou bloqueios embutidos.
- Gemini for Google Cloud/Vertex tem ciclo de autenticação por projeto/IAM diferente do Developer API de chave do AI Studio; **esta integração não é Vertex AI**.
- Para acesso avançado a modelos cibernéticos do Google sem certas restrições, existe o **Fairwind Program**, separado, sujeito à aprovação da organização; não presumir elegibilidade nem tentar reproduzir acesso de terceiros.
- A API gratuita pode utilizar conteúdos para melhoria de produtos, dependendo dos termos e tier. Nunca enviar dados sensíveis sem verificar as condições do projeto.

Documentação oficial:
- https://ai.google.dev/gemini-api/docs/generate-content/safety-settings
- https://ai.google.dev/api/generate-content
- https://ai.google.dev/gemini-api/docs/models
- https://ai.google.dev/gemini-api/docs/pricing
- https://deepmind.google/fairwind-program/

**Veredito técnico 22/10/2026:** `MCP_CODE_QA_PASS_30 | FOUR_CLIENTS_REGISTERED | HERMES_HANDSHAKE_PASS | GOOGLE_API_LIVE_UNVERIFIED`.
