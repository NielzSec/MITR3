---
name: mitr3-gemini-research
description: Integração do Gemini Developer API via MCP para pesquisa em laboratório autorizado com safetySettings por chamada e orçamento reduzido.
version: 1.0.0
---

# Gemini Research MCP — MITR3

**MCP:** `gemini-research` · **Servidor:** `~/MITR3/bin/mitr3-gemini-research-mcp.py`. Detalhes e rollback: `docs/MITR3-GEMINI-RESEARCH-MCP-20261022.md`.

## Ferramentas

- `gemini_research_status`: presença de credencial e modelos configurados, sem inferência.
- `gemini_research_models`: GET autenticado da lista de modelos oficiais, sem inferência.
- `gemini_research_generate`: inferência real para casos autorizados; pode consumir crédito.

Exemplo de argumentos de `gemini_research_generate`:

```json
{
  "case_id": "MITR3-LAB-CODE-AUDIT",
  "profile": "authorized_research",
  "model": "gemini-3.5-flash-lite",
  "max_output_tokens": 384,
  "prompt": "Examine este trecho de código de meu laboratório e sugira melhorias de segurança e testes..."
}
```

Somente o perfil `authorized_research` insere em `models.generateContent`:

```json
"safetySettings": [
  {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
]
```

Isso configura **um filtro ajustável do Google por requisição**, não remove proteções embutidas do modelo nem obrigações de uso responsável. O perfil `standard` preserva os defaults do provedor; erros de configuração não acionam fallback oculto.

## Orçamento e limites

- Modelos: `gemini-3.5-flash-lite` (padrão econômico), `gemini-3.6-flash`, `gemini-3.8-flash`.
- Limites: 5 requisições de geração por processo MCP; 6.000 caracteres de entrada; 2.048 tokens de saída por chamada e 4.096 reservados por sessão; **12 reservas de geração por dia UTC compartilhadas entre os agentes**, com lock e log privado.
- `case_id` é obrigatório; não enviar credenciais, tokens, dados privados ou respostas brutas de terceiros.
- Gateway sem shell, browser, uploads ou ferramentas de execução; conecta apenas à API oficial do Google com HTTPS validado.
- Use Ponytail e MegaBrain antes de chamar modelo pago. Não duplique pesquisa nem remova gates JEV/GPT QA para economizar tokens.

## Credencial

Usa `GEMINI_API_KEY` ou `GOOGLE_API_KEY` do ambiente do processo, ou o arquivo privado `~/.config/mitr3/gemini-api-key` com proprietário correto e modo 0600. OAuth do Antigravity **não** garante chave para a API Gemini Developer.

Em terminal interativo, para instalar uma chave própria do AI Studio sem exibi-la:

```bash
install -d -m 0700 ~/.config/mitr3
umask 077
read -r -s -p "Gemini API key: " MITR3_GEMINI_KEY
printf '\n'
printf '%s' "$MITR3_GEMINI_KEY" > ~/.config/mitr3/gemini-api-key
unset MITR3_GEMINI_KEY
chmod 0600 ~/.config/mitr3/gemini-api-key
```

Valide depois:

```bash
python3 ~/MITR3/bin/mitr3-gemini-research-mcp.py status
python3 ~/MITR3/bin/mitr3-gemini-research-mcp.py models
```

**Não colar chaves no chat/Maestri/Git, nem colocar credenciais literais na configuração dos agentes.** Testes ativos apenas em sistemas autorizados e com orçamento aprovado.
