# Entregas GPT-6 para OpenCode — MegaBrain + MITR3

Data: 2026-10-20. Local: /tmp/opencode/mitr3-gpt6-context-bridge
Branch: gpt6/context-bridge-20261020
Status: alterações testadas em worktree isolado, master não modificado.
Este arquivo não envia mensagem direta pelo Maestri.

## Commits independentes para revisão

1. d4503cc — ponte somente leitura entre a CLI de inteligência local e o
   rag_context do MegaBrain MCP, com resultados e citações separados.
   Prova real: CVE-2023-23397 --> CWE-294 da CISA; MegaBrain retornou
   contexto geral de segurança, **não** comprovação dessa aresta.
2. 9046d42 — snapshot KEV versão 2: hash de shortDescription, notes e
   forensicTriage sem persistir os textos completos, cwes ordenadas e
   deduplicadas, bloqueio de CVEs repetidas e migração v1→v2 via rebaseline
   (sem sinalizar 1.748 CVEs antigas como novos updates).
3. Terceiro commit desta branch — verificador de readback MegaBrain:
   contabiliza placeholder e divergência entre safe_content e
   content_redacted, sem expor corpo do documento.

### Evidência e limite do MegaBrain

- Testado via Tailscale MCP real com rag_context e knowledge_read.
- rag_context informou evidence_sufficiency=unassessed.
- O readback mostrou 26 armazenados, 16 com conteúdo legível e 10 com
  placeholder de segredo. Em **todos esses dez**, content_redacted=false.
- Este dado revela uma inconsistência da API, mas não identifica a regra
  de redaction e não prova que todo caso ofensivo seria bloqueado.
- Nenhuma reescrita, desativação de filtro ou contorno de proteção.

### Propriedades de segurança

- Nenhum novo serviço, modelo LLM, dependência global ou varredura ativa.
- Ao apresentar contexto do MegaBrain, descarta conteúdo bruto dos chunks,
  expõe apenas IDs de citação e marca relation_validated=false.
- As arestas locais carregam fonte e SHA256 e agora conferem o hash
  declarado contra o conteúdo local, com falha fechada.
- Nunca inferir CWE↔ASVS ou CVE↔ator; nenhuma nova aresta foi inventada.
- O índice local e caches da máquina principal não são reescritos
  pela branch enquanto estiver isolada.

### Comandos de aceitação

    cd /home/nielz/MITR3
    git branch --list 'gpt6/*'
    git log --oneline master..gpt6/context-bridge-20261020
    git diff master..gpt6/context-bridge-20261020 --stat

A integração deve ser feita pelo OpenCode/Codex após revisão:
cherry-pick dos commits desejados em ordem, ou por PR local.

Testes sem rede: usar
    python3 -m unittest discover -s /tmp/opencode/mitr3-gpt6-context-bridge/tests -p 'test_*.py' -q

Para testar a ponte contra o próprio MegaBrain, usar venv MCP existente:
    ~/.local/share/mitr3-nexus-venv/bin/python /tmp/opencode/mitr3-gpt6-context-bridge/bin/mitr3-context-bridge.py CVE-2023-23397 --remote

O próximo passo para o time: Codex validar relevância das citações
e do lote de regressão cego; OpenCode revisar migração snapshot e
corrigir conteúdo/redaction no servidor remoto; Hermes e VANTA usar
os resultados como evidência com escopo e atribuição preservados.

