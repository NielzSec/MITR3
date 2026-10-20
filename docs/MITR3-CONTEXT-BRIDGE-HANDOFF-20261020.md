# GPT-6 → OpenCode: contexto cruzado MegaBrain + grafo local

Data: 2026-10-20
Implementação isolada: branch gpt6/context-bridge-20261020.
Não aplica mutações no MegaBrain nem no repositório master automaticamente.

## Motivação

O MITR3 tem 1.689 relações estruturadas cwe_of vindas do feed CISA KEV, com SHA256 do feed.
O MegaBrain tem rag_context com citações por documento/chunk/evidência e uma base ampla de skills,
mas a existência de uma citação NÃO comprova uma relação específica.

Em uma consulta de prova por CVE-2023-23397, a camada local retornou
CVE-2023-23397 --cwe_of--> CWE-294, com evidência do CISA KEV.
No MegaBrain, a mesma pergunta retornou contexto genérico de uma skill
de segurança de API. A ponte manteve o remoto separado.

## O que entrega

- bin/mitr3-context-bridge.py: consulta somente leitura ao índice local
  e à CLI oficial de relações.
- Com --remote: uma consulta rag_context no MegaBrain MCP com limite de contexto e tempo.
- Resultado com local.matches (ID/fonte/URL/nível), local.source_declared_relations
  (aresta direta+tipo+hash) e megabrain.citations (origem, IDs de documento/evidência,
  relation_validated=false).
- Não grava prompt remoto nem o corpo dos chunks, não executa código de fontes,
  não faz knowledge_store.
- Se o MCP remoto falhar, a resposta local continua funcionando com erro explícito.

## Uso no Arch, após cherry-pick

    ~/MITR3/bin/mitr3-context-bridge.py CVE-2023-23397
    ~/.local/share/mitr3-nexus-venv/bin/python ~/MITR3/bin/mitr3-context-bridge.py CVE-2023-23397 --remote
    ~/.local/share/mitr3-nexus-venv/bin/python ~/MITR3/bin/mitr3-context-bridge.py "cache poisoning" --remote --json

## Limites de evidência

Não confundir capacidade de pesquisar contexto com comprovação de vínculo.
MegaBrain retornou evidence_sufficiency=unassessed e contextos de skills genéricas.
Para promover nova aresta, OpenCode/Codex devem reunir evidência
específica e estruturada, verificar autoria, integridade e política de divulgação,
depois usar a curadoria humana e testes.

Não implementa mapeamento automático CWE→ASVS, técnicas→atores ou malware→grupos.
Não confere escopo para execução ativa.

## Integração com o time

OpenCode: revisar branch e rodar test_context_bridge.py.
Codex: checar o contrato de output e se nenhuma citação remota vira prova.
Hermes: pesquisar e atribuir fonte, autor, licença e confiança.
VANTA: auditar vínculos RE/CTF somente com evidência autorizada.
JEV: abster-se sobre relações sem documentação específica.

Próxima entrega sugerida: auditar safe_content redigido no MegaBrain
(10/26 fichas) e fortalecer KEV delta com campos adicionais e migração
versionada, preservando semântica de primeiro snapshot.

