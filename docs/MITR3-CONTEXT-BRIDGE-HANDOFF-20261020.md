# GPT-6 → OpenCode: contexto cruzado MegaBrain + grafo local

Data: 2026-10-20
Implementação original: branch gpt6/context-bridge-20261020, incorporada ao master.
Integração atual: inclui o grafo ATT&CK de 462bb00, mantendo namespaces separados.
A ponte continua somente leitura e não aplica mutações no MegaBrain.

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

## Uso atual no Arch

    ~/MITR3/bin/mitr3-context-bridge.py CVE-2023-23397
    ~/.local/share/mitr3-nexus-venv/bin/python ~/MITR3/bin/mitr3-context-bridge.py CVE-2023-23397 --remote
    ~/.local/share/mitr3-nexus-venv/bin/python ~/MITR3/bin/mitr3-context-bridge.py "cache poisoning" --remote --json

## Limites de evidência

Não confundir capacidade de pesquisar contexto com comprovação de vínculo.
MegaBrain retornou evidence_sufficiency=unassessed e contextos de skills genéricas.
Para promover nova aresta, OpenCode/Codex devem reunir evidência
específica e estruturada, verificar autoria, integridade e política de divulgação,
depois usar a curadoria humana e testes.

Não infere mapeamento CWE→ASVS, técnicas→atores ou malware→grupos por texto.
As relações ATT&CK expostas abaixo são somente os relationships explícitos do STIX.
Não confere escopo para execução ativa.

## Integração ATT&CK: contrato separado

    ~/MITR3/bin/mitr3-context-bridge.py T1059.001
    ~/MITR3/bin/mitr3-context-bridge.py T1059.001 --json
    ~/MITR3/bin/mitr3-context-bridge.py T9999 --json

A ponte reconhece IDs exatos `T####`, `T####.###`, `TA####`, `G####`, `S####`,
`M####` (sem distinguir caixa). Usa exclusivamente
`mitr3-rag-intel.py graph <ID> --json --all`, sem fallback FTS/relations para ID
ATT&CK desconhecido. `TA####` é reconhecido, mas táticas não integram as entidades
da v1; portanto pode retornar vazio. Texto livre continua no catálogo existente.

`graph --json` agora inclui `metadata={source_id,url,sha256}` lido do SQLite na
mesma transação de entidades/arestas. A opção `--all` é exclusiva do JSON e
remove o corte por direção; o texto humano padrão de `graph` ficou byte a byte
igual. A ponte exige `len(outbound/inbound)==counts[direction]`, recusando páginas
truncadas. `--limit` da ponte controla matches do catálogo, não corta arestas ATT&CK.

Verificação, antes de retornar qualquer aresta:

1. Hash SHA256 dos bytes do bundle (stream binário, sem parse de STIX/prosa)
   igual ao manifest `knowledge/reference-datasets/cache/enterprise-attack-manifest.json`.
2. Mesmo hash em `metadata.sha256` da resposta graph, proveniente de
   `state/mitr3-attack.sqlite3`; fonte/URL também precisam ser as do bundle MITRE.
3. Mesmo hash em `origin.bundle_sha256` de **cada** aresta. Falta/divergência gera
   `LocalError` e nenhum resultado parcial; isso também impede que `--remote`
   tente compensar uma falha local com citações.
4. Predicados permitidos: `uses`, `mitigates`, `subtechnique-of`, `attributed-to`.
   Outros tipos não são promovidos. Exige ID `relationship--...`, `modified`
   com timezone, pontas com IDs/tipos STIX dos seis tipos suportados e incidência
   na entidade resolvida. CVE/CWE/ASVS/CASE não são pontas válidas nesse envelope.

Contrato JSON da ponte:

- `local.matches`, `local.source_declared_relations`, `local.relation_count`:
  exclusivamente catálogo CVE/CWE/ASVS/CASE; vazios/zero para consulta ATT&CK.
- `local.attack_entities`: ID STIX, ID MITRE, nome, tipo e `namespace='attack'`.
- `local.attack_relations`: `direction`, `predicate`, `source_node`, `target_node`
  (IDs STIX), `source_name`, `target_name`, `stix_id` (relationship), `modified`,
  `sha256`, `source_id`, `source_url`, `assertion_type='source_declared_only'`,
  `namespace='attack'`.
- `local.attack_relation_count` e `local.attack_relations_by_type`: somente ATT&CK.
  Consulta CVE mantém esses campos vazios/zero e nem invoca `graph`.
- `note` final e `policy` declaram nos dois modos: aresta ATT&CK não prova relação
  CVE/CWE/ASVS/CASE, nem o inverso; citação MegaBrain não valida aresta de nenhum
  desses namespaces. Citações remotas seguem `relation_validated=false`.

Resultado no bundle SHA256
`81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`:
`T1059.001` resolve PowerShell e **243 arestas**: outbound `subtechnique-of=1`,
inbound `mitigates=5` e `uses=237` (`attributed-to=0`). A relação de sub-técnica
aponta a Command and Scripting Interpreter. `T9999` retorna listas vazias sem erro.
O modo humano da ponte mostra contagens completas e até oito exemplos; JSON
contém todas as arestas verificadas.

Validação: **118/118 testes**, sem ResourceWarning (104 anteriores + 14 novos).
O suite inclui manifest alterado em tmp, metadata/aresta com hash divergente,
falha atômica na última aresta, ausência de resgate remoto, tipos não permitidos,
campos ausentes, truncamento e isolamento bidirecional de namespaces. Eval
candidate completo inalterado: recall 0.975, abstenção 1.000. Fixture e `search()`
inalterados. Evidências em `reports/context-bridge-attack-v1-qa.json`.

## Integração com o time

OpenCode: revisar branch e rodar test_context_bridge.py.
Codex: checar o contrato de output e se nenhuma citação remota vira prova.
Hermes: pesquisar e atribuir fonte, autor, licença e confiança.
VANTA: auditar vínculos RE/CTF somente com evidência autorizada.
JEV: abster-se sobre relações sem documentação específica.

Próxima entrega sugerida: auditar safe_content redigido no MegaBrain
(10/26 fichas) e fortalecer KEV delta com campos adicionais e migração
versionada, preservando semântica de primeiro snapshot.

