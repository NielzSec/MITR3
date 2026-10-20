# MITR3 RAG — auditoria pós-feedback do OpenCode

Data: 2026-10-19 | Base: commit 4bfb4f9 (legado), versão candidata local
Responsável: GPT-6; handoff para maestro OpenCode, Codex e MegaBrain.
Nenhum processo externo ou exploração foi executado.

## 1. A linha de base antiga não mede qualidade

A bateria de 6 perguntas anterior apenas confirmou funcionamento do índice.
Foi removida das métricas de qualidade do refresh e renomeada para
legacy_smoke_benchmark com aviso explícito.

Fixture congelado: tests/fixtures/intel-relevance-v1.json.
Tem 20 consultas positivas de CVE/ASVS e conceitos conhecidos do corpus,
e 10 negativas que devem se abster. Esses exemplos são curados com
conhecimento do corpus e NÃO formam teste cego independente.

Os números do baseline foram reconstruídos usando o código exato do
commit 4bfb4f9, índice original recomposto a partir dos feeds em cache
e das 26 fichas. Assim, não se compara a versão nova contra si mesma.

| Métrica | Baseline OR/FTS5 | Roteamento tipado + AND/FTS5 |
|---|---:|---:|
| Recall@5 (média macro, 20 consultas) | 0,988 | 0,975 |
| Hit@5 | 1,000 | 1,000 |
| Precision@5 (denominador fixo de cinco) | 0,240 | 0,240 |
| Precision entre documentos retornados | 0,640 | 0,975 |
| Abstenção correta (10 negativas) | 0,200 | 1,000 |

**Interpretação:** melhorar a proporção entre os poucos itens retornados
não equivale a melhorar a P@5 convencional. O uso de AND pode piorar
o recall em perguntas parafraseadas e só é seguro como uma heurística
conservadora. A avaliação ainda não mede respostas dos agentes,
citações de evidência, falsos positivos fora do fixture ou compreensão
semântica. A cobertura das consultas negativas é pequena.

Melhorias locais: IDs CVE/ASVS ausentes agora retornam vazio, sem fallback
OR; pergunta explícita de atribuição de ransomware/encryptor/afiliados
se abstém porque o catálogo não armazena relações com agentes/famílias;
perguntas sobre CTF/cache/smuggling recebem filtro por classe de fonte;
aliases editoriais curtos para categorias técnicas, sem afirmar fatos novos.

**Não declarar** capacidade de determinar famílias de ransomware,
origem de exploit, grupos criminosos ou relações CVE→ator.

## 2. KEV delta persistente

Implementado em bin/mitr3-rag-intel-refresh.py:

- snapshot anterior em state/mitr3-kev-snapshot.json
- campo kev_delta no relatório latest, com CVEs adicionadas,
  removidas e metadados modificados
- histórico compacto em state/mitr3-kev-delta-history.jsonl
- kev_recent_by_date_added_last_7_days independente do delta
- validação de feed e rebuild antes de consolidar snapshot.

Primeira execução: initial_baseline. **Nunca tratar as 1.748 CVEs
existentes como entradas novas.** A segunda execução comparou snapshots:
0 entradas novas, 0 removidas, 0 atualizadas. O feed continha sete
entradas com dateAdded nos últimos 7 dias, mas nenhuma chegou
entre as duas execuções do MITR3. Testes sintéticos cobrem
adição, remoção, atualização e ausência de base anterior.

## 3. Skill fora do cwd

Symlink já corrigido pelo OpenCode:
~/.config/opencode/skills/mitr3-intelligence-rag

Adicionada referência direta no AGENTS.md global de OpenCode, para não
depender de cwd=/home/nielz/MITR3. A ativação em sessões previamente
abertas depende do ciclo de carregamento do OpenCode; não afirmar que
uma sessão já incorporou as instruções até testá-la diretamente.

## 4. MegaBrain: redaction e inconsistência de status

Origem do QA: state/public-rag-mcp-qa.json, knowledge_read remoto.

- 26 documentos armazenados; 16 legíveis; 10 com safe_content
  igual a [REDACTED:SECRET_CONTENT] (taxa 38,46%).
- Entre os dez: cinco pesquisas, três catálogos e dois CTF write-ups.
  Entre os dezesseis visíveis também existem pesquisas e casos CTF.
  Portanto, **não está provado** que toda pesquisa ofensiva seja filtrada;
  nem temos causa conhecida para cada rejeição.
- Dois exemplos observados: ps-cache-2024 e ctfcit-2026-faultline
  retornam found=true, index_status=ready,
  content_redacted=false, indexed_chunks=0 e safe_content placeholder.
  Isto é uma inconsistência do status da API, não prova que o filtro
  tenha acertado ou errado na classificação de segredo.
- Controle legível: jctf-rsa-41140 tem found=true, placeholder=false.
  Ambos os resultados retornam indexed_chunks=0; esse campo sozinho
  não é indicador de legibilidade.

Ação requerida no MegaBrain: investigar classificação com log interno
privado (código de motivo, regra e identificador, sem valor potencialmente
sensível). Corrigir semântica do campo content_redacted / status para
que a UI e os validadores tratem safe_content placeholder como indisponível.
Revisar taxa de falso positivo no servidor sem expor segredos.
NÃO alterar conteúdo para driblar regra, desligar filtro ou reenviar
milhares de fichas enquanto a qualidade da leitura não estiver entendida.

## 5. Próximos testes independentes

- Codex: criar uma segunda bateria cega a partir de solicitações reais
  que não sejam referências exatas do índice, anotadas antes da consulta.
- Hermes: perguntas paraphraseadas em PT/EN, consultas multi-entidade,
  CVEs sem cobertura, técnicas relacionadas e 20+ negativas realistas.
- VANTA: avaliar qualidade de explicação com evidência de fonte,
  não apenas se um documento foi encontrado.
- MegaBrain: corrigir status de readback e documentar razão de redaction.
- OpenCode: só promover o índice a camada de decisão após QA independente,
  avaliação de precisão de citação e custos.

Documentos gerados:
reports/intel-relevance-v1-baseline.json
reports/intel-relevance-v1-candidate.json

