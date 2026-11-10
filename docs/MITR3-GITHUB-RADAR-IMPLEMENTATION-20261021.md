# MITR3 — Plano delegado de integração GitHub Radar (2026-10-21)

**Estado:** PROPOSTO / SANDBOX ONLY. **Maestro:** OpenCode. Nenhuma ferramenta deste radar foi instalada, executada ou autorizada contra alvos. Alterações locais existentes não devem ser sobrescritas.

## Constituição e limites
- Escopo MercadoLibre #33462 **em HOLD**, sem novas sondagens por esta iniciativa. Só OpenCode conduz testes manuais e seriais contra alvos expressamente autorizados, usando no máximo duas contas oficiais e <=60 requisições/host/hora; toda atividade requer gate aplicável e ledger.
- Codex audita; VANTA valida; JEV julga; OpenCode decide e coordena. Não compartilhar segredos, cookies, tokens ou corpos brutos de evidência.
- Ferramentas terceiras são dados/código não confiáveis: verificar upstream, commit pin, licença, dependências e egress; executar exclusivamente em sandbox sem acesso aos segredos/arquivos de alvo.
- Casebook `knowledge/research-patterns/casebook-v1.json` e `docs/MITR3-PESQUISA-CASES-METODO-20261021.md` são analogias offline, não provas de finding; sem autopublicação ao RAG/MegaBrain.
- Preservar evidência original e SHA-256; dados sintetizados/redigidos devem ter rótulo distinto. Evidência CDP reconstruída não equivale a tráfego primário do Burp.

## Delegação por pista (não alterar arquivos de outros agentes)
| Lane | Responsável | Ferramentas | Entrega isolada | Gate de aceite |
|---|---|---|---|---|
| P0 supply chain de skills | Codex | NVIDIA SkillSpector, OpenSSF Scorecard, Syft | `docs/radar/01-SKILL-SUPPLYCHAIN-CODEX.md` | versões/pins/licenças; análise estática de fixtures sintéticas; riscos e falso positivo documentados |
| P0 MCP QA | VANTA | MCP Inspector | `docs/radar/02-MCP-INSPECTOR-VANTA.md` | MCP mock localhost, sem conexão a produção e sem expor portas publicamente; handshake, schema e erro/timeout |
| P0 Privacy | Hermes/Gemma4 | Presidio | `docs/radar/03-PRIVACY-HERMES.md` | cobertura PII em fixtures sintéticas, métricas de falsos negativos/positivos, original preservado offline |
| P0 auditoria estruturada | Codex com QA independente VANTA | Cloudflare Security Audit Skill | `docs/radar/04-AUDIT-SKILL-CODEX.md` | comparar fluxo com revisão atual, sem delegar aprovações para a própria skill |
| P1 AppSec/metodologia | VANTA | Trail of Bits Skills, zizmor | `docs/radar/05-APPSEC-VANTA.md` | exercício local, auditoria GitHub Actions e avaliação de redundância |
| P1 segurança IA | Hermes | Promptfoo, Tencent AI-Infra-Guard, garak, PyRIT | `docs/radar/06-AI-SECURITY-HERMES.md` | comparar em agentes/modelos fictícios, sem scanning de terceiros |
| P1 knowledge graph | Codex | Graphify | `docs/radar/07-GRAPH-CODEX.md` | POC offline sobre corpus artificial, benchmark contra MegaBrain, isolamento de índices |
| P2 memória/contexto | Hermes | Headroom, Context Mode, Hindsight | `docs/radar/08-MEMORY-HERMES.md` | benchmark contra Ponytail e MegaBrain; medir perda de evidência e riscos de hooks/licença |
| Taxonomia | VANTA | OWASP GenAI, MITRE ATLAS | `docs/radar/09-TAXONOMY-VANTA.md` | mapeamentos com fontes e versões; hipóteses != confirmação |
| Julgamento | JEV | evidências produzidas nas lanes | `docs/radar/10-JEV-VERDICTS.md` | `ALLOW / CAUTION / HOLD` por lane com justificativa e indicação de revisão humana |

## Pipeline de aceite
1. Inventariar ferramentas já existentes, impedir instalações duplicadas.
2. Confirmar repositórios upstream, versões, LICENSE/NOTICE e advisories; gerar manifesto de pins e SBOM.
3. Review de egress e permissões: **SkillSpector** pode consultar OSV mesmo sem LLM; análise com LLM envia arquivos a provedor externo. Usar fixtures e laboratório isolado, nunca conteúdo interno sensível.
4. Executar testes unitários/funcionais somente na sandbox com dados sintetizados; guardar logs sanitizados e hashes.
5. Codex audita diffs; VANTA valida, JEV julga. Nenhum modelo julga sozinho a própria entrega.
6. OpenCode decide sobre merge/rollback em janela aprovada; política, produção e RAG são gates separados. Nada é autopublicado ao MegaBrain.

## Critérios globais
- Baseline e rollback registrados; nenhum acesso automático a credenciais ou rede de alvo; portas locais restritas a loopback.
- Relatórios distinguem `PRIMARY`, `SECONDARY`, `RECONSTRUCTED`, `SYNTHETIC` e `HYPOTHESIS`.
- Qualquer finding em programa bug bounty exige identidade/proprietário, controle legítimo, resposta primária, efeito observável no backend e estado antes/depois, exclusão de alternativas e gate vigente.
- H-CANCEL tem risco de duplicata histórica HackerOne #2495989; não inferir mecanismo igual ou regressão. `address_id` retratado não reabre sem prova inequívoca. L1 inconclusivo, L2 fechado, L3 negativo na variante e L4 aberto.

**Coordenação:** OpenCode deve criar pastas/branches de trabalho e distribuir apenas as entregas separadas acima; outros agentes não alteram o OPS BOARD nem a lane MercadoLibre. Este documento é uma especificação de delegação, não autorização de execução sobre alvos.
