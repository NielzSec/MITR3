# MITR3 Hackbots — fase 0 (offline)

**Estado:** piloto experimental; runner determinístico e probes locais sintéticos disponíveis.
Não executa pentest nem lança agentes LLM. Probes de rede usam apenas canários locais.

## Decisão de arquitetura

- **Orca é o painel e transporte** do time. O OpenCode/Morfeus continua como coordenador lógico quando o operador o iniciar.
- Este diretório contém contratos, skills modulares, QA offline e runner sintético isolado.
- **Ruflo é opcional**, sem instalação: avaliar somente após medir Orca + contrato local.
- MegaBrain é conhecimento curado; JEV avalia propostas, nunca assina um aceite humano.
- Limite inicial: **2 workers** simultâneos por API; especialistas adicionais permanecem inativos.
- Skills canônicas ficam em `../skills/mitr3-hb-*/SKILL.md`; não duplicar em outros diretórios.

## Primeiro fluxo

1. Operador define artefato local e finalidade; escopo ativo segue `../docs/SCOPE.md` (Nexus), sem exceções.
2. Maestro atribui uma missão `contracts/mission.schema.json`.
3. Um worker executa **somente leitura offline** e entrega `contracts/result.schema.json`.
4. Validador independente confere contrato, cobertura, vínculos de evidência e aceite humano.
5. Revisão humana aprova ou devolve para correção; somente depois considerar ingestão no MegaBrain.

## Comandos locais e sem rede

```sh
python3 hackbots/tools/validate.py mission hackbots/examples/mission-offline.json
python3 hackbots/tools/validate.py result hackbots/examples/result-review-pending.json
python3 -m unittest discover -s hackbots/tests -v
```

**Importante:** `result-review-pending.json` é apenas exemplo. PASS no validador não significa finding confirmado, vulnerabilidade real, escopo autorizado nem aprovação do operador.

## Continuidade do Master Plan

[Pacote de agentes e skills](docs/TEAM-PACK.md): Research, QA e skill do Specter
gerados para revisão; Morfeus preservado. Não instalados ou ativados no Orca.

[Roadmap](docs/HACKERBOTS-ROADMAP.md), [arquitetura](docs/HACKERBOTS-ARCHITECTURE.md),
[papéis](docs/HACKERBOTS-ROLES.md) e [gates](docs/HACKERBOTS-SECURITY-GATES.md)
distinguem o implementado do proposto. A ordem atual é fundação → Research/QA →
especialistas, sem habilitação automática do catálogo.
[Pacote F01](deploy/README.md): launcher/units preparados, não instalados.
[Primeiro Research Hackerbot](docs/FIRST-RESEARCH-HACKERBOT.md): especificação e
oráculos manuais sintéticos, sem modelo/skill ativados.

Consulte `docs/ORCA.md`, `bots.json` e as skills. Não criar serviços systemd, docks, daemons nem schedulers nesta fase.


## Skill Builder experimental (v0.2)

Ferramenta: `hackbots/skill-builder/README.md`; skill de operação: `.opencode/skills/mitr3-hb-skill-builder/SKILL.md`.
Gera rascunhos de skills com metodologia versionável, checklist por ID e testes declarados,
e compara saídas JSON com oráculos fixados por SHA256, incluindo regressões na mesma suíte.
O gate `REVIEW` **não é aprovação nem execução verificada**. Não há publicação automática.

O inventário `tools/js_inventory.py` aceita arquivos regulares de até 5 MB,
rejeita symlinks no caminho por descritores de diretório e limita a leitura.
É um extrator por regex, não um parser JavaScript nem medidor de cobertura semântica.
Linhas físicas avançam somente em LF, como no Execution Verifier.
Requer Linux; pressupõe raiz controlada pelo operador. Não isola processos hostis do
mesmo usuário, hardlinks ou alterações concorrentes de conteúdo.
Na saída compartilhável v2, todos os caminhos viram `/{route-N}`; nome e hash do
arquivo de origem são omitidos. IDs correlacionam ocorrências somente dentro de um
relatório. Linhas, tipos de chamada e contagens continuam visíveis: revisar metadados
antes de compartilhar. Sem opção adicional, nenhum relatório privado é escrito.

`python3 hackbots/tools/js_inventory.py hackbots/examples/sample.js --save-private`
guarda rotas e proveniência em `hackbots/private/<report_id>.json` (arquivo 0600,
pasta 0700, ignorada no Git), sem sobrescrever. Queries, credenciais de URL e fragments
são descartados inclusive nessa versão privada. O JSON compartilhável não é um
resultado completo do contrato de evidências: a proveniência exige o mapa privado.
Consumidores da saída antiga devem migrar explicitamente para `schema_version: 2`.

Protótipo offline disponível: [Execution Verifier](docs/EXECUTION-VERIFIER.md).
Recalcula linhas físicas e cobertura de intervalos declarados; não executa agentes
nem autentica traces. O [runner isolado](runner/README.md) executa apenas o worker
determinístico fixo, não a fixture JavaScript; consulta por agentes ainda não está integrada.

O validador de contratos aceita JSON de até 1 MB, rejeita chaves duplicadas e números
não finitos, symlinks em qualquer componente e hardlinks. Evidências têm teto de 25 MiB
e leitura limitada pelo descritor validado. Um resultado `accepted` no JSON continua
sendo uma declaração estrutural, não autenticação da identidade do revisor humano.

### Pesquisa aplicada / próximos laboratórios

[Piloto Web offline](docs/WEB-HACKERBOT-PILOT.md): avaliador de metadados SQLi sem agente.

[Plano PHP2Shell](docs/PHP2SHELL-LAB-PLAN.md): pesquisa de CVEs e testes futuros em Docker/VM, NÃO IMPLANTADO.

## Captura de rede REA (operador, 26/10/2026)

Utilitário funcional: `python3 hackbots/tools/rea_network_capture.py browser CENARIO.json` (navegador isolado) ou `... mitm CAPTURA.mitm` (importação offline do mitmproxy). Capturas brutas e resumos SHA-256 ficam em `hackbots/private/rea-network/`, não são versionados. Procedimentos e testes: [REA-NETWORK-CAPTURE-20261026](docs/REA-NETWORK-CAPTURE-20261026.md). A presença do utilitário **não** altera `can_issue_network=false` nem ativa agentes, listeners ou serviços.
