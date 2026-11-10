# Hackerbots — papéis e limites

Todos os especialistas abaixo estão PLANEJADOS ou ESPECIFICADOS, não habilitados.
O worker determinístico existente é infraestrutura de teste, não um especialista.
Papéis canônicos operacionais continuam em bots.json; esta tabela define o roadmap,
sem criar processos, backends novos ou permissões.

| Papel | Primeira capacidade permitida quando autorizada | Ferramentas candidatas / entrega | Fase |
| --- | --- | --- | --- |
| Recon & Intelligence / Research | Pesquisa offline em corpus aprovado, depois fontes passivas autorizadas | Hermes/MegaBrain sob acesso restrito; fatos com fonte/data/confiança | B: primeiro especialista |
| QA & Evidence Reviewer | Conferir resultado de outro produtor | Schemas/hashes/oráculos; lacunas e contraexemplos | B |
| JavaScript Analyst | Análise estática de fixture JS | Reutilizar js_inventory; rotas opacas e mapa privado | C |
| Web Security Analyst | Revisão de aplicação/código sintético | Analisadores locais; hipóteses e controles, sem tráfego externo | C |
| API Security Analyst | OpenAPI/código/mock local | Matriz autorização/endpoint; evidência, sem teste em servidor real | C |
| Reverse Engineering | Estática de ELF/PE/APK autorizado | REA Guarded, Ghidra/JADX; funções/fluxos/limites | D |
| Fuzzing & Binary Research | Harness aprovado em laboratório | AFL++/sanitizers/GDB conforme disponibilidade; crash reproduzível | E |
| Vulnerability Intelligence | Correlação de versões com advisories aprovados | OSV/CVE/CPE por consulta autorizada; exposição potencial com limites | E |

Morfeus coordena; Hermes pesquisa; MegaBrain fornece dados de conhecimento; Codex faz
engenharia/QA; Antigravity/VANTA apoia análise especializada; JEV avalia em shadow.
Um papel cadastrado não prova disponibilidade, modelo selecionado ou custo autorizado.
Research e Vulnerability Intelligence se sobrepõem em fontes; reutilizar corpus e
normalização de evidência, separando missão/oráculo, sem duplicar um serviço de pesquisa.

Antes de cada execução: tipo de tarefa, escopo, skill, ferramentas disponíveis,
permissões, teto de custo, output e verificação precisam estar fixados. Pesquisa em
write-up não concede autorização para reproduzir ataque. Versão potencialmente afetada
não é finding confirmado. Nenhum especialista pode revisar independentemente sua
própria conclusão ou registrar aceite humano por conta própria.
