# MITR3 — pacote de agentes preparado em 2026-10-24

Estado: **CANDIDATES_CREATED / NOT_INSTALLED / NOT_ACTIVATED**.
Pedido atual prioriza montar os Hackerbots. Este pacote materializa papéis e skills;
não instala contas, serviços ou modelos. F01 e aceite operacional continuam pendentes.

## Time inicial e roteamento

| Agente / papel existente | Missão única | Entrada principal |
| --- | --- | --- |
| Morfeus / OpenCode | Coordenar e encaminhar revisão | `.opencode/skills/mitr3-hb-maestro/SKILL.md` existente |
| Research / Hermes | Extrair fatos de corpus aprovado | `hackbots/skill-builder/drafts/mitr3-hb-research-curator/SKILL.md` |
| QA / reviewer | Revisar evidências de outro produtor | `hackbots/skill-builder/drafts/mitr3-hb-qa-reviewer/SKILL.md` |
| Specter / Web | Interpretar diferencial HTTP sintético | `hackbots/skill-builder/drafts/mitr3-hb-web-evidence/SKILL.md` |

Research e QA formam o primeiro time do plano; Specter já tinha perfil candidato,
agora tem metodologia gerada. Ele permanece na fase posterior até avaliação.
JS/API/RE/Fuzzing/Vulnerability Intelligence continuam no roadmap; não criar oito
terminais nem duplicar especialistas existentes antes de medir o primeiro time.
`bots.json` permanece o catálogo de papéis existente; esta tabela é staging, não
registro de disponibilidade. Modelo do Morfeus não foi alterado ou presumido validado.

Skills novas são geradas pelo Builder existente, cada uma com quatro passos,
evidência por passo e quatro casos declarados positivos/negativos. Cada entrada
carrega apenas um playbook em `hackbots/agent-candidates/playbooks/`, que roteia
subskills existentes conforme a tarefa. Não há cópia de todo o catálogo no prompt.
Arquivos em drafts são ignorados pelo Git: os métodos e playbooks de origem em
`hackbots/agent-candidates/` permitem reprodução sem depender desses rascunhos.

## Reprodução e verificação

Na raiz MITR3, para cada `research`, `qa`, `specter`, executar por operador:

```sh
python3 hackbots/skill-builder/skill_builder.py new hackbots/agent-candidates/methods/research.method.json
python3 hackbots/skill-builder/skill_builder.py audit mitr3-hb-research-curator
```

Repetir com os outros métodos/nomes da tabela. Se já existir, usar apenas `audit`;
`new` recusa sobrescrita. Não editar os drafts para satisfazer o gate.
Builder PASS verifica geração/consistência, com `evals_executed=0`; não comprova
execução de agente. Não há run observado ou suíte artificial para fabricar PASS.
Research conserva fixtures R01–R03; Specter reutiliza benchmark v2. QA verifica
hash divergente, promoção indevida e conflito de autoria. Oráculos e mapeamento
Evaluator precisam de revisão independente antes do ensaio real monitorado.

Handoffs textuais não são `result.json`. Se a missão exigir JSON, usar os schemas
v0.1 existentes, sem campos extras nem cobertura inventada. Sem medição confiável,
entregar handoff incompleto com lacuna explícita. JEV segue shadow.

## Handoff Maestri

Prompts preparados: `hackbots/agent-candidates/research-role.md`, `qa-role.md` e
o perfil Specter existente. O perfil Specter aponta para a skill desta tabela.
Nenhum prompt foi atribuído a terminal; nenhuma configuração OpenCode foi instalada.

`maestri list` e `maestri debug` nesta sessão falharam com **Operation not permitted**
no socket existente. Logo não há inventário confiável de conexões para recrutar ou
atribuir papéis. Não tentar outro transporte para contornar a restrição.
Quando o ambiente permitir e a fase operacional tiver sido liberada:

1. `maestri list`, `maestri role list` e `maestri preset list` para descobrir o time.
2. Reutilizar Morfeus/Specter/Research/QA presentes; não reiniciar nem substituir
   terminal automaticamente. `role assign` reinicia e perde histórico.
3. Criar papéis ausentes com `maestri role create NOME PROMPT`, usando os arquivos
   preparados; recrutar somente função ausente, após F01 e revisão de runtime.
4. Validar permissões no runtime instalado e ensaio isolado antes de conectar
   dados/ferramentas reais. O frontmatter Specter é proposta, não enforcement provado.

Não há ativador automático. Máximo piloto: dois workers, preferencialmente produtor
e revisor em sequência; apenas um worker sintético no runner atual. A skill não
concede shell, rede ou acesso direto a `hackbots/private`.

## Referências e limites

[Arcanum, Building AI Hackbots Part 1](https://arcanum-sec.com/blog/hackbots/),
consultado em 2026-10-24: missão estreita, contexto curado e automação determinística
orientaram o pacote. A página lista vídeos de criação; os vídeos/transcrições não
foram examinados nesta rodada e não são prova de decisões técnicas do projeto.
Não foram instalados DSPy, LangChain ou outro orquestrador.

`human_approved=false`, `promotable=false`, `behavioral_gate=NOT_RUN` e
`trace_authenticity=NOT_VERIFIED` para as candidatas. A revisão independente desta
autoria, quando registrada, tem escopo documental; não fecha F01, não calibra o
modelo futuro e não equivale ao aceite humano.
