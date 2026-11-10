# Maestri ↔ MITR3 Hackbots

> Arquivo histórico. A coordenação atual está em [ORCA.md](ORCA.md) desde 10/11/2026.

**Decisão inicial:** continuar usando Maestri, evitando instalar dois orquestradores simultaneamente.

- Maestri: canvas, comunicação `maestri ask`, notas e divisão visual de responsabilidade.
- OpenCode: coordenador lógico quando explicitamente iniciado pelo operador.
- Hackbots: contratos de entrada/saída e skills consultadas por caminho, sem execução residente.
- MegaBrain: pesquisa e conhecimento após curadoria; nunca automaticamente após uma execução.
- JEV + verificador determinístico + revisor humano: gates distintos.

**Piloto:** começar com JavaScript Analyst e Evidence Reviewer (máximo 2 workers). Web Recon, API, AuthZ e RE em espera. Preferir API remota para modelos; nunca iniciar todos os agentes em paralelo no host de 16 GB.

Atualização de planejamento: a ordem do [roadmap](HACKERBOTS-ROADMAP.md) passa a ser
fundação/custódia → Research/QA → JS/Web/API. A frase acima registra o piloto original,
não habilita esses perfis. O limite atual de execução continua um worker sintético.

**Integração futura:** abrir no Maestri o workspace existente `~/MITR3` e apontar a instrução da missão para `skills/mitr3-hb-*/SKILL.md`. Não alterar agentes ou canvases existentes sem revisão.

**Ruflo:** avaliar separadamente em laboratório se agrega agendamento/estado/custo suficientes para justificar outro runtime. Se aprovado, deve respeitar o maestro atual e não controlar a rede nem instalar hooks globais por padrão.

**Não executar alvos nesta fase:** o contrato do Nexus `docs/SCOPE.md` requer aceite humano por artefato; programa bug bounty demanda ainda regras/escopo específicos. Um status PASS do verificador nunca substitui autorização ou revisão.

Referências: https://arcanum-sec.com/blog/hackbots/ ; https://agentskills.io/specification ; https://www.themaestri.app/pt-br/linux ; https://github.com/ruvnet/ruflo ; https://github.com/OWASP/DevSecOpsGuideline
