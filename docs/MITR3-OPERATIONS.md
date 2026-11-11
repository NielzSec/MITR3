# MITR3 — Cybersecurity & AI Operations
Atualizado: 2026-10-19 | Arch Linux

## Missão
MITR3 não é apenas CTF. É uma equipe de inteligência, pesquisa, engenharia reversa e auditoria de segurança. Cenários: bug bounty, pentest autorizado, AppSec web/API, mobile, infraestrutura/redes, Active Directory, cloud/Kubernetes, firmware e malware, OSINT, desenvolvimento de ferramentas, segurança de aplicações e CTF.

## Funções
- Hermes: pesquisa e documentação usando MegaBrain e fontes verificáveis.
- OpenCode: executor único para testes ativos dentro das regras do engajamento.
- Codex: code review, QA e testes de reprodutibilidade.
- Antigravity: arquitetura, código, RE e desenvolvimento de ferramentas.
- JEV: avaliação shadow de qualidade/custo; não autoriza operações.
- Coordenador: backlog, escopo, evidências, prioridades e postmortem.

## Escopo por engajamento
Para bug bounty guardar regras públicas do programa, ativos incluídos/excluídos, métodos permitidos, intensidade, limites, dados de teste, janela e contatos. Para pentest guardar contrato/ROE e escopo do cliente. Escopo por ativo e método, não por palavra-chave. Preservar pesquisas ofensivas como conhecimento, mas testar só ativos autorizados.

## Playbooks
### Bug bounty
1. Ler política do programa/safe harbor/exclusões e versionar escopo.
2. Reconhecimento passivo, histórico e tecnologia; correlacionar MegaBrain/Context7.
3. Inspeção web com DevTools, Playwright, Burp Suite e inventário de API.
4. Validar controle de acesso, autenticação, BOLA/IDOR/BFLA, fluxo OAuth, sessão, lógica de negócio, injeções e configurações no escopo e limites do programa.
5. Evidência mínima, impacto e reprodução sem expor dados de terceiros.
6. Relatório/submissão, duplicatas, correção, reteste e lições.

### Pentesting autorizado
1. Contrato/ROE, ativos, contas de teste, horários, criticidade e canal de emergência.
2. Mapeamento autorizado, análise web/API/mobile/network/AD/cloud e validação graduada.
3. Relacionar SAST/DAST/SCA/SBOM, versões, CVEs, logs e arquitetura.
4. Relatório técnico/executivo, riscos, recomendações, re-teste e registro de falhas de hipótese.

### Malware em pentest autorizado (2026-11-11)
Regra do time: agentes MITR3 podem criar, usar e executar malware durante um pentesting real, sob as condições abaixo. Sem elas, a operação é bloqueada.

1. **Autorização:** somente sob contrato/ROE válido (purpose `authorized_pentest`, `ctf` ou `internal_audit`). O contrato lista explicitamente as famílias de malware permitidas (ex.: loader, C2, ransomware de prova, dropper, persistence), os ativos-alvo e a janela. Sem contrato cobrindo a família e o alvo, nem criar, nem usar, nem executar.
2. **Contrato por artefato:** cada binário/payload recebe contrato Nexus por SHA256 (`authorize_scope.py`, TTY, `AUTORIZO <12 hex>`), mesmo fluxo de RE. Rebuild = novo hash = novo contrato.
3. **Criação:** qualquer agente pode criar (Hermes pesquisa e TTPs, Antigravity arquitetura e código, OpenCode desenvolvimento). Artefato hash-pinned em `evidence/` do case.
4. **Execução:** SOMENTE OpenCode, executor único de testes ativos. Somente contra ativos do escopo do contrato, em ambiente isolado (VM/lab de detonação) ou alvo contratado. Nenhum outro agente executa; nenhum agente executa fora da janela.
5. **Controles obrigatórios:** sem autopropagação além dos ativos do escopo; sem persistência além da janela do contrato; credenciais/dados coletados ficam no case, nunca em RAG, repos compartilhados ou logs; BlackOps valida OPSEC antes da execução (rotina prévia, canais, anonimidade).
6. **QA independente:** Codex revisa que o artefato confina ao escopo (alvos, famílias, mecanismos de propagação/persistência) antes de cada detonação. Detonação sem esse gate = violação da regra.
7. **Evidência e encerramento:** logs de detonação com timestamps, hashes, IOCs gerados e TTPs observados no case; limpeza/remoção pós-janela registrada; IOCs e comportamento vão no relatório final.

### Engenharia reversa e baixo nível
1. Nexus: health, toolchain index, preview route e scope status.
2. REA, reverse-skill, Ghidra, JADX, radare2, GDB; IDA somente se instalação genuína compatível for validada.
3. Escrita/análise via Nexus só após contrato interativo e SHA256 do artefato.
4. Evidência de CFG/XREF/pseudocódigo, casos não resolvidos, versão de ferramentas e limitações.

### Pesquisa AI/Cyber
1. MegaBrain skill_search + knowledge_search + rag_context para contexto versionado.
2. CVE/CWE/ATT&CK, advisories, fontes técnicas e write-ups como evidências verificáveis.
3. JEV shadow e validação independente do resultado.
4. Registrar pergunta, hipótese, método, observação, evidência, erro e lição.
5. Medir precisão de citações, recall, taxa de alucinação, tempo e tokens.

## Memória
Ra/Osiris encerrados em 17/10/2026: 3/3 flags, 100%. Não reativar a instância anterior.
Workspace histórico privado: /home/nielz/mitr3-private-restore/current
Novos engajamentos usam novos boards/workspaces; histórico e secrets não são copiados para RAG.
Biblioteca: /home/nielz/Documents/MegaBrain-OSINT4ALL
MCPs: megabrain, mitr3-nexus, rea, chrome-devtools, playwright, context7, apisec-ng.
Nexus recuperado: runtime novo com 10 tools, baseado em código do chat anterior; integração IDA/Ghidra headless ainda não testada e análise nativa limitada.

## Ambiente operacional (2026-10-19)

Host Arch Linux, root liberado para o squad. Raiz de trabalho: `~/MITR3/`.

- `bin/mitr3-health.sh [--json]` — inventário e saúde do host, 42 ferramentas verificadas.
- `bin/new-case.sh <nome> [purpose]` — scaffold de engajamento (case.md, evidence/, logs/, report.md).
- `docs/SCOPE.md` — contrato humano do Nexus, por artefato e SHA256, assinado no TTY.
- `docs/TOOLCHAIN.md`, `docs/RE-VALIDATION.md`, `docs/WEBAPI-VALIDATION.md`, `docs/OSINT-PLAYBOOK.md`.

Ferramentas: Ghidra 12.1.2 (+headless), r2 6.2.2, rizin 0.8.2, jadx 1.5.6, apktool 3.0.3, gdb 18.1,
frida, pwntools, ropper, checksec, impacket, AFL++, upx, trivy, semgrep, osv-scanner, nuclei,
httpx, subfinder, ffuf, katana, dnsx, gau, amass, chisel, mitmproxy, nmap, masscan, sqlmap,
msf, hashcat, john, hydra, gh, docker, playwright chromium.

MCPs: megabrain (HTTP), rea (209 tools), mitr3-nexus, context7, chrome-devtools (Brave),
playwright, apisec-ng (token corrigido, `secbolt:` removido).

Lacunas conhecidas: IDA Pro (sem licença), Burp Suite (proprietário, baixar do PortSwigger),
CodeQL local (bundle com gate de licença; MegaBrain remoto já tem 2.27.2).
