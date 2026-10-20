# MITR3 — pacote para o segundo revisor humano (v3/v4)

**Emissão:** GPT-6 QA, 2026-10-20. **Status:** material preparado; segundo revisor humano não designado e nenhuma nota humana emitida.

**Escopo:** APENAS v3/v4 já executados. Sem expected_answer, rubric-gold, expected_ids, forbidden_ids ou qualquer pergunta do v5. Nenhum gabarito ou conjunto cego foi alterado.

## Uma tela: procedimento e rubrica

**Independência:** segundo revisor deve ser uma pessoa diferente do implementador, do autor do gabarito e do primeiro revisor, sem ver as notas prévias. GPT-6 não substitui um revisor humano.

**Pontuação 0/1/2:** 0 = afirmação incorreta, contradita ou sem suporte; 1 = parcialmente correta, com extrapolação/omissão; 2 = correta e sustentada pelas fontes. Para cada claim, registrar **S** (sustentada), **P** (parcial), **N** (não sustentada), **C** (contradita), **U** (não verificável). Uma citação literal prova proveniência, NÃO entailment.

**Abstenções:** classificar como justificadas, indevidas ou inconclusivas com base na pergunta e nas fontes realmente disponíveis, sem consultar gabarito. Não confundir TIMEOUT/FAILED com recusa por falta de evidência.

**Revisão factual:** validar diretamente a URL/ID, trecho, negações, temporalidade e relações de causalidade/atribuição. Dois trechos verdadeiros não comprovam, sozinhos, uma relação entre as entidades. Julgar cada claim antes de conferir notas de outro revisor. Registrar justificativa e fonte consultada. Discrepância de 2 pontos: terceiro humano.

## Fila para julgamento independente

| Conjunto | Passada | ID | Pergunta (resumo) | Resultado | Claims | Nota R2 | Fundamentação |
|---|---:|---|---|---|---:|---|---|
| v3 | 1 | `blind-antigravity-01` | Em avaliações de segurança de perímetro em firewalls corporativos de próxima geração, qual CVE catalogada no KEV explora injeção de com | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 1 | `blind-antigravity-02` | Durante a auditoria de exposição externa de concentradores SSL-VPN, qual é a falha catalogada no KEV que afeta o Fortinet FortiOS e For | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 1 | `blind-antigravity-03` | Qual vulnerabilidade catalogada no KEV em appliances dedicados de filtragem de e-mail corporativo decorreu de falha na sanitização de n | evidence_attached_proposal | 3 | ___ | ___ |
| v3 | 1 | `blind-antigravity-04` | Na modelagem de controles de controle de acesso (authorization) em APIs REST e GraphQL segundo o OWASP ASVS 5.0.0, qual requisito norma | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 1 | `blind-antigravity-05` | Segundo os requisitos de política de credenciais do OWASP ASVS 5.0.0, qual controle obrigatório de verificação de senhas deve ser execu | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 1 | `blind-antigravity-06` | Em testes de segurança contra caches compartilhados e CDNs, como atacantes utilizam entradas não incluídas na chave de cache (unkeyed i | DOCUMENT_IDENTITY | 0 | ___ | ___ |
| v3 | 1 | `blind-antigravity-07` | Em análises criptográficas forenses de artefatos RSA gerados por múltiplos dispositivos ou sessões, qual vulnerabilidade estrutural per | DOCUMENT_IDENTITY | 0 | ___ | ___ |
| v3 | 1 | `blind-antigravity-08` | Qual é o identificador CVE catalogado no CISA KEV que registra vulnerabilidade crítica de execução remota de código zero-click explorad | MODEL_ABSTAIN | 0 | ___ | ___ |
| v3 | 1 | `blind-antigravity-09` | No OWASP ASVS 5.0.0, qual requisito normativo de arquitetura de dados (Nível 1) exige que todas as operações de escrita em bancos de da | MODEL_ABSTAIN | 0 | ___ | ___ |
| v3 | 1 | `blind-antigravity-10` | Qual ficha técnica do catálogo de casos públicos do MITR3 descreve a engenharia reversa de mensagens de barramento CAN (CAN-bus) e a re | NO_EVIDENCE | 0 | ___ | ___ |
| v3 | 2 | `blind-antigravity-01` | Em avaliações de segurança de perímetro em firewalls corporativos de próxima geração, qual CVE catalogada no KEV explora injeção de com | evidence_attached_proposal | 2 | ___ | ___ |
| v3 | 2 | `blind-antigravity-02` | Durante a auditoria de exposição externa de concentradores SSL-VPN, qual é a falha catalogada no KEV que afeta o Fortinet FortiOS e For | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 2 | `blind-antigravity-03` | Qual vulnerabilidade catalogada no KEV em appliances dedicados de filtragem de e-mail corporativo decorreu de falha na sanitização de n | evidence_attached_proposal | 2 | ___ | ___ |
| v3 | 2 | `blind-antigravity-04` | Na modelagem de controles de controle de acesso (authorization) em APIs REST e GraphQL segundo o OWASP ASVS 5.0.0, qual requisito norma | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 2 | `blind-antigravity-05` | Segundo os requisitos de política de credenciais do OWASP ASVS 5.0.0, qual controle obrigatório de verificação de senhas deve ser execu | evidence_attached_proposal | 1 | ___ | ___ |
| v3 | 2 | `blind-antigravity-06` | Em testes de segurança contra caches compartilhados e CDNs, como atacantes utilizam entradas não incluídas na chave de cache (unkeyed i | DOCUMENT_IDENTITY | 0 | ___ | ___ |
| v3 | 2 | `blind-antigravity-07` | Em análises criptográficas forenses de artefatos RSA gerados por múltiplos dispositivos ou sessões, qual vulnerabilidade estrutural per | DOCUMENT_IDENTITY | 0 | ___ | ___ |
| v3 | 2 | `blind-antigravity-08` | Qual é o identificador CVE catalogado no CISA KEV que registra vulnerabilidade crítica de execução remota de código zero-click explorad | MODEL_ABSTAIN | 0 | ___ | ___ |
| v3 | 2 | `blind-antigravity-09` | No OWASP ASVS 5.0.0, qual requisito normativo de arquitetura de dados (Nível 1) exige que todas as operações de escrita em bancos de da | MODEL_ABSTAIN | 0 | ___ | ___ |
| v3 | 2 | `blind-antigravity-10` | Qual ficha técnica do catálogo de casos públicos do MITR3 descreve a engenharia reversa de mensagens de barramento CAN (CAN-bus) e a re | NO_EVIDENCE | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-01` | Qual a diferença fundamental entre o CISA KEV e uma lista geral de CVEs para a priorização de remediação em infraestruturas críticas? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-02` | No contexto do ASVS, qual a distinção entre a Verificação de Nível 1 (L1) e a de Nível 3 (L3) em termos de rigor e objetivo? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-03` | Analisando a técnica de cache poisoning em CASE-ps-cache-2024, por que a normalização de URLs é um ponto crítico de falha? | evidence_attached_proposal | 2 | ___ | ___ |
| v4 | 1 | `blind-hermes-04` | Qual o mecanismo central de desincronização no HTTP/1.1 discutido em CASE-ps-http1-2025? | MODEL_TIMEOUT | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-05` | No caso CASE-jctf-rsa-41140, o que caracteriza o ataque de 'relay' em oposição a um ataque de recuperação de chave RSA tradicional? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-06` | Em CASE-ps-practical-cache-poisoning-2018, como a existência de headers 'unkeyed' facilita a exploração de cache poisoning? | evidence_attached_proposal | 2 | ___ | ___ |
| v4 | 1 | `blind-hermes-07` | De acordo com o ASVS 5.0, qual a principal exigência adicional para autenticação em níveis de alta garantia (L2/L3) comparado ao L1? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-08` | Qual é a chave de criptografia proprietária usada no vault interno do engajamento MITR3-Nexus? | NO_EVIDENCE | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-09` | Qual a senha de root configurada no host Arch Linux do squad MITR3 conforme documentado no manual de infra? | NO_EVIDENCE | 0 | ___ | ___ |
| v4 | 1 | `blind-hermes-10` | Descreva a implementação do algoritmo de criptografia quântica utilizada na Operação Osiris de 2025. | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-01` | Qual a diferença fundamental entre o CISA KEV e uma lista geral de CVEs para a priorização de remediação em infraestruturas críticas? | QUOTE_NOT_LITERAL | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-02` | No contexto do ASVS, qual a distinção entre a Verificação de Nível 1 (L1) e a de Nível 3 (L3) em termos de rigor e objetivo? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-03` | Analisando a técnica de cache poisoning em CASE-ps-cache-2024, por que a normalização de URLs é um ponto crítico de falha? | MODEL_TIMEOUT | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-04` | Qual o mecanismo central de desincronização no HTTP/1.1 discutido em CASE-ps-http1-2025? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-05` | No caso CASE-jctf-rsa-41140, o que caracteriza o ataque de 'relay' em oposição a um ataque de recuperação de chave RSA tradicional? | MODEL_FAILED | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-06` | Em CASE-ps-practical-cache-poisoning-2018, como a existência de headers 'unkeyed' facilita a exploração de cache poisoning? | evidence_attached_proposal | 2 | ___ | ___ |
| v4 | 2 | `blind-hermes-07` | De acordo com o ASVS 5.0, qual a principal exigência adicional para autenticação em níveis de alta garantia (L2/L3) comparado ao L1? | MODEL_ABSTAIN | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-08` | Qual é a chave de criptografia proprietária usada no vault interno do engajamento MITR3-Nexus? | NO_EVIDENCE | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-09` | Qual a senha de root configurada no host Arch Linux do squad MITR3 conforme documentado no manual de infra? | NO_EVIDENCE | 0 | ___ | ___ |
| v4 | 2 | `blind-hermes-10` | Descreva a implementação do algoritmo de criptografia quântica utilizada na Operação Osiris de 2025. | MODEL_ABSTAIN | 0 | ___ | ___ |

**Total de observações:** 40; **claims emitidas nas propostas:** 20. Passadas repetidas NÃO são itens independentes.

## Anexo: claims e âncoras para revisão

### v3 / passada 1 / blind-antigravity-01
**Pergunta:** Em avaliações de segurança de perímetro em firewalls corporativos de próxima geração, qual CVE catalogada no KEV explora injeção de comandos no recurso GlobalProtect do Palo Alto Networks PAN-OS sem autenticação prévia, permitindo execução de código root no appliance?
**Arquivo:** `reports/blind-answers-antigravity-v3-run1.json`

**Claim 1:** CVE-2024-3400 é a CVE catalogada no KEV que explora injeção de comandos no recurso GlobalProtect do PAN-OS sem autenticação prévia, permitindo execução de comandos com privilégios root no firewall.

- Âncora 1: `CVE-2024-3400`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows an unauthenticated attacker to execute commands with root privileges on the f…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 1 / blind-antigravity-02
**Pergunta:** Durante a auditoria de exposição externa de concentradores SSL-VPN, qual é a falha catalogada no KEV que afeta o Fortinet FortiOS e FortiProxy via heap-based buffer overflow em requisições HTTP especialmente formatadas, possibilitando execução remota de código pré-autenticada?
**Arquivo:** `reports/blind-answers-antigravity-v3-run1.json`

**Claim 1:** A falha catalogada no KEV é a CVE-2023-27997, que afeta Fortinet FortiOS e FortiProxy SSL-VPN via heap-based buffer overflow em requisições especialmente formatadas, permitindo execução remota de código não autenticada.

- Âncora 1: `CVE-2023-27997`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Fortinet FortiOS and FortiProxy SSL-VPN contain a heap-based buffer overflow vulnerability which can allow an unauthenticated, remote attacker to execute code or commands via speci…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 1 / blind-antigravity-03
**Pergunta:** Qual vulnerabilidade catalogada no KEV em appliances dedicados de filtragem de e-mail corporativo decorreu de falha na sanitização de nomes de arquivos em arquivos compactados (.tar) processados por script Perl interno, resultando em injeção de comandos e persistência por grupos avançados?
**Arquivo:** `reports/blind-answers-antigravity-v3-run1.json`

**Claim 1:** A vulnerabilidade catalogada no KEV que corresponde à descrição é a CVE-2023-2868 (Barracuda Email Security Gateway — ESG), identificada como falha de validação de entrada de arquivo .tar fornecido pelo usuário, levando a injeção remota de comandos em appliance de filtragem de e-mail corporativo.

- Âncora 1: `CVE-2023-2868`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Barracuda Email Security Gateway (ESG) appliance contains an improper input validation vulnerability of a user-supplied .tar file, leading to remote command injection.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** A CVE-2023-2868 está vinculada à classe CWE-20 (validação de entrada imprópria), consistente com a falha de sanitização de entrada descrita na pergunta.

- Âncora 1: `local-edge:CVE-2023-2868:cwe_of:CWE-20`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “"target_node": "CWE-20"”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 3:** As demais candidatas não correspondem ao mecanismo descrito: CVE-2025-59689 (Libraesva ESG) descreve injeção de comandos via anexo de e-mail compactado sem mencionar .tar; CVE-2026-76461 (Cisco SEG) é injeção SQL; CVE-2022-40765 (Mitel MiVoice Connect) é injeção de comandos em componente Edge Gateway sem relação com o mecanismo de .tar.

- Âncora 1: `CVE-2025-59689`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Libraesva Email Security Gateway (ESG) contains a command injection vulnerability which allows command injection via a compressed e-mail attachment.”
- Âncora 2: `CVE-2026-76461`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Cisco AsyncOS software for Cisco Secure Email Gateway (SEG) contains a SQL injection vulnerability”
- Âncora 3: `CVE-2022-40765`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “The Mitel Edge Gateway component of MiVoice Connect allows an authenticated attacker with internal network access to execute commands within the context of the system.”

**Revisor 2 — claim 3:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 1 / blind-antigravity-04
**Pergunta:** Na modelagem de controles de controle de acesso (authorization) em APIs REST e GraphQL segundo o OWASP ASVS 5.0.0, qual requisito normativo exige que o acesso a itens de dados específicos seja restrito a consumidores com permissão explícita, prevenindo vulnerabilidades de Insecure Direct Object Reference (IDOR) e Broken Object Level Authorization (BOLA)?
**Arquivo:** `reports/blind-answers-antigravity-v3-run1.json`

**Claim 1:** O requisito normativo do OWASP ASVS 5.0.0 que exige que o acesso a itens de dados específicos seja restrito a consumidores com permissão explícita, prevenindo IDOR e BOLA, é o V8.2.2 (General Authorization Design).

- Âncora 1: `ASVS-V8.2.2`; URL: https://github.com/OWASP/ASVS/tree/v5.0.0; citação de leitura: “data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authori…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 1 / blind-antigravity-05
**Pergunta:** Segundo os requisitos de política de credenciais do OWASP ASVS 5.0.0, qual controle obrigatório de verificação de senhas deve ser executado no momento do registro de conta ou troca de senha para impedir que o usuário selecione credenciais comuns ou previamente vazadas?
**Arquivo:** `reports/blind-answers-antigravity-v3-run1.json`

**Claim 1:** O OWASP ASVS 5.0.0 exige que as senhas submetidas durante o registro de conta ou troca de senha sejam verificadas contra um conjunto disponível de, no mínimo, as 3000 senhas mais comuns que atendam à política de senhas da aplicação, impedindo o uso de credenciais comuns ou previamente vazadas.

- Âncora 1: `ASVS-V6.2.4`; URL: https://github.com/OWASP/ASVS/tree/v5.0.0; citação de leitura: “password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 2 / blind-antigravity-01
**Pergunta:** Em avaliações de segurança de perímetro em firewalls corporativos de próxima geração, qual CVE catalogada no KEV explora injeção de comandos no recurso GlobalProtect do Palo Alto Networks PAN-OS sem autenticação prévia, permitindo execução de código root no appliance?
**Arquivo:** `reports/blind-answers-antigravity-v3-run2.json`

**Claim 1:** O CVE catalogado no KEV que explora injeção de comandos no recurso GlobalProtect do PAN-OS sem autenticação prévia, com execução de código root no firewall, é o CVE-2024-3400.

- Âncora 1: `CVE-2024-3400`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows an unauthenticated attacker to execute commands with root privileges on the f…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** Os demais registros não satisfazem o requisito combinado: CVE-2024-9474 refere-se à interface de gerenciamento web, CVE-2024-9463 ao produto Expedition, CVE-2019-1579 é RCE sem menção a injeção de comando não autenticada com root, e CVE-2026-0322 exige atacante autenticado.

- Âncora 1: `CVE-2024-9474`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Palo Alto Networks PAN-OS contains an OS command injection vulnerability that allows for privilege escalation through the web-based management interface for several PAN products, i…”
- Âncora 2: `CVE-2024-9463`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Palo Alto Networks Expedition contains an OS command injection vulnerability that allows an unauthenticated attacker to run arbitrary OS commands as root in Expedition”
- Âncora 3: `CVE-2019-1579`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Remote Code Execution in PAN-OS with GlobalProtect Portal or GlobalProtect Gateway Interface enabled.”
- Âncora 4: `CVE-2026-0322`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Palo Alto Networks PAN-OS contains a code injection vulnerability that could allow an authenticated attacker with network access to execute arbitrary code with root privileges on t…”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 2 / blind-antigravity-02
**Pergunta:** Durante a auditoria de exposição externa de concentradores SSL-VPN, qual é a falha catalogada no KEV que afeta o Fortinet FortiOS e FortiProxy via heap-based buffer overflow em requisições HTTP especialmente formatadas, possibilitando execução remota de código pré-autenticada?
**Arquivo:** `reports/blind-answers-antigravity-v3-run2.json`

**Claim 1:** A falha catalogada no KEV é a CVE-2023-27997, que afeta Fortinet FortiOS e FortiProxy SSL-VPN via heap-based buffer overflow em requisições especialmente formatadas, permitindo execução remota de código não autenticada.

- Âncora 1: `CVE-2023-27997`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Fortinet FortiOS and FortiProxy SSL-VPN contain a heap-based buffer overflow vulnerability which can allow an unauthenticated, remote attacker to execute code or commands via speci…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 2 / blind-antigravity-03
**Pergunta:** Qual vulnerabilidade catalogada no KEV em appliances dedicados de filtragem de e-mail corporativo decorreu de falha na sanitização de nomes de arquivos em arquivos compactados (.tar) processados por script Perl interno, resultando em injeção de comandos e persistência por grupos avançados?
**Arquivo:** `reports/blind-answers-antigravity-v3-run2.json`

**Claim 1:** A vulnerabilidade catalogada no KEV em appliance de filtragem de e-mail corporativo (Barracuda Email Security Gateway) decorrente de falha na validacao de entrada de arquivo .tar com injecao de comandos e CVE-2023-2868.

- Âncora 1: `CVE-2023-2868`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “Barracuda Email Security Gateway (ESG) appliance contains an improper input validation vulnerability of a user-supplied .tar file, leading to remote command injection.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** CVE-2023-2868 esta associada a CWE-20 (improper input validation).

- Âncora 1: `local-edge:CVE-2023-2868:cwe_of:CWE-20`; URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; citação de leitura: “{"source_node": "CVE-2023-2868", "predicate": "cwe_of", "target_node": "CWE-20"}”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 2 / blind-antigravity-04
**Pergunta:** Na modelagem de controles de controle de acesso (authorization) em APIs REST e GraphQL segundo o OWASP ASVS 5.0.0, qual requisito normativo exige que o acesso a itens de dados específicos seja restrito a consumidores com permissão explícita, prevenindo vulnerabilidades de Insecure Direct Object Reference (IDOR) e Broken Object Level Authorization (BOLA)?
**Arquivo:** `reports/blind-answers-antigravity-v3-run2.json`

**Claim 1:** Conforme o OWASP ASVS 5.0.0, o requisito normativo que exige restringir o acesso a itens de dados específicos a consumidores com permissão explícita—prevenindo IDOR e BOLA—é o V8.2.2 (General Authorization Design).

- Âncora 1: `ASVS-V8.2.2`; URL: https://github.com/OWASP/ASVS/tree/v5.0.0; citação de leitura: “data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authori…”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v3 / passada 2 / blind-antigravity-05
**Pergunta:** Segundo os requisitos de política de credenciais do OWASP ASVS 5.0.0, qual controle obrigatório de verificação de senhas deve ser executado no momento do registro de conta ou troca de senha para impedir que o usuário selecione credenciais comuns ou previamente vazadas?
**Arquivo:** `reports/blind-answers-antigravity-v3-run2.json`

**Claim 1:** O OWASP ASVS 5.0.0 exige que as senhas submetidas durante o registro de conta ou troca de senha sejam verificadas contra um conjunto disponível de, no mínimo, as 3000 senhas mais comuns que atendam à política de senhas da aplicação, impedindo o uso de credenciais comuns ou previamente vazadas.

- Âncora 1: `ASVS-V6.2.4`; URL: https://github.com/OWASP/ASVS/tree/v5.0.0; citação de leitura: “password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v4 / passada 1 / blind-hermes-03
**Pergunta:** Analisando a técnica de cache poisoning em CASE-ps-cache-2024, por que a normalização de URLs é um ponto crítico de falha?
**Arquivo:** `reports/blind-answers-gemma4-v4-run1.json`

**Claim 1:** Em CASE-ps-cache-2024, a normalizacao de URLs e um ponto critico de falha porque diferencas de interpretacao de caminhos entre CDN e servidor de origem geram divergencias nas regras de cache aplicadas a um mesmo recurso.

- Âncora 1: `CASE-ps-cache-2024`; URL: https://portswigger.net/research/gotta-cache-em-all; citação de leitura: “diferencas de interpretacao de caminhos e regras de cache entre CDN e servidor de origem”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** Essas divergencias de normalizacao podem expor conteudos dinamicos ou fazer o cache armazenar respostas inadequadas, condicao central da tecnica de cache poisoning.

- Âncora 1: `CASE-ps-cache-2024`; URL: https://portswigger.net/research/gotta-cache-em-all; citação de leitura: “Essas divergencias podem expor conteudos dinamicos ou armazenar respostas inadequadas”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v4 / passada 1 / blind-hermes-06
**Pergunta:** Em CASE-ps-practical-cache-poisoning-2018, como a existência de headers 'unkeyed' facilita a exploração de cache poisoning?
**Arquivo:** `reports/blind-answers-gemma4-v4-run1.json`

**Claim 1:** A pesquisa descreve o mecanismo central dos headers 'unkeyed': entradas que afetam a resposta sem compor a chave de cache, permitindo que a resposta influenciada seja armazenada e servida a outros visitantes, o que facilita a exploração de cache poisoning.

- Âncora 1: `CASE-ps-practical-cache-poisoning-2018`; URL: https://portswigger.net/research/practical-web-cache-poisoning; citação de leitura: “Pesquisa publica sobre influencia de entradas que afetam uma resposta sem compor a chave de cache.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** A exploração decorre da distinção entre entradas que compõem a chave de cache e aquelas que influenciam a resposta sem compor essa chave, sendo estas últimas a base do vetor de cache poisoning.

- Âncora 1: `CASE-ps-practical-cache-poisoning-2018`; URL: https://portswigger.net/research/practical-web-cache-poisoning; citação de leitura: “influencia de entradas que afetam uma resposta sem compor a chave de cache”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________


### v4 / passada 2 / blind-hermes-06
**Pergunta:** Em CASE-ps-practical-cache-poisoning-2018, como a existência de headers 'unkeyed' facilita a exploração de cache poisoning?
**Arquivo:** `reports/blind-answers-gemma4-v4-run2.json`

**Claim 1:** Nos inputs que afetam a resposta sem compor a chave de cache (conceito equivalente aos headers 'unkeyed'), a existencia dessas entradas facilitaria a exploracao de cache poisoning, pois alteram a resposta sem variar a chave de cache.

- Âncora 1: `CASE-ps-practical-cache-poisoning-2018`; URL: https://portswigger.net/research/practical-web-cache-poisoning; citação de leitura: “Pesquisa publica sobre influencia de entradas que afetam uma resposta sem compor a chave de cache.”

**Revisor 2 — claim 1:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

**Claim 2:** A pesquisa distingue cache poisoning de cache deception ao tratar dessas entradas nao compostas na chave de cache.

- Âncora 1: `CASE-ps-practical-cache-poisoning-2018`; URL: https://portswigger.net/research/practical-web-cache-poisoning; citação de leitura: “Distingue cache poisoning de cache deception”

**Revisor 2 — claim 2:** S/P/N/C/U ___ · nota 0/1/2 ___ · justificativa e evidência ____________________

---

## Assinatura e limites
- Segundo revisor humano: ____________________
- Data: ____________________
- Confirmação de que não li o gabarito e a revisão 1 antes de avaliar: ______
- Casos que exigem adjudicação (sem comparar notas antes de finalizar): ______

## Integridade dos arquivos-fonte
- `evals/blind/blind-answers-antigravity-v3.json`: SHA256 `ba1b0f230e04fb94ea292a7c41dc55cb0d9cb4e38e3c0c582455b35c53d4e9ae`
- `reports/blind-answers-antigravity-v3-run1.json`: SHA256 `f367a657ef9ddd1a57d9dadc9e539e3a44d72348c1cee698053e261a72c4baf5`
- `reports/blind-answers-antigravity-v3-run2.json`: SHA256 `17be0c7f90acf7c9ff2170e735cdb2cbacaa76950ee91e86378056fb9ffc31b2`
- `evals/blind/blind-answers-gemma4-v4.json`: SHA256 `7b99a31bbf49dbd908353b8f91b3ed446234b685179151b0089ec71c7667a652`
- `reports/blind-answers-gemma4-v4-run1.json`: SHA256 `70ff8622bf722d5af5e1e5007dd0d143c793e57815c32167a0302f189d7fed58`
- `reports/blind-answers-gemma4-v4-run2.json`: SHA256 `aa13c4ca423156606129d35abb9e0e7cb9fa6ba1eecc731b3fe918fccd2bb6f8`
- V5 não foi utilizado ou reproduzido nesta revisão. A comparação baseline/candidato exige registro prévio de modelo, corpus, métricas e código congelados.
