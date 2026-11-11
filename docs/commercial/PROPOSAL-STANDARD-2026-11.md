# PROPOSTA TÉCNICA E COMERCIAL DE SERVIÇOS DE SEGURANÇA DA INFORMAÇÃO

**Cliente:** [Nome da Empresa Contratante / Razão Social]  
**Aos cuidados de:** [Nome do Decisor / Cargo / E-mail]  
**Data da Emissão:** 11 de Novembro de 2026  
**Validade da Proposta:** 15 (quinze) dias  
**Emissor:** MITR3 Security & Intelligence Squad  
**Referência:** Avaliação de Segurança Ofensiva Black-Box — Pacote Standard

---

## 1. Sumário Executivo

A **MITR3** apresenta à **[CONTRATANTE]** esta proposta comercial e técnica para execução de **Auditoria de Superfície Externa de Ataque e Segurança de Aplicações Web e APIs**.

O objetivo do serviço é identificar, correlacionar e reportar vulnerabilidades, exposições de telemetria e falhas de configuração em ativos voltados para a internet pública, prevenindo vazamentos de dados, interrupções operacionais e penalidades da **LGPD (Lei Geral de Proteção de Dados)**.

---

## 2. Metodologia de Avaliação e Regras de Engajamento (RoE)

Nossa metodologia combina inteligência artificial especializada, ferramentas de engenharia reversa e análise de conformidade internacional (**OWASP ASVS 5.0**, **WSTG**, **NIST SP 800-115** e **API Security Best Practices**):

1. **Abordagem Black-Box Não-Destrutiva**: Simula a visão de um atacante externo não autenticado, sem causar impacto na disponibilidade dos serviços.
2. **Ausência Total de Ataques de Negação de Serviço (DoS/DDoS)**: É expressamente proibida qualquer ação que vise sobrecarregar a infraestrutura da Contratante.
3. **Custódia Rigorosa de Evidências**: Cada vulnerabilidade identificada é acompanhada de hash criptográfico SHA-256 e passos de reprodução, sem exfiltração de dados pessoais reais de clientes.
4. **Metodologia APIsec**: Avaliação estruturada de endpoints REST/GraphQL seguindo o OWASP API Security Top 10.

---

## 3. Escopo Autorizado — Pacote Standard

Os testes serão restritos unicamente aos ativos listados formalmente pela Contratante:

**Aplicações Web (até 5 URLs/direórios):**
- `[domínio principal e até 4 subdomínios ou caminhos específicos]`

**APIs REST/GraphQL (até 5 endpoints base ou grupos):**
- `[api.exemplo.com.br]` ou `[https://api.exemplo.com.br/v1]`

**Infraestrutura de Suporte:**
- Certificado TLS/SSL da superfície exposta

**Fora do Escopo:**
- Testes de carga, Dynamic Application Security Testing (DAST) com autenticação ativa, avaliação de código-fonte (SAST), e qualquer ativo não expressamente listado.

---

## 4. Fases de Execução

| Fase | Descrição | Duração Estimada |
| :--- | :--- | :--- |
| **Fase 1: Reconhecimento Passivo & OSINT** | Mapeamento de subdomínios, certificados, vazamentos de credenciais corporativas, fingerprints de tecnologia e enumeração de endpoints públicos. | Dia 1 |
| **Fase 2: Análise de Superfície Web & APIs** | Identificação de endpoints expostos, análise de cabeçalhos de segurança, avaliação de configuração TLS, validação de proteções WAF/Bot, e inspeção de APIs REST/GraphQL quanto ao OWASP API Security Top 10. | Dia 1–Dia 2 |
| **Fase 3: Inspeção de Front-End & JavaScript** | Análise estática de código cliente, busca por chaves de API embutidas, sourcemaps, rotas ocultas e avaliação de vulnerabilidades XSS refle e stored no contexto das aplicações listadas. | Dia 2 |
| **Fase 4: Emissão de Relatório & Reunião de Debrief** | Consolidação dos relatórios Executivo e Técnico, matriz de risco (CVSS 3.1), plano de remediação priorizado e call de debriefing ao vivo. | Dia 3 |

---

## 5. Entregáveis

Ao término do projeto, a Contratante receberá:

1. **Relatório Executivo (Para Diretoria/C-Level)**: Visão de impacto financeiro, riscos operacionais, mapa de calor e rating de maturidade de segurança.
2. **Relatório Técnico Detalhado (Para TI/Dev)**: Instruções práticas passo a passo (PoC reproduzível) para remediação rápida de cada achado.
3. **Declaração de Conformidade & Fechamento**: Atestado de execução e encerramento seguro dos testes.

---

## 6. SLA de Entrega

| Item | Prazo |
| :--- | :--- |
| **Execução completa** | Até 3 dias úteis após aprovação e entrega da lista de ativos |
| **Relatório Preliminar** | Até 24h após conclusão da fase de campo |
| **Call de Debrief** | Agendado em até 5 dias úteis após entrega do relatório |
| **Suporte pós-entrega (esclarecimentos)** | 5 dias úteis contados da data do relatório final |

---

## 7. Investimento e Condições de Pagamento — Pacote Standard

| Item | Detalhe |
| :--- | :--- |
| **Valor Total** | **R$ 3.490,00** (três mil, quatrocentos e noventa reais) |
| **Pagamento** | 50% no aceite da proposta / 50% na entrega do relatório final |
| **Emissão de NF** | Após cada parcela |
| **Validade da Proposta** | 15 dias |

---

## 8. Termo de Aceite e Início

Para aprovação e agendamento da janela de execução, favor retornar esta proposta assinada ou responder ao e-mail comercial com a confirmação expressa de aceite, incluindo a lista final de ativos no escopo.

**Pela Contratante:**  
Nome: ____________________________________________  
Cargo: ___________________________________________  
Data: ____ / ____ / 2026  
Assinatura: ______________________________________  

**Pela MITR3:**  
Coordenação de Operações Ofensivas  
MITR3 Intelligence & Security Squad
