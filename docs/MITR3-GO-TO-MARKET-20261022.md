# MITR3 — Plano comercial e website (v1, 22/10/2026)

**Estado:** plano inicial + protótipo local. Não há contratos, recompensas, certificações, clientes ou resultados comerciais presumidos. **Não publicar o site sem revisar identidade, contato, provas e políticas.**

## Objetivo
Transformar pesquisa e infraestrutura do MITR3 em receita recorrente de serviços legítimos, enquanto desenvolvemos reputação por bug bounties elegíveis. Prioridade: **primeiro contrato pequeno com boa entrega e autorização escrita**; hardware de 32 GB depois de receita líquida reservada.

## Posicionamento
- Nome comercial provisório: **MITR3 | Segurança Ofensiva & Engenharia**, iniciativa por NielzSec (confirmar identidade jurídica e registro da marca).
- Mensagem central: **Segurança ofensiva que termina em correção.**
- Cliente ideal inicial: pequenas SaaS, e-commerces, agências que desenvolvem sistemas, fintechs em MVP, fornecedores de software B2B. Iniciar por empresas com proprietário técnico e ciclo de contratação curto.
- Diferencial: testes orientados a hipóteses e evidência reprodutível, engenharia reversa, revisão de código e segurança de APIs; MegaBrain/LLMs ajudam a pesquisar, mas achados são validados humanamente. Não usar nomes de ferramentas como substituto de qualidade.
- Não divulgar alvos, chaves, prompts internos, credenciais, identificadores dos clientes, vulnerabilidades não corrigidas ou conteúdo de programas privados.

## Catálogo inicial (valores de planejamento interno, não promessas públicas)
| Oferta | Escopo / entregável | Prazo de referência* | Hipótese de preço inicial* |
|---|---|---|---|
| Diagnóstico de segurança orientativo | Entrevista técnica + revisão autorizada de configuração/código fornecidos + riscos priorizados. **Não chamar de pentest**. | 2–4 dias | R$ 700–1.800 |
| Revisão focada de código/API | Até N endpoints/caminhos combinados, controles de autorização, autenticação, validação e lógica de negócio; matriz de testes e correções. | 5–8 dias | R$ 2.500–5.500 |
| Pentest web/API delimitado | Aplicação e ambientes listados em RoE, validação manual controlada, evidências sanitizadas, CVSS quando aplicável, sumário executivo e 1 reteste das falhas altas/críticas. | 8–15 dias | R$ 5.000–12.000 |
| Hardening/DevSecOps sprint | SAST/SCA/CodeQL, revisão CI/CD, segredos, permissões, infraestrutura básica e plano de remediação. | 3–7 dias | sob proposta |
| Reteste/autorização pós-correção | Verificação somente dos achados acordados. | 1–3 dias | incluso em ofertas definidas ou orçamento |

*Hipóteses de entrada a calibrar conforme escopo e capacidade real; preço e prazo sempre aprovados por proposta. Referências públicas de mercado mostram enorme dispersão. Não prometer certificação de conformidade nem cobertura total.

## Trilha de bug bounty — renda variável e reputação
- Priorizar HackerOne e Bugcrowd: programas públicos ativos que **oferecem recompensa** (não confundir VDP com bounty pago), escopo claro e autorização da política vigente.
- Selecionar no máximo **2 programas por ciclo de 14 dias**, preferindo tecnologia dominada pelo MITR3 (Web, API, authz, business logic). Considerar tempo de resposta e duplicatas conhecidas.
- Antes de cada ação: registrar versão/timestamp das regras, ativos in-scope, tipos proibidos, limites de taxa, contas de teste e condições de colaboração.
- Operar manualmente onde exigido; testes de concorrência, scraping, automação, ataques em massa e dados de terceiros somente se explicitamente permitidos. Em dúvida, parar e solicitar esclarecimento ao programa.
- Pipeline: hipótese -> QA de escopo -> teste controlado -> impacto com dados sintéticos -> PoC mínima -> revisão JEV/humana -> relatório reproduzível -> submissão -> triagem -> reteste quando solicitado.
- Métricas semanais: horas investidas, programas avaliados, hipóteses qualificadas, evidências confiáveis, relatórios aceitos, duplicatas, recompensas líquidas. **Zero previsão garantida de payout**.
- Estudos de caso públicos exclusivamente de labs próprios ou disclosures autorizadas e sanitizadas.

## Prospecção comercial sem invasão não autorizada
- Landing page + GitHub profissional + 2 relatórios demonstrativos em laboratório: (a) controle de acesso BOLA em API mockada; (b) revisão de fluxo login/reset em app de treinamento.
- Prospectar **10–15 contatos qualificados/semana** via canais profissionais, relacionamento com desenvolvedores/agências e comunidades. Evitar spam automatizado.
- Primeira mensagem: conversar sobre maturidade de segurança e oferecer conversa de 15 min; **não afirmar que a empresa tem vulnerabilidade sem autorização para testar**.
- Funil: prospect -> discovery -> NDA se necessário -> escopo e RoE -> proposta -> contrato -> execução autorizada -> relatório -> apresentação -> reteste -> feedback público se permitido.
- Trabalhos iniciais preferencialmente pequenos, contrato de escopo fechado, sinal condicionado ao acordo e cronograma realista.

## Documentos comerciais a preparar
1. Proposta comercial com objetivo, escopo, fora de escopo, premissas, preço, datas, entregáveis, reteste e critérios de aceite.
2. Contrato revisado por profissional com autorização expressa do proprietário dos ativos, RoE, janelas, contatos de emergência, limite de carga, interrupção imediata, confidencialidade/NDA, responsabilidade e pagamento.
3. Política de manuseio de evidências: criptografia, acesso restrito, retenção mínima, exclusão ao final, consentimento para publicação.
4. Modelo de relatório: resumo executivo, metodologia OWASP WSTG, achados com impacto, severidade, reproduções com dados sintéticos, correções e reteste.
5. Política LGPD do website com finalidade e base de tratamento para leads, prazo de retenção, canal de direitos; não coletar credenciais ou dados sensíveis no formulário.
6. Formalização fiscal, emissão de notas e obrigações avaliadas com contador antes das primeiras propostas pagas.

## Website — decisão de produto
- Objetivo único do MVP: transformar visita em **pedido de avaliação de escopo**.
- Estrutura: hero com proposta de valor -> 3 serviços -> método -> diferenciais honestos -> demonstrações com labs -> FAQ -> contato/call-to-action -> políticas.
- Design: escuro sóbrio, creme e cobre, tipografia forte, sem hologramas genéricos, sem contadores de clientes fictícios ou depoimentos inventados.
- Tech: HTML/CSS/JS estáticos, sem dependências e sem rastreadores; hospedagem potencial em Cloudflare Pages (custo de assets estáticos gratuito sob limites de plano). Contato definitivo por Pages Functions/Worker com validação server-side do Turnstile, rate limiting, armazenamento mínimo e política de privacidade.
- Segurança de deploy: domínio registrado e DNS revisado, HTTPS, CSP por cabeçalho compatível com scripts externos, Referrer-Policy, X-Content-Type-Options, formulários com honeypot, Turnstile e validação de entrada, segredo somente no backend, logs sem dados de clientes.
- Protótipo em `~/Documents/MITR3-WEB/site/` funciona offline. O formulário de protótipo **apenas gera um briefing TXT local**, não envia dados; proteger leads com backend somente após aprovar endereço de contato/domínio.
- Publicar somente após validação do usuário e preenchimento de canal de contato verdadeiro, identidade/razão social e política de privacidade.

## Plano 0–90 dias
| Horizonte | Execução | Meta operacional (não garantia) |
|---|---|---|
| Semana 1 | Definir marca e escopo de serviços; revisar website MVP; publicar 1 case sintético e 1 relatório exemplo; preparar propostas e RoE | Site pronto para avaliação; materiais revisados |
| Semana 2 | Completar canal de contato, domínio e deploy; montar pipeline CRM simples e 15 leads; 2 programas bounty em avaliação | 10 conversas iniciadas; 2 calls propostas |
| Semanas 3–4 | Fazer discovery, enviar 2–4 propostas qualificadas, concluir 1 case de lab com evidência e investigar programas conforme regras | Primeiro piloto **possível**, sem receita presumida |
| Mês 2 | Ajustar oferta conforme objeções, parcerias com dev agencies, refinar QA interno e revisão cruzada, continuar bounty | Portfólio demonstrável, conversão medida |
| Mês 3 | Retenção, reteste, indicação e possível plano mensal de acompanhamento com SLO explícito | Receita repetível como objetivo |

## Finanças e upgrade de hardware
- Exemplo de cenário **hipotético**, não receita prevista: 2 revisões focadas a R$ 3.000 = R$ 6.000 brutos, antes de impostos, tarifas, ferramentas e horas.
- Criar caixa separado: obrigações e impostos (estimados com contador); infraestrutura; reserva; reinvestimento/hardware. Não gastar payout pendente.
- **Inventário real do host (22/10/2026):** ASUS PRIME H510M-E, i5-10400F, 1 DIMM ADATA 16 GiB DDR4-3000 configurado a 2666 MT/s e 1 slot livre. DMI/BIOS v1017 reporta máximo de 32 GiB, enquanto a ficha ASUS da placa declara 64 GB (2 slots); conferir atualização de BIOS/QVL e compatibilidade antes de assumir 48/64 GB. Melhor caminho conservador: acrescentar módulo DDR4 de 16 GB compatível e atingir **32 GB totais**. Comprar 1x32 GB adicionais para obter 48 GB exigiria validação extra e pode não ser reconhecido na configuração atual. Atualizar memória não resolve processos MCP duplicados por si só.

## Fontes e pontos de conferência (22/10/2026)
- OWASP WSTG: https://wstg.owasp.org/latest/2-Introduction/
- OWASP Reporting: https://wstg.owasp.org/latest/5-Reporting/01-Reporting_Structure/
- HackerOne opportunities e bounty: https://hackerone.com/opportunities/all
- Bugcrowd escopo: https://docs.bugcrowd.com/researchers/participating-in-program/reviewing-bounty-briefs/
- Bugcrowd recompensas: https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/
- ANPD segurança para pequenos negócios: https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/guia-orientativo-sobre-seguranca-da-informacao-para-agentes-de-tratamento-de-pequeno-porte
- Cloudflare Pages Functions/preços: https://developers.cloudflare.com/pages/functions/pricing/
- Cloudflare Turnstile server-side: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

## Próximo gate
1) aprovar nome de exibição "MITR3 | NielzSec"; 2) selecionar domínio; 3) definir canal público de contato sem colar segredos; 4) selecionar 2 labs demonstrativos; 5) revisão legal/políticas e publicação.
