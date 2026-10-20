# MITR3 — Portão A MercadoLibre — parecer GPT-6 QA (FAIL)
Data: 2026-10-20 · Revisão documental somente · Maestro: OpenCode.
**Decisão parcial QA: FAIL**. A emenda exige QA+JEV; este parecer **não** é um PASS conjunto nem autoriza qualquer teste ativo.

## Bases conferidas
- Extrato original da API HackerOne de 25 registros, SHA256 `349db7e29ad9e5a80e5400ee37a2e000c1551925a2bf6e04b378d0d5e298ef81`, armazenado localmente com acesso privado. 22 registros com `eligible_for_bounty=true` e `eligible_for_submission=true`.
- Política obtida da página do programa, SHA256 `74df70a9d27ffc20f5bd450365a9f2a07d6ac50c17e15f48f9b3bdcc3cc1c007`. O texto não fixa QPS/RPS numérico nem regra adicional explícita para `*.adminml.com`.
- HackerOne Signal Requirements (atualizado em outubro de 2026): https://docs.hackerone.com/en/articles/8505319-signal-requirements e Restricted from Submissions https://docs.hackerone.com/en/articles/8474047-restricted-from-submissions.

## Decisões por pergunta
1. **Crypto e Point Smart:** o extrato já delimita Crypto a `www.mercadopago.com.mx/crypto/*`, `www.mercadopago.cl/crypto/*` e `www.mercadopago.com.br/crypto/*`. Point Smart traz `Tier 1 - MLA/MLB` e links de produto nas páginas da Argentina e Brasil. Não inferir elegibilidade de blockchain, wallets de terceiros, infraestrutura não listada ou dispositivos alheios. Para Crypto, prova mínima: defeito reproduzível na função explicitamente em scope, com conta própria/teste e sem transferência financeira ou dados alheios. Para Point Smart, hardware de laboratório sob controle legítimo e demonstração local não destrutiva de falha concreta com cartões/usuários de teste onde permitido; não atacar instalações/pessoas ou processar transações reais. **PENDÊNCIA:** confirmar com programa quais metodologias físicas/firmware/dispositivo e transações de teste estão autorizadas antes de executar.
2. **Tiers:** a alegação "tiers ausentes da API" é **refutada** pelo próprio extrato: campo `attributes.instruction` associa **Tier 1 a 21 dos 22 ativos elegíveis** (incluindo `*.adminml.com` e Point Smart). **Crypto não informa tier** e não deve ser arbitrado. `Tier 3` na política refere-se a **categoria de achados não-aplicativos** (exposição de credencial/configuração com avaliação própria), não ao terceiro nível automático de cada ativo; recompensa Tier 3 não usa CVSS.
3. **Signal:** usuário sem histórico não comprova Signal >=1.0; a plataforma concede **até 3 trial reports compartilhados entre programas em que não se alcança o limiar**, sujeitos à elegibilidade específica. Para bug bounty remunerado, HackerOne informa exigência de verificação de identidade. Confirmar status da conta e cotas pela UI autenticada, sem transmitir credenciais; nenhum trial report é requisito prévio para ler o programa ou estudar escopo. Ainda precisa provar elegibilidade de submissão de `nielzsec`.
4. **AdminML:** no extrato `*.adminml.com` é in scope, Tier 1; política não expressa restrição extra nominal. Isso NÃO autoriza teste de acesso a contas de empregados, tentativa de credenciais, brute-force, mass fuzzing, acesso além de prova mínima ou exploração de ativos sem vínculo exato com o wildcard. Trabalho manual e controlado, interromper se exposição de terceiros.
5. **Manual versus massivo:** nenhuma quota numérica é definida na política; não inventar requests/segundo. Reconhecimento passivo e poucas provas de hipótese específicas e não destrutivas estão alinhadas a "creative testing"; descoberta automatizada ampla, crawling generalizado de wildcards, fuzzing agressivo e tentativas em escala ficam barrados. Solicitar confirmação formal ao programa antes de automação de fronteira; respeitar indicadores de sobrecarga e interromper em caso de dúvida.

## Pendências que bloqueiam PASS do Portão A
- Corrigir spec v1: tiers estão no campo `instruction`; registrar mapeamento explícito dos 21 Tier 1 e Crypto=UNKNOWN, com o vínculo ao hash/objeto exato.
- Fixar Crypto a 3 caminhos listados; delimitar hardware/firmware e testes de Point Smart autorizados, ou retirar essas superfícies do plano ativo até esclarecimento oficial.
- Confirmar elegibilidade/ID verified e limite disponível de trial reports da conta pesquisadora; não presumir Signal >=1.0.
- Aprovação JEV por claim sobre o extrato + política efetivamente entregues (não apenas resumos), preservando política de confidencialidade e identidade.
- Definir playbook de método manual, autorização por ativo, limite operativo conservador e stop conditions por caso; se for proposta automação de busca, obter permissão escrita apropriada.
- Só então reconsiderar PASS; até lá **execution=STOP**, permitindo preparação documental e leitura de fontes públicas.

Nenhum scan, teste em alvo, autenticação, chamada à API alvo ou submissão de relatório foi executado por este QA.
