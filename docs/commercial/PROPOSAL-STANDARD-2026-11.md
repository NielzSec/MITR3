# Proposta técnica e comercial — pacote Standard

**RASCUNHO INTERNO — NÃO ENVIAR.** Preço, prazo e condições abaixo são propostas de trabalho; não representam oferta aprovada, contrato, disponibilidade ou compromisso de atendimento. Requerem aprovação do operador e revisão jurídica/comercial.

**Cliente:** [empresa e razão social]<br>
**Responsável:** [nome e cargo]<br>
**Data:** [preencher após aprovação]<br>
**Validade:** [definir após aprovação]<br>
**Preço proposto:** R$ 3.490,00

## 1. Objetivo

Avaliar, de forma autorizada e limitada, a segurança das páginas e rotas de API nominadas no anexo de escopo. O trabalho registra evidências mínimas necessárias para explicar e corrigir comportamentos observados. Não garante ausência de vulnerabilidades.

## 2. Pré-requisitos e início

O prazo só começa após todos estes itens serem confirmados por escrito:

1. contrato/ordem de serviço assinada por representante autorizado;
2. inventário fechado de domínios, URLs e grupos de rotas de API;
3. autorização explícita do titular dos ativos e regras de engajamento aprovadas;
4. janela de execução, contato de emergência e critérios de parada;
5. credenciais de teste, se algum fluxo autenticado for incluído.

Sem esses itens, não há teste ativo nem contagem de prazo. A atividade é suspensa se o cliente pedir, se a autorização ficar incerta ou se surgir risco de impacto fora do combinado.

## 3. Escopo proposto

O pacote cobre **um domínio primário** e, dentro dele, até:

- 5 URLs/páginas web listadas nominalmente;
- 1 base de API com até 5 grupos de rotas listados nominalmente;
- observação passiva de certificados TLS dos hostnames explicitamente incluídos.

O anexo assinado deve listar host, URL/base, ambiente, proprietário, método permitido, autenticação e janela. Limites não são transferíveis a subdomínios, IPs, tenants, fornecedores ou ambientes não listados.

## 4. Método, limites e exclusões

O método combina revisão passiva de informações públicas com verificações manuais de baixo impacto expressamente autorizadas. Cada técnica ativa precisa constar das regras de engajamento assinadas.

Ficam excluídos: DoS/carga, engenharia social, phishing, acesso físico, persistência, alteração ou exclusão de dados, exfiltração, teste de credenciais de terceiros, exploração destrutiva, bypass fora do escopo, infraestrutura cloud, código-fonte, ativos não nominados e qualquer tráfego a terceiros. Testes autenticados e reteste exigem autorização e preço separados.

Se uma confirmação segura exigir ler dado sensível, provocar impacto ou exceder a autorização, a verificação para e o relatório descreve a limitação sem coletar o dado.

## 5. Entregáveis e aceite

1. **Relatório executivo:** objetivo, escopo, janela, limitações e resumo priorizado.
2. **Relatório técnico:** cada observação com ativo, condição, impacto contextualizado, evidência minimizada, reprodução de baixo risco quando autorizada e recomendação.
3. **Manifesto de integridade:** SHA-256 dos arquivos entregues; hashes não provam por si só a validade de um finding.
4. **Debrief remoto de até 30 minutos**, agendado dentro do prazo acordado.

Se não houver achados, será entregue um relatório de resultado sem achados observados no escopo e período definidos; isso não certifica que os ativos estejam livres de vulnerabilidades.

O aceite documental verifica que os entregáveis acima foram recebidos, correspondem ao escopo assinado e abrem corretamente. Correções de erro factual devem ser solicitadas em até 5 dias úteis. Revisão de severidade, reteste, alteração de escopo e trabalho de remediação não estão incluídos.

## 6. Prazo proposto

Prazo de até **3 dias úteis**, contado após a confirmação de todos os pré-requisitos da seção 2. O prazo pode ser pausado por indisponibilidade do cliente, bloqueios técnicos ou pedido de parada. Horário de referência proposto: dias úteis, horário de Brasília. Não há SLA de atendimento emergencial ou resposta 24/7.

## 7. Investimento proposto

**R$ 3.490,00**, valor ainda não aprovado. Condições sugeridas para revisão: 50% após assinatura e 50% após entrega. Impostos, emissão fiscal, despesas, validade e forma de pagamento dependem de confirmação comercial e jurídica.

## 8. Dados e confidencialidade

Coletar o mínimo necessário, mascarar dados pessoais em evidências e não publicar informações do cliente. Retenção, acesso, descarte, confidencialidade e tratamento de dados devem ser definidos no contrato; este rascunho não substitui os instrumentos legais.

## 9. Aprovação

Esta minuta não autoriza execução. A execução depende de contrato e anexo de escopo assinados por representantes autorizados, conforme `docs/SCOPE.md` e regras de engajamento específicas.

**Contratante:** [nome, cargo, data e assinatura]<br>
**MITR3:** [representante, data e assinatura]
