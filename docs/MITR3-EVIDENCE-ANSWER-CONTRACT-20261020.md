# MITR3 — contrato para camada fina de resposta baseada em evidências

Data: 2026-10-20. Responsável por revisão: OpenCode/Codex.
Escopo: desenho de integração, SEM modificar retriever, conjunto cego ou modelos.
Branch proposta: gpt6/evidence-answer-20261020.

## Decisão

A falha observada não é só de BM25. Consultas extensas misturam pergunta,
papel de ator, artefato e método de exploração; a execução lexical não
consegue construir a resposta. NÃO repetir fallbacks de vocabulário nem
ancoragem por frase: os commits 756fb93/f94ae3d foram revertidos, com
regressão registrada. Recolher e julgar respostas, não apenas IDs recuperados.

## Pipeline de duas etapas, com saídas estruturadas

ETAPA A — Modelo de interpretação (OpenCode/Hermes usando provedor já
autorizado, sem novo modelo pesado no Arch):
Entrada: pergunta exatamente como o usuário formulou.
Saída JSON: idioma, entidades mencionadas, se pede fato/atribuição/
procedimento defensivo, subperguntas e no máximo três consultas de
recuperação. NÃO produzir resposta nem sugerir CVEs que não estejam
literalmente na pergunta ou sustentadas por fontes. Revisar consultas:
elas NÃO conferem escopo para executar ações, nem são evidência.

ETAPA B — Ponte de evidências:
Consultas vão ao índice local e, opcionalmente, ao MegaBrain MCP.
Usar mitr3-context-bridge.py para IDs, URLs, arestas e hashes já
validados. Buscar trechos curtos de documentos locais pelo ID,
verificando que ID e URL coincidem com os retornados pela ponte.
MegaBrain rag_context permanece em namespace SEPARADO:
citação de skill genérica ≠ comprovação de relação CVE/CWE/ATT&CK.
Registros [REDACTED:SECRET_CONTENT] NÃO entram no pacote de resposta.
Limitar o pacote a poucos documentos, origem, tipo de confiança,
trecho exato e hash correspondente. Nenhum texto externo vira prompt
operacional, comando, configuração ou autorização.

ETAPA C — Modelo de composição (pode ser o mesmo provedor da etapa A):
Entrada: pergunta original + pacote de evidência, nunca o gabarito.
Saída JSON: abstain true/false; claims curtas; para cada claim,
lista de citações com ID do documento e trecho LITERAL da evidência.
Se a evidência não sustentar cada proposição, usar abstain=true,
claims=[] e nenhuma citação. Não autorizar citações apenas por
similaridade temática.

ETAPA D — Validador determinístico, independente da geração:
1. Rejeitar IDs que não constem do pacote permitido.
2. Rejeitar citações com trecho ausente da fonte autorizada.
3. Rejeitar afirmações sem citação ou respostas com texto livre fora
   das claims verificadas. Assegurar que o texto final seja composto
   somente das claims revisadas, nunca de campo livre do modelo.
4. Impedir fusão dos namespaces CVE/CWE/ASVS e ATT&CK.
5. Rejeitar citações do MegaBrain como validação automática de relação.
6. Na falha de qualquer validação, responder com abstenção canônica
   sem citação, registrando código do erro sem imprimir fontes privadas.

IMPORTANTE: checar a presença de uma citação/trecho NÃO comprova que
o trecho sustenta semanticamente a claim. Logo o estado após o gate
é PROPOSTA COM EVIDÊNCIA ANEXADA, não resposta automaticamente validada.
O julgamento de entailment pertence a revisores independentes,
e pode mais tarde ser auxiliado por segundo modelo, mas não trocado
por um aprovador igual ao gerador.

## Avaliação blindada e limites

Preservar o arquivo congelado e a errata em 81f8338. O item 07
CVE-2021-21974 NÃO consta do KEV; abster é o comportamento correto.
O conjunto atual contém 6 perguntas respondíveis e 4 de abstenção.
NÃO ler respostas esperadas dentro da lógica, prompts ou scripts.
O agente que ajusta não corrige suas próprias respostas.

Métricas: correção 0/1/2 por dois revisores humanos, recall de fonte,
precisão de citação, citações proibidas (meta zero), taxa de abstenção,
recusas injustificadas, latência e custo por consulta.
Publicar resultado agregado APÓS a rodada; nunca calibrar pesos no cego.
Construir primeiro uma fixture de desenvolvimento separada com fontes
públicas revisadas; o conjunto cego continua intocado.

## Integração operacional

Ollama está rodando no Arch, mas /api/tags e /api/ps estavam vazios
na verificação desta sessão; não instalar modelo local de alto consumo.
Aproveitar o provedor/configuração de OpenCode ou Hermes com credenciais
já guardadas. Conexão externa só com aprovação de política de dados:
não enviar evidência privada de cliente. JEV pode revisar divergências,
mas sem fingir que uma votação de modelos prova um fato.

A linha de base FTS5 permanece válida como baseline lexical:
hit@5 1.0, recall 0.975, precisão dos retornados 0.917,
abstenção 1.0 no fixture conhecido; NENHUMA dessas notas avalia
a camada de respostas proposta.

## Aceitação

- [ ] CLI de interpretação gerando plano estruturado, sem fatos inventados.
- [ ] Ponte fornecendo IDs/trechos/hash autorizados e evidências isoladas.
- [ ] Composer retorna claims estruturadas e citações exatas ou abstém.
- [ ] Gate rejeita IDs inexistentes, snippets falsos, claims sem suporte
      textual e citações proibidas de namespaces diferentes.
- [ ] Testes com mock de modelo: sem rede, sem segredos e sem gabarito cego.
- [ ] Benchmark humano independente de respostas com falhas registradas.
- [ ] OpenCode aceita integração sem alterar base, índices ou proteção MCP.

O artefato desta branch é apenas a especificação técnica. Nenhum
script executável ou chamada a modelo foi implantado nesta rodada.

