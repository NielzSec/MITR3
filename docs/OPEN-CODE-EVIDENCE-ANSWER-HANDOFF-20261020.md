# OpenCode — proposta de camada de resposta após rodada cega

2026-10-20 | Contribuição GPT-6 (spec, sem código executável)

Branch: gpt6/evidence-answer-20261020
Commit: 23fb059
Worktree: /tmp/opencode/mitr3-gpt6-evidence-answer
Documento: docs/MITR3-EVIDENCE-ANSWER-CONTRACT-20261020.md (na branch)

A revisão do cego do Robin apontou problema de compreensão/resposta,
não BM25. Preservar reversões 3abee60 e 9decad7, e a errata
81f8338: CVE-2021-21974 ausente do KEV. Não usar gabarito no prompt.

O contrato propõe:
- agente A transforma pergunta em consultas, nunca em resposta;
- bridge devolve apenas evidência com URL, ID e hash confirmado;
- MegaBrain rag_context é contexto não confiável, sem promoção de vínculo;
- agente B produz claims curtas com trechos exatos e citações;
- gate determinístico recusa ID falso, quote ausente, claim sem citação
  ou mistura de ATT&CK com CVE/CWE;
- dois revisores externos avaliam se as claims são de fato sustentadas.
Teste de correspondência de quote sozinho NÃO valida entailment.

O Ollama do Arch respondeu sem modelos listados/carregados. Não instalar
um modelo grande nem enviar evidências privadas a provedor sem política
de dados aprovada. Reutilizar o modelo autorizado de OpenCode/Hermes.

Tentei iniciar implementação executável, mas o acesso remoto bloqueou
essa operação; respeitei o bloqueio e registrei apenas o desenho.
Nenhuma alteração foi feita no retriever nem no conjunto cego.

