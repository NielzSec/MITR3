# MITR3 — Handoff de pesquisa: vulnerabilidade transitiva sem CVE explícita

**Data:** 2026-10-20 · **Origem:** GPT-6, análise de material público indicado pelo operador.
**Destinatário:** OpenCode (maestro); Hermes/Gemma4, Codex, VANTA/Antigravity e JEV.
**Estado:** proposta metodológica; **nenhum alvo testado**, nenhum scanner executado e nenhuma ingestão ou publicação automática autorizada.

## 1. Vídeo e correção conceitual

- LiveOverflow, **OpenAI Hacked with a 1-Year-Old Bug** (2026-10-02, 10:12): https://www.youtube.com/watch?v=qypnjORyWNI
- Segmentos úteis: 00:00 escolha de superfície; 03:04 versão instalada; 04:49 atraso na correção; 08:07 herança via Discourse; 09:03 manutenção de dependências.
- Cadeia descrita no vídeo: **serviço que usa Discourse → processamento de imagens via ImageMagick → biblioteca libheif → pacote da distribuição Debian na imagem Docker**. O ponto de entrada é uma funcionalidade legítima do app, enquanto o defeito está numa dependência transitiva.
- **Precisão importante:** o vídeo diz que o *bug específico* havia sido corrigido upstream sem um CVE próprio; menciona também **outra** CVE na mesma função, **não equivalente** à falha explorada. Portanto, não reclassificar o incidente como “exploração de uma CVE conhecida” sem identificar exatamente o patch/falha. Não confundir patch silencioso, CVE vizinha e vulnerabilidade demonstrada.
- “O código próprio do web app não tinha a falha” não significa que o produto implantado estivesse seguro: um caminho de processamento pode expor falha de componente de terceiros.

## 2. Princípio para o MITR3

**Pesquise a cadeia de processamento e a composição real do runtime, não só endpoints e CVEs da aplicação principal.**

Fluxo de pesquisa: ativo e funcionalidade em escopo → tipo de entrada controlável e caminho de dados → framework/serviço auxiliar → biblioteca direta ou transitiva → artefato implantado (build/digest) → versão e patches efetivos → advisory/commit upstream → exposição **comprovada** → QA de impacto.

Superfícies para *priorização de pesquisa passiva*, sem afirmar problema presente: parsers de HEIF/AVIF, SVG, PDF e XML; conversores de imagem/documento, thumbnails, anexos, vídeo, importadores, renderizadores, bibliotecas nativas; imagens base Docker, pacotes de distro, plugins e SDKs.

## 3. Perguntas de triagem e falsos positivos

1. A evidência é da **versão efetivamente implantada**, e não de manifest antigo, imagem base genérica, lockfile desatualizado ou ambiente distinto?
2. Há prova de que o componente vulnerável é **carregado/chamado** pelo fluxo e de que o formato/caminho afetado é alcançável? Dependência instalada ≠ explorável.
3. A distribuição aplica **backport** do patch? Não inferir vulnerabilidade só porque a versão parece inferior à upstream; conferir changelog/patch da distro e commit de correção.
4. O CVE/GHSA reportado corresponde **ao mesmo defeito e às mesmas pré-condições**, e não a bug parecido na mesma função?
5. Existe mitigação no produto (conversão externa isolada, política de codecs, sandbox, permissões, formato bloqueado) ou VEX “not affected” que muda a conclusão?
6. Existe patch silencioso sem CVE? Se sim, registrar **commit + trecho/diff + intervalo de versões + fonte**, sem inventar identificador.
7. Separar **exposição da cadeia** de **explorabilidade** e de **impacto demonstrado**. Não concluir RCE a partir de OOB ou scanner isolado.

## 4. Contrato de evidências e classificação

- **Lead:** indicação pública/heurística de componente possivelmente usado.
- **Inventário verificado:** versão, distribuição, build/digest/SBOM ou lockfile observado em artefato autorizado.
- **Afetabilidade verificada:** advisory ou diff aplicável à versão, com análise de backport e pré-condições.
- **Reachability verificada:** call path concreto entrada → componente vulnerável, incluindo mitigação relevante.
- **Achado confirmado:** evidência de efeito/impacto reproduzida **somente em laboratório expressamente autorizado**, respeitando escopo e plano; na ausência dela, manter “hipótese”, não reportar exploração.

Cada registro deve conter: fonte/URL/autor/data; componente, ecossistema, caminho transitivo, versão e digest; commit/advisory/CVE **se existir**; status do patch de distro; caminho de entrada; evidência e SHA256; limitações; revisor; decision gate. Sem inventar dados de alvo.

## 5. Proposta de distribuição do trabalho — NÃO É AUTORIZAÇÃO DE EXECUÇÃO

- **OpenCode (maestro):** classificar como nova linha de pesquisa **SUPPLYCHAIN-REACHABILITY**; preservar o plano H1 em andamento e decidir prioridade/escopo.
- **Hermes/Gemma4:** curar fontes públicas confiáveis (OSV, advisories upstream, Debian Security Tracker, changelogs) e separar *fato*, *inferência* e *lacuna*.
- **Codex:** desenhar checklist de inventário read-only para artefatos autorizados (SBOM/lockfile/digest/purl, grafo de dependências, backports) e testes de QA **com fixtures locais**, sem iniciar varredura.
- **VANTA:** revisão estática de parsers/call graphs para mapear alcançabilidade; sem execução de amostras não confiáveis ou PoC sem sandbox e autorização.
- **JEV:** rejeitar claims de “CVE explorável” quando houver só correspondência de nome/versão; exigir evidências de *mesma falha*, patch e reachability; permitir abstenção.
- **MegaBrain:** preparar ficha para fila de curadoria humana, **sem** publicação automática; seguir `docs/MITR3-INTELLIGENCE-RAG.md` e `bin/mitr3-rag-curate.py`.

## 6. Segurança, escopo e decisão

Para HackerOne MercadoLibre #33462, tratar apenas como **heurística transferível**, **não como afirmação de que MercadoLibre usa Discourse/libheif ou possui essa falha**. Fazer apenas revisão passiva de documentação, componentes divulgados e artefatos localmente autorizados. Não fazer upload de arquivos maliciosos, fuzzing, descoberta em massa, DoS, interação com terceiros ou novo teste ativo sem portão de autorização do engagement. O caso BOLA de cancelamento é uma linha separada, sem evidência compartilhada.

**Gate:** sem versão real + vínculo ao fluxo + defeito aplicável → **sem finding**. Sem impacto autorizado → **hipótese/risco potencial**, não exploração confirmada. Qualquer teste futuro exige aprovação explícita do maestro e do operador.

## 7. Fontes de suporte

- Vídeo de origem: https://www.youtube.com/watch?v=qypnjORyWNI
- Debian Security Tracker (componente de exemplo): https://security-tracker.debian.org/tracker/source-package/libheif
- OSV / versões e advisories: https://osv.dev/ e https://google.github.io/osv-scanner/
- CISA, SBOM e VEX (afetabilidade ≠ presença): https://www.cisa.gov/sites/default/files/2023-12/SECURING%20THE%20SOFTWARE%20SUPPLY%20CHAIN%20RECOMMENDED%20PRACTICES%20FOR%20SOFTWARE%20BILL%20OF%20MATERIALS%20CONSUMPTION%20%282%29.pdf

**Entregável esperado caso aprovado pelo maestro:** matriz de triagem de componentes e provas por etapa, com evidências de fonte, falso positivo explicitamente testável, e um rascunho de fixture para checagem de backport/reachability. Não é pedido de exploração.
