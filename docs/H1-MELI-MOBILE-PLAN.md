# H1-MELI — Plano de Análise Estática de Aplicativos Móveis (Fase 3 - Prep)

- **Programa:** MercadoLibre Bug Bounty (HackerOne ID: 33462)
- **Data:** 2026-10-20
- **Status:** Fase 3 (Plano de Preparação) — Em conformidade com `docs/H1-0-MERCADOLIBRE-SPEC-20261020.md` e `docs/H1-QA-JEV-GATES-AMENDMENT-20261020.md`
- **Operador Responsável:** Kai (`nielzsec`)
- **Lane Técnica:** AI-Research / Reverse Engineering (VANTA)
- **Modo Operacional:** **100% ESTÁTICO (Offline). Zero tráfego de rede ativo contra infraestrutura de produção.**

---

## 1. Escopo de Ativos Móveis Elegíveis

A análise estática restringe-se estritamente aos ativos móveis listados como elegíveis (submission=true, bounty=true) na especificação do programa:

| Identificador do Ativo | Plataforma | Origem Obrigatória |
| :--- | :--- | :--- |
| `com.mercadolibre` | Android | Google Play Store Oficial |
| `com.mercadopago.wallet` | Android | Google Play Store Oficial |
| `com.mercadoenvios.driver` | Android | Google Play Store Oficial |
| `com.mercadoenvios.crowdsourcing` | Android | Google Play Store Oficial |
| `com.mercadopago.MercadoPago` | iOS | Apple App Store Oficial |
| `com.3mosquitos.MercadoLibre` | iOS | Apple App Store Oficial |

*Nota: Ativos fora de escopo (ex.: Kangu, Redelcom) permanecem estritamente bloqueados de qualquer inspeção.*

---

## 2. Protocolo de Aquisição, Integridade e Cadeia de Custódia

Para assegurar que o código analisado seja autêntico e livre de adulterações externas de terceiros, estabelece-se o seguinte protocolo de custódia:

1. **Fonte Exclusiva de Aquisição:**
   - Os binários devem ser baixados **diretamente das lojas oficiais** (Google Play e Apple App Store) utilizando dispositivos físicos controlados do laboratório ou ferramentas autenticadas com contas oficiais (`apkeep`, `google-play-scraper`, `ipatool`).
   - **Proibição estrita:** É vedado o uso de repositórios de espelho ou portais de terceiros (como APKPure, Aptoide, APKMirror), eliminando qualquer risco de contaminação por malware ou modificações de terceiros.
2. **Selagem e Hash Criptográfico:**
   - Imediatamente após o download de cada APK (incluindo split-APKs/APKs múltiplos) ou arquivo IPA, deve ser calculado e registrado o hash `SHA-256`.
   - O hash, data/hora UTC e versão do pacote devem ser registrados no manifesto de evidências do engajamento (`evidence/SHA256SUMS`).
3. **Isolamento em Disco:**
   - Os artefatos baixados devem ser armazenados em diretório de trabalho dedicado com permissão restrita (`chmod 0600`), fora de índices públicos.

---

## 3. Toolchain de Análise Estática (Apparatus)

A análise operará sem execução do aplicativo e sem envio de tráfego de rede:

### 3.1 Camada Android (DEX / Bytecode Java & Kotlin)
- **`JADX` / `JADX-CLI` (v1.5.0+):** Descompilação completa de arquivos DEX para Java legível; busca estruturada de regex por endpoints, strings, componentes declarados e assinaturas criptográficas.
- **`apktool` (v2.9.0+):** Extração de recursos brutos, desmontagem de bytecode para Smali, e inspeção detalhada do `AndroidManifest.xml` canônico e `network_security_config.xml`.
- **`Semgrep` (com regras OWASP MASVS e Security-Extended Mobile):** Varredura automatizada local para identificação prévia de padrões conhecidos de APIs inseguras, hardcoded secrets e bindings vulneráveis.

### 3.2 Camada Nativa (C/C++ Shared Objects & Mach-O)
- **`Ghidra` (v11.x) / `REA MCP`:** Engenharia reversa e descompilação de bibliotecas nativas compartilhadas (`lib/arm64-v8a/*.so`, `lib/armeabi-v7a/*.so`) no Android e do executável principal descompactado no iOS. Foco prioritário em:
  - Métodos JNI (`Java_com_mercadolibre_*` e `Java_com_mercadopago_*`);
  - Constantes criptográficas embutidas, tabelas de S-Box ou rotinas proprietárias de cifragem;
  - Resolução dinâmica de APIs e strings ofuscadas em runtime.
- **`readelf` / `objdump` / `rabin2`:** Mapeamento de imports/exports, checagem de símbolos e flags de segurança de compilação.

### 3.3 Camada iOS (Mach-O, Assets & Plist)
- **`jtool2` / `rabin2`:** Inspeção de headers Mach-O, entitlements, arquiteturas e strings estáticas.
- **Análise de `Info.plist`:** Mapeamento de custom URL schemes (`CFBundleURLSchemes`), permissões de hardware (`NSCameraUsageDescription`, etc.) e exceções de transporte (`NSAppTransportSecurity`).

---

## 4. Hipóteses de Vulnerabilidades Elegíveis (Alinhadas ao Programa)

Para não desperdiçar esforço analítico em itens inelegíveis, o plano foca exclusivamente em hipóteses que representam impacto concreto e possuem elegibilidade explícita nas regras do MercadoLibre:

### Hipótese 1: Exposição de Credenciais e Segredos de Infraestrutura (Tier 3)
- **Vetor:** Hardcoded API keys, tokens de serviço de nuvem (AWS Access Keys, GCP Service Accounts, Azure Client Secrets), chaves de parceiros corporativos ou credenciais internas de microsserviços inseridas em assets, strings, classes Java ou bibliotecas nativas `.so`.
- **Validação Permitida pela Política:** A política do MercadoLibre autoriza a confirmação da validade de credenciais expostas mediante **uma única chamada não destrutiva** (ex.: `sts:GetCallerIdentity` ou consulta de metadados sem alteração de estado). É terminantemente proibido pivotar, acessar dados de terceiros ou extrair volumes de dados.

### Hipótese 2: Content Providers Exportados Vulneráveis (SQLi / Path Traversal Local)
- **Vetor:** Declaração de `<provider>` no `AndroidManifest.xml` com `android:exported="true"` sem exigência de permissões customizadas de proteção (`android:protectionLevel="signature"`).
- **Impacto a Provar:**
  - *SQL Injection Local:* Provedores que executam queries SQL concatenando diretamente parâmetros recebidos via `query()`, `insert()` ou `update()`.
  - *Directory Traversal / File Theft:* Implementação insegura de `openFile()` ou `openAssetFile()` sem validação de caminhos canônicos (`..`), permitindo que um aplicativo malicioso instalado no mesmo dispositivo leia arquivos confidenciais da pasta privada (`/data/data/com.mercadolibre/...`).

### Hipótese 3: Intent Redirection & Acesso a Componentes Internos
- **Vetor:** Atividades ou Broadcast Receivers exportados que aceitam um `Intent` como extra e o repassam sem validação como argumento de `startActivity()`, `startService()` ou `sendBroadcast()` (padrão Intent Redirection).
- **Impacto a Provar:** Permissão para que aplicativos não privilegiados iniciem componentes internos não-exportados do MercadoLibre/MercadoPago, contornem checagens de autenticação locais ou capturem tokens de autorização em fluxos de redirecionamento.

### Hipótese 4: WebViews com Configurações Perigosas de Acesso Local
- **Vetor:** Configurações de `WebSettings` que habilitam acesso irrestrito a arquivos locais e execução de scripts:
  - `setAllowFileAccessFromFileURLs(true)`
  - `setAllowUniversalAccessFromFileURLs(true)`
  - Exposição de interfaces nativas via `addJavascriptInterface` em endpoints suscetíveis a XSS local ou injeção de HTML.
- **Restrição Crucial:** Não reportar redirecionamento de URL aberto em in-app browser (ver exclusões). O foco é exclusivamente na fuga da sandbox da WebView para leitura de arquivos privados do app ou execução de comandos locais.

### Hipótese 5: Criptografia Frágil em Armazenamento Local Crítico
- **Vetor:** Uso de algoritmos obsoletos ou chaves simétricas estáticas embutidas no código para criptografar tokens de sessão, credenciais ou dados bancários/financeiros no `SharedPreferences`, banco de dados SQLite local (sem SQLCipher ou com chave hardcoded) ou KeyStore manipulada incorretamente.
- **Impacto a Provar:** Capacidade de recuperar as chaves estáticas diretamente do bytecode/`.so` e decifrar artefatos locais armazenados sem depender de privilégios de root.

### Hipótese 6: Zip Slip / Manipulação de Caminho em Extração de Bundles
- **Vetor:** Rotinas de descompressão automática de arquivos zip/tar (usados para atualizações dinâmicas de assets, layouts ou código React Native) sem checagem de canonical path (`entry.getName().contains("..")`).
- **Impacto a Provar:** Possibilidade de sobrescrever bibliotecas `.so` ou arquivos de configuração executáveis dentro do diretório do aplicativo durante processos de extração.

---

## 5. Exclusões Mandatórias do Programa (O Que NÃO Fazer e NÃO Reportar)

Em observância irrestrita à política oficial do MercadoLibre e ao §2 da especificação, **nenhum relatório será redigido ou submetido** com base nos seguintes tópicos:

1. **Certificate Pinning / SSL:** Proibido reportar ausência, falha ou possibilidade de bypass de Certificate Pinning ou SSL Pinning.
2. **Ofuscação:** Proibido reportar ausência de ofuscação de código, ausência de ProGuard/DexGuard ou facilidade de descompilação.
3. **Mecanismos Anti-Instrumentação:** Proibido reportar ausência de detecção de Root, ausência de detecção de Frida/Xposed ou falhas de implementação de SafetyNet / Play Integrity.
4. **Componentes Exportados sem Impacto:** Proibido reportar a mera presença de `android:exported="true"` em Manifests sem demonstrar um vetor de ataque explorável e impacto palpável.
5. **Deeplinks In-App-Browser:** Proibido reportar links nos esquemas `mercadopago://in-app-browser` ou `meli://in-app-browser` e open redirects dentro da WebView.
6. **Varredura Automatizada Massiva:** Proibido rodar fuzzers dinâmicos de intents ou scanners automatizados contra os apps em execução.
7. **Tráfego contra Produção:** Nenhuma requisição a `api.mercadolibre.com` ou `api.mercadopago.com` deve ser disparada durante a fase de análise estática.

---

## 6. Critérios de Parada e Encaminhamento para Portão B

- **Critério de Parada por Finding:**
  1. A análise estática identifica a evidência no código (arquivo, classe, método, linha exata).
  2. Confirma-se que o finding não se enquadra em nenhuma das exclusões do §5.
  3. Redige-se o rascunho de evidência estática com SHA-256 do binário de origem.
- **Portão B (QA + JEV):**
  - O achado estático é submetido ao crivo conjunto de QA (GPT-6) e JEV.
  - Apenas findings com veredito `PASS` em ambos os controles poderão avançar para a Fase 6 (confirmação pontual não destrutiva e submissão formal no HackerOne).
