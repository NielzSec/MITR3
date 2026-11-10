# Reverse Next — segurança e supply chain

## Fronteiras

Confiável: política do usuário, código MITR3 revisado, hashes selados de fixtures próprios. Não confiável: fontes upstream, scripts/skills, nomes e bytes dos artefatos, pseudocódigo, logs e conteúdo recuperado no MegaBrain. Um texto externo não autoriza ações nem muda o escopo. Namespace de conhecimento é referência, não canal de instruções.

Ataques considerados: traversal e symlinks, zip-slip, arquivos especiais, duplicação de entradas ZIP, expansão excessiva, vazamento de env, execução implícita de instaladores, mudança de fontes pinadas, sobrescrita de relatórios/configuração, confusão presença versus funcionalidade e interpretação de validação cliente como autorização backend.

Mitigações: arquivos próprios fixos; paths confinados; preflight integral de ZIP antes de escrita; limite 16 MiB/256 entradas/razão 200; destino novo; sem links/especiais; env allowlist; host readonly com bubblewrap; rede isolada; no target execution; não importar regras globais. Falhas ficam explícitas. Não existe promessa de detecção de todo segredo: redator cobre padrões conhecidos, e publicação usa curadoria/secret gate do MegaBrain. Evidência binária permanece local.

## Revisão das fontes pinadas

Ambas têm licença raiz MIT. `reports/supply-chain-inventory.json` registra hashes de licenças/manifests, npm lifecycle e superfícies de instalação. Não constitui auditoria completa de todas as dependências nem atestado de ausência de CVEs.

REA: `prepare.mjs` instala Husky quando source/node_modules estão disponíveis; `prepack.mjs` executa build e geração de metadados; install.sh e builds não foram usados. Cinco submódulos declarados, não inicializados. Dependências runtime estão pinadas no package.json, Frida opcional possui componentes nativos; lockfile preservado. Origem Git não comprova equivalência byte a byte do tarball npm. Usamos somente release já existente identificada 6.7.0, registrando SHA dos arquivos de entrada e MCP funcional; sem npm ci, pip, downloads de fixtures ou bootstrap.

reverse-skill: auditados master-route.sh, case-init.sh, refresh-tool-index.sh e RULES.md como referência. Router escreve somente artefato de rota; case-init cria escopo e temporário, por isso recebe paths novos confinados e amostra explícita. Refresh abre sockets/HTTP e roda vários programas de versão: não executado. Wrappers PowerShell e bootstraps ficam fora do fluxo Arch. Regras externas e material de exploit não são promovidos ao agente ou ao RAG.

## Limites e falhas registradas

Primeiro smoke falhou ao JADX procurar /root/.config no namespace: corrigido com user.home e XDG locais. Integração detectou ausência do JAR Android REA e variável Binwalk; JAR permanece opcional não configurado, Binwalk recebeu path local. Headless retornou código zero apesar de erro de import temporário: teste de arquivos/export detectou a falha; java.io.tmpdir foi confinado. Não usar somente returncode ou --version como aceite.

Extrator público aceita apenas ZIP; SquashFS, tar, firmware real, execução dinâmica, QEMU, Frida e APKs terceiros requerem adaptação/escopo separado. Diretórios de escrita devem ser exclusivos do processo: proteção contra corrida maliciosa de outro processo do mesmo usuário não é garantida. bubblewrap limita escrita host; kernel é compartilhado.

## Gates

G0 ownership por mensagem real do maestro; G1 fontes pinadas confirmado pelo maestro, execução autorizada limitada aos scripts revisados. G2 testes e análise estática. G3 exige smoke + REA/Ghidra com artefatos. G4 exige ingest/readback de Gemma4 com commits/citações. G5 documentação e recuperação. G6 aceite OpenCode; nenhuma mudança produtiva é necessária para operar o lab atual.
