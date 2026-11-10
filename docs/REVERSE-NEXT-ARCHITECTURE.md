# MITR3 Reverse Next — arquitetura

Implementação local offline em `labs/reverse-next`. OpenCode controla gates; Codex mantém scripts/tests/fixtures, Antigravity cases, Gemma4 conhecimento/skill, DeepSeek revisão de autorização. H1-MELI e OT são independentes.

## Fluxo reproduzível

```bash
cd <MITR3_ROOT>/labs/reverse-next
bash scripts/mitr3-reverse-lab.sh --dry-run
bash scripts/mitr3-reverse-lab.sh --check
bash scripts/mitr3-reverse-lab.sh --build
bash scripts/mitr3-reverse-lab.sh --verify
python3 -m unittest discover -s tests -v
bash scripts/mitr3-reverse-lab.sh --smoke
python3 scripts/verify_integration.py
```

`--build` só prepara amostras próprias; se há manifesto, verifica integridade e não recompila. Não instala pacotes. `--dry-run` não escreve. Cada smoke cria diretório novo em reports; falhas não são recicladas em sucessos. O runtime/cache está em `.runtime`. O inventário mede versões sem equiparar presença a função validada.

O executor usa bubblewrap: host montado somente leitura, lab gravável, `/tmp` efêmero, rede isolada com loopback. Ferramentas recebem ambiente mínimo, sem env credentials. Binários analisados não são executados. Não equivale a uma VM contra vulnerabilidades do kernel; o escopo padrão é amostra sintética própria.

## Fontes e roteamento

REA source `01788bac863ac786bfbb648cad69b11e23b40a89`, reverse-skill `cab634bd855fc287f6e420c1f36fd1a6b9245960`; clones limpos, separados da release npm. `pin_check` rejeita HEAD diferente ou worktree modificada. Nenhum instalador, hook ou submódulo foi executado.

`master-route.sh` usa a tabela oficial `skills/config/routing.json`. Executamos o script revisado com output explícito em staging; o resultado é dado externo, não instrução global. `case-init.sh` recebe somente amostra própria fixa, preset offline e diretório novo. Seu preset upstream não é autoridade de autorização. O inventário próprio substitui `refresh-tool-index.sh`, que abre conexões locais e não satisfaz o contrato offline.

## Trilhas e evidências

Native: C próprio → gcc → ELF → readelf/rizin → REA MCP/Ghidra → funções, callers e pseudocódigo. O wrapper reusa `fwlab.ghidra.headless_command` e `ot-firmware/tools/AuthExport.java` somente leitura, gravando projeto e export no lab novo. A função authorize_demo exige role 7 e owner 42.

Android: manifesto + smali próprios → Apktool → APK com timestamps normalizados → JADX e APKTool offline. Sem assinatura de produção, instalação ou emulador. Checagem local de papel 7 não prova autorização de servidor.

Firmware: ZIPs sintéticos v1/v2 com ELF e política → Binwalk estático → extrator ZIP limitado → inventário e diff. Só require_owner e versão mudam; o ELF é idêntico. Não emula firmware nem chama extratores externos indiscriminados.

Casos de Antigravity são independentes dos runs de QA. Cada caso/run inclui hipóteses, limitações e hashes; metadados de horário são variáveis, conteúdo dos fixtures é selado. Consulte os manifests de cada run, não apenas um arquivo “latest”.

## MCP e configuração

Cliente stdio próprio `mcp_probe.py`: initialize, initialized, tools/list e chamadas reais usando snapshot local do pacote npm 6.7.0 em `<TOOLS_ROOT>/rea-runtime-6.7.0` (7.881 arquivos com manifesto SHA-256), sem npx/download. REA tem 207 ferramentas; disponibilidade real é por provider. Ghidra 12.1.2, Java 27 e decompiler ELF x86_64 foram medidos. `REA_BINWALK_COMMAND` é local ao processo.

OpenCode já registra REA pinado. `reports/rea-opencode-dry-run.txt` foi revisado: propõe update da entrada e instalação da skill global. Nenhuma ação foi aplicada, pois o registro existente funciona e não é necessário importar skill upstream global ou reiniciar sessões. O cliente de teste comprova protocolo real; não afirma que cada sessão produtiva recarregou configuração.

Provider Android do REA exige JAR jadx-headless-mcp 0.7.1, ausente. A trilha Android usa JADX/APKTool locais comprovados. IDA portátil fornecido em 2026-10-21 identifica arquivo 7.0 de 720393004 bytes; plataforma/licença/integridade não atestadas, não executado nem necessário ao Ghidra. Documentação pinada do REA relata headless IDA 9.1/9.3 em outros hosts; não há prova de compatibilidade Linux/7.0.

## Recuperação

Nada foi aplicado a serviços ou configs globais. Antes de modificar artefato próprio já existente, criar cópia privada com SHA e verificar a restituição. Para retirar o laboratório, arquivar exclusivamente `labs/reverse-next` após ownership do maestro; manter relatórios históricos. Não usar git reset/clean. Não apagar OT, caches REA compartilhados ou sessões de outros agentes.
