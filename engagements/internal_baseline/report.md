# Technical report — internal_baseline

Data: 2026-10-19 · Operador: nielz / squad MITR3 · Escopo: dois componentes locais.
Estado: remediado e retestado (F-01, F-02, F-03). F-04 é falso positivo.

## Executive summary

A cadeia estática rodou completa em alvo real: semgrep, trivy e osv-scanner produziram
evidência JSON selada por SHA256. O Dockerfile do apisec rodava como root e não tinha probe;
ambos corrigidos, imagem reconstruída e reescaneada. O inventário Python do scanner de imagem
apontava três pacotes desatualizados; a árvore real do runtime está limpa (verificado por
`pip list` e por scan da árvore extraída). O que resta é a base Debian: 166 advisories de
pacote de sistema, 44 HIGH, resolvidos por reconstrução periódica — não por mudança de código.

## Scope and method

- alvos: `mitr3-nexus-re`, `apisec-ng-mcp-server`
- semgrep 1.181.0 — `--config=p/python --config=p/secrets --metrics=off`
- trivy 0.76.0 — `fs --scanners vuln,secret,misconfig`, um alvo por execução; `image` na imagem construída
- osv-scanner 2.7.0 — `scan source -r`
- nada executado contra rede; nenhum alvo externo tocado

## Findings

### F-01 — Container rodava como root

- severity: HIGH → **corrigido**
- asset: `apisec-ng-mcp-server/Dockerfile`
- evidence original: `trivy_apisec-ng-mcp-server.json`, DS-0002
- fix: `RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin mcp` + `USER 10001`
- retest: `docker image inspect` → `User=10001`; `trivy fs --scanners misconfig` → `[]`

### F-02 — Dependências com advisories

- severity: MEDIUM → **parcial, com causa separada**
- evidence: `trivy_apisec_image.json` (166 OS, 44 HIGH; 6 Python), `trivy_apisec_image_retest.json`
- o que era real: `setuptools 70.3.0`, `urllib3 2.7.0`, `msgpack 1.1.2` no inventário do scanner
- fix aplicado: mínimos explícitos em `requirements.txt` (`setuptools>=78.1.1`, `urllib3>=2.8.0`, `msgpack>=1.2.1`), imagem reconstruída
- verificação de runtime: `pip list` e `python -c` → `setuptools 84.0.0`, `urllib3 2.8.0`, `msgpack 1.2.3`
- verificação independente: árvore de `site-packages` extraída e escaneada com `trivy fs` → **0 vulnerabilidades**
- conclusão: o scanner de imagem continua lendo dist-info de camada antiga; a árvore em execução está limpa. Resta a base Debian (abaixo).

### F-03 — Dockerfile sem HEALTHCHECK

- severity: LOW → **corrigido**
- fix: `HEALTHCHECK ... CMD pgrep -f apisec-ng-mcp-server.py || exit 1` (servidor stdio, sem porta)
- retest: `docker image inspect` → healthcheck presente; trivy misconfig → `[]`

### F-04 — chmod 0o700 sinalizado pelo semgrep

- severity: INFO (falso positivo)
- evidence: `semgrep.json`, `scope.py:53`, `stdio_server.py:22`
- análise: `os.chmod(SCOPES, 0o700)` é o modo correto para diretório privado. Sem ação.

### F-05 — Base Debian com advisories pendentes

- severity: HIGH (aceito, com cadência)
- evidence: `trivy_apisec_image.json` — 166 pacotes, 44 HIGH (`bsdutils`, `libblkid1`, `libacl1`…)
- causa: `python:3.12-slim` (Debian 13.7) no digest usado no build
- ação: reconstruir a imagem a cada ciclo de patch da base; não há mudança de código que resolva
- observação: o container não é exposto publicamente; risco limitado ao host que o roda

## Remediation plan

1. ~~`USER` no Dockerfile~~ feito.
2. ~~HEALTHCHECK~~ feito.
3. ~~Mínimos de setuptools/urllib3/msgpack~~ feito e verificado no runtime.
4. Cadência de rebuild da imagem para acompanhar a base Debian.
5. Re-rodar os três scanners e comparar com `evidence/SHA256SUMS`.

## Retest log

| data | ação | resultado |
|---|---|---|
| 2026-10-19 11:20 | build `apisec-ng-mcp:audit` | User=10001, healthcheck ativo, trivy misconfig 0 |
| 2026-10-19 11:26 | build `apisec-ng-mcp:audit2` com mínimos | `pip list` 84.0.0 / 2.8.0 / 1.2.3; `trivy fs` na árvore extraída = 0 |

## Unknowns

- O scanner de imagem insiste em reportar versões antigas de Python; a divergência está registrada e
  resolvida por verificação direta. Vale abrir issue no trivy se reaparecer em outra imagem.
- CVEs da base Debian não foram triadas uma a uma; contagem e pacote são o dado desta rodada.
