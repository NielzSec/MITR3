# DARKWEB-POC-CATALOG — 2026-10 (anexo vivente)

Catálogo de intel dos subdreads de PoC/exploit do Dread, mantido pelo Robin (MITR3).
Regra v2 (Kai): leitura passiva via GET; **nunca** registro, login, posting ou qualquer interação (playbook §5/§9).
Formato por linha: `/d/` | thread | data | resumo (1 linha) | CVE-IDs citados | PoC released? (sim/não/parcial).
**Este catálogo NUNCA colar corpo de PoC** — CVE-id + descrição de 1 linha bastam.

## Estado (2026-10-19, 2 janelas de GET espaçadas)

Alvo: `dread-current` = `http://dreadytu5e57d2xyx2fdgpvqnaf7zxhwr65k5vozpfbotulgv46lc7id.onion/`

| /d/ | thread | data | resumo | CVE-IDs | PoC released? |
|---|---|---|---|---|---|
| /d/PoC | — | 2026-10-19 | Board não existe no dread-current: HTTP 404 (nginx), 146 B | — | — |
| /d/poc | — | 2026-10-19 | Variante minúscula: HTTP 404 (nginx), 146 B | — | — |
| /d/Exploit | — | 2026-10-19 | Board não existe no dread-current: HTTP 404 (nginx), 146 B | — | — |
| /d/exploit | — | 2026-10-19 | Variante minúscula: HTTP 404 (nginx), 146 B | — | — |

Nenhuma thread catalogável — nenhum dos quatro paths responde com conteúdo.

## Evidência

- Frontpage do dread-current (frame de 257611 B, sha256 no MANIFEST) lista **18 subdreads**: DNMSourcing, DarkNetMarkets, DarknetMarketsNoobs, Daunt, Dread, HarmReduction, Monero, OpSec, OpSecNoobs, Recon, Test4Pay, all, hackingNoobs, marketannouncements, marketplace, traplordatlantic — **nenhum com nome PoC/Exploit/CVE**.
- GETs desta missão (2 janelas, 2026-10-19 UTC): `/d/PoC` 11,2 s · `/d/poc` 1,9 s · `/d/Exploit` 5,6 s · `/d/exploit` 3,2 s — todos HTTP 404, corpo nginx 146 B. Frames em quarentena com sha256 (`/tmp/opencode/darkquarantine/m9-dread-*`, linhas no MANIFEST).
- Mirrors Dread observados mas **não varridos** (fora do alvo desta missão): `dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion` (OnionDir /cat2).

## Regras de atualização (monitor 09:30)

1. Este arquivo é anexo vivente do monitor `darkweb-monitor.sh`; o doc principal (DARKWEB-SOURCES-v1.6) permanece fechado.
2. Ao aparecer 200 em `/d/PoC` ou `/d/Exploit` (ou novo subread de PoC no frontpage): popular a tabela com thread, data, resumo de 1 linha, CVE-ids e flag de PoC.
3. Só GET passivo, máx. 2 janelas por rodada, espaçadas; sem interação nunca.
4. PoC released = "sim" só quando o próprio thread anuncia/libera exploit; "parcial" quando há descrição/diagrama sem artefato; "não" quando é discussão/aviso sem exploit.
5. Atualização exige novo hash no MANIFEST + linha nova em `SHA256SUMS` (selo).
