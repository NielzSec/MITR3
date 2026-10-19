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
| /d/PoC (mirror) | Day 3: So Why Did We Do It? | sem data estática (JS) | Mirror `dreadytofat…` (OnionDir /cat2) respondeu 200, mas é a instância **“Dread2”**: os 2 paths servem o **mesmo post fixado** (“Pinned on home”), sem listagem de board | nenhum | não |
| /d/Exploit (mirror) | Day 3: So Why Did We Do It? | sem data estática (JS) | Idêntico ao /d/PoC (6727 B, mesmo título) — não há subread de exploit neste mirror | nenhum | não |

Nenhuma thread de PoC catalogável: dread-current responde 404 nos 4 paths e o mirror “Dread2” serve apenas o post fixado. **Caminho Dead encerrado no catálogo** (m10, 2026-10-19): reabrir somente se o monitor detectar board real de PoC/Exploit em qualquer um dos dois hosts.

## Evidência

- Frontpage do dread-current (frame de 257611 B, sha256 no MANIFEST) lista **18 subdreads**: DNMSourcing, DarkNetMarkets, DarknetMarketsNoobs, Daunt, Dread, HarmReduction, Monero, OpSec, OpSecNoobs, Recon, Test4Pay, all, hackingNoobs, marketannouncements, marketplace, traplordatlantic — **nenhum com nome PoC/Exploit/CVE**.
- GETs desta missão (2 janelas, 2026-10-19 UTC): `/d/PoC` 11,2 s · `/d/poc` 1,9 s · `/d/Exploit` 5,6 s · `/d/exploit` 3,2 s — todos HTTP 404, corpo nginx 146 B. Frames em quarentena com sha256 (`/tmp/opencode/darkquarantine/m9-dread-*`, linhas no MANIFEST).
- Mirror Dread do OnionDir /cat2 (`dreadytofat…`) — varrido na m10 (ver linha abaixo).
- **m10 (2026-10-19, 2 janelas espaçadas)**: mirror `dreadytofat…` — `/d/PoC` 59,1 s e `/d/Exploit` 1,2 s, ambos HTTP 200, 6727 B, mesmo post fixado; instância “Dread2” sem subreads PoC/Exploit. Frames em quarentena (`m10-mirror-d-*`, linhas no MANIFEST).

## Regras de atualização (monitor 09:30)

1. Este arquivo é anexo vivente do monitor `darkweb-monitor.sh`; o doc principal (DARKWEB-SOURCES-v1.6) permanece fechado.
2. Ao aparecer 200 em `/d/PoC` ou `/d/Exploit` (ou novo subread de PoC no frontpage): popular a tabela com thread, data, resumo de 1 linha, CVE-ids e flag de PoC.
3. Só GET passivo, máx. 2 janelas por rodada, espaçadas; sem interação nunca.
4. PoC released = "sim" só quando o próprio thread anuncia/libera exploit; "parcial" quando há descrição/diagrama sem artefato; "não" quando é discussão/aviso sem exploit.
5. Atualização exige novo hash no MANIFEST + linha nova em `SHA256SUMS` (selo).
