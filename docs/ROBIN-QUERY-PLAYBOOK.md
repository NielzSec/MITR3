# ROBIN — Banco de Buscas Avançadas (Query Playbook v1)

**Data:** 2026-10-19 · Autor: maestro (OpenCode) · Operador: Robin (deep/dark lane)
**Regra base:** playbook §5/§9 — leitura passiva sempre liberada; **nunca** interação, registro, compra ou contato. Fórum/market = fonte de leitura, não de transação. **PII em claro jamais é coletada** (nenhuma query deste banco pede nomes/logs individuais).

> Princípio: engines onion são fracas em sintaxe, fortes em conteúdo. A precisão vem de **frases exatas + sinônimos técnicos em inglês + nome de família** — não de termos genéricos. "exploit" é ruído; "malleable c2 profile github" é sinal.

---

## 1. Sintaxe por engine (o que cada uma aceita de verdade)

| Engine | Sintaxe suportada | Notas |
|---|---|---|
| **Ahmia** (`ahmia.fi`) | `"frase exata"`, `-exclusão`, termos múltiplos = AND implícito | Full-text sobre onion; ignora operadores avançados (site:/intitle:). Rate-limit gentil: ≥10 s. |
| **DDG via Tor** (`duckduckgo.com`) | `"frase"`, `site:`, `intitle:`, `inurl:`, `filetype:`, `OR`, `-termo` | Melhor engine para achar página onion por tema: `site:.onion c2`. |
| **Torch** (`torch`) | `"frase"`, AND implícito | Índice velho; bom para histórico de fóruns. |
| **Tor66 / OnionLand / dnreport** | `"frase"` básica | Diretórios/agregadores parciais; usados p/ cruzar (2 engines = validação). |
| **GitHub API** (clearnet) | `q=termo+in:name,description,readme`, `language:`, `created:>`, `sort=updated` | 10 req/min sem auth. Melhor fonte real de PoC/C2/RAT source. |
| **grep.app** (clearnet) | UI via browser (portal/playwright); `/api/search` sem headers devolve HTML | Grep em código público; acha string de config/implant. |
| **Sploitus / Packet Storm / Exploit-DB** | busca por CVE/produto | Pivô clearnet após achar CVE no onion. |

**Regra de ouro:** toda query executa em ≥2 engines; veredito só com cruzamento. Hit isolado = "não validado".

---

## 2. Banco por categoria (queries cirúrgicas)

### 2.1 C2 / post-exploitation frameworks — P0
| Alvo | Queries (onion full-text) | Queries clearnet (GitHub/grep.app) |
|---|---|---|
| Cobalt Strike | `"cobalt strike" (cracked OR loader OR "4.9" OR 4.11)` · `"malleable c2" profile` · `"team server" cobalt strike leak` | `q=cobalt-strike+in:name,description` · `q=malleable-c2` · grep.app: `cobaltstrike` |
| Sliver | `sliver c2 implant` · `"sliver" armory extension` | `q=sliver+implant language:go` |
| Mythic | `mythic c2 agent docker` | `q=mythic+c2` |
| Havoc / C3 / Merlin / Covenant | `havoc c2 framework` · `covenant c2 grunt` · `merlin c2` | `q=havoc+c2` · `q=covenant+c2` |
| Brute Ratel / Nighthawk | `"brute ratel" (cracked OR "full version")` · `"nighthawk" c2` | `q=brute-ratel` |
| Config/implants | `"c2 profile" exchange` · `beacon config` · `"sleep mask" c2` | grep.app: `beacon` + `"user-agent"` |
| Panels/RaaS | `(c2 OR "command and control") panel builder` | — |

### 2.2 Mirai & botnets IoT — P0
| Alvo | Queries onion | Queries clearnet |
|---|---|---|
| Mirai core | `"mirai source"` · `"mirai leak"` · `"mirai botnet" builder` · `"mirai" cnc panel` | `q=mirai+in:name language:c` · `q=mirai+botnet` |
| Variantes | `satori botnet` · `mozi botnet` · `"gafgyt" OR bashlite source` · `tsunami botnet` · `qbot source` | `q=mozi+botnet` · `q=bashlite` · `q=qbot+botnet` |
| Loader/scanner | `"telnet scanner" botnet` · `"ssh bruteforce" botnet` · `"iot loader"` | `q="telnet"+scanner+language:c` |
| Painéis | `"botnet panel" api` · `"c2 panel" mirai` | — |
| Pivô CVE IoT | (usar CVE achada) + `router (exploit OR rce)` no onion | `q=nuclei-templates+iot` · Sploitus pela CVE |

### 2.3 Stealers / log markets — P0
| Alvo | Queries onion | Queries clearnet |
|---|---|---|
| RedLine | `"redline stealer" (builder OR source OR crack)` · `redline logs` | `q=redline-stealer` |
| Lumma / Vidar / Raccoon / Meta | `lumma stealer` · `vidar stealer source` · `raccoon stealer` · `"meta stealer"` | `q=lumma+stealer` · `q=vidar+stealer` |
| Log markets (só leitura/intel) | `"stealer logs" market` · `"fresh logs"` | ransomware.live não cobre; usar CTI | 
| Regra PII | **contar ofertas/preços/claims, nunca baixar logs** | — |

### 2.4 RATs — P1
`"quasar rat" source` · `"asyncrat" builder` · `njrat` · `"dcrat" panel` · `"venomrat"` · `remcos` · `xworm` — no GitHub: `q=asyncrat` · `q=quasarrat` · `q="remote+access+trojan" language:csharp`.

### 2.5 Ransomware ecosystem — P1
| Alvo | Queries |
|---|---|
| Famílias | `lockbit (builder OR source OR leak)` · `"blackcat" OR alphv` · `akira ransomware` · `play ransomware` · `clop` · `phobos ransomware source` · `qilin` · `medusa locker` |
| Código | `"ransomware source"` · `"locker source"` · `"esxi encryptor"` · `"affiliate panel" ransomware` |
| Pivô clearnet | `ransomware.live` API · `ransomwatch` (GitHub) · contar vítimas por setor/país, sem PII de vítimas |

### 2.6 Exploit/PoC supply — P0
- GitHub: `q=CVE-2026 in:name,description` · `q="poc" in:readme created:>2026-01-01` · `q=awesome-cve-poc` · `q=exploit language:python`
- Clearnet: Sploitus (por CVE), Packet Storm, Exploit-DB, nuclei-templates (`cves/`)
- Onion: `"0day" (exploit OR poc) forum` · `"cve-2026" exploit` · `"proof of concept" rce`

### 2.7 Initial access brokers — P1 (leitura/vitrine; nunca transacionar)
`"initial access broker"` · `"vpn access" corporate` · `"rdp access"` · `citrix access` · `"network access" sale` — registrar apenas **tipo/oferta/região declarada**, nunca identidades/PII.

### 2.8 Phishing / loader kits — P1
`"phishing kit" (gravity OR 16shop OR "xerxes")` · `scampage` · `"evilginx" phishlet` · `"reverse proxy" phishing` — clearnet: `q=phishlet`.

### 2.9 Bulletproof / abuso de infra — P2
`"bulletproof hosting"` · `"offshore hosting" "no logs"` · `"dmca ignored"` — mapear provedores citados (nome do serviço, não cliente).

### 2.10 Credential/breach intel — P2 (bounded)
`combolist (stats OR count)` · `"breach" database sale` — **agregados apenas**; nunca baixar, nunca armazenar credenciais.

### 2.11 Dread/catálogo — P2
`site:dread*.onion` via DDG? Dread não indexa bem — usar a frontpage de subdreads (já mapeada) e as queries de categoria dentro dos boards públicos de leitura.

---

## 3. Protocolo de validação (Robin)

```
ts | engine | query | hits (nº) | top3 (título curto) | veredito (vivo/morto/não validado)
```
1. Toda query roda em **≥2 engines**, 2 janelas espaçadas (≥10 s Ahmia).
2. Hit só entra no catálogo se cruzou ≥2 fontes **ou** se o domínio é da família conhecida (github.com, packetstorm...).
3. Não clicar em links de market/forum além da página pública do resultado; nada de login.
4. Selo: SHA256 do log + linha no MANIFEST.
5. Expansão de sinônimos é medida de sucesso: cada categoria deve registrar ≥2 variantes que funcionaram melhor.

## 4. Primeira rodada (m12) — prioridades

| # | Categoria | Queries a validar |
|---|---|---|
| 1 | C2 (Cobalt Strike/Sliver) | 4 queries onion + 3 GitHub |
| 2 | Mirai/variantes | 4 onion + 3 GitHub |
| 3 | Stealers (RedLine/Lumma) | 3 onion + 2 GitHub |
| 4 | RATs | 2 onion + 2 GitHub |
| 5 | Ransomware | 3 onion + ransomware.live |
| 6 | PoC supply | GitHub `CVE-2026` + Sploitus |

Saída: `docs/DARKWEB-QUERY-LOG-2026-10.md` (tabela §3) + atualização deste banco com o que funcionou (marcar ✅/❌ por query) + re-selo do playbook se §12 for adicionada.

---

## 12. Primeira rodada — placar m12 (2026-10-20 UTC)

Fonte da verdade: `docs/DARKWEB-QUERY-LOG-2026-10.md` (§2 metodologia, §9 notas por engine).

| # | Query (§2/§4) | OL | T66 | AH | GitHub/Sploitus | Veredito |
|---|---|---|---|---|---|---|
| 1 | `"cobalt strike" cracked loader` | 15 | 0 | 9 | 852 | ✅ cruzado 2-fontes (`kzmcudnrse…` fórum "Dead Drop") |
| 2 | `"malleable c2" profile` | 18 | 0 | 0 | 71 | ❌ só ruído no onion — reformular p/ `… profile github` (clearnet) |
| 3 | `sliver c2 implant` | 17 | 0 | 0 | 1 | ⏳ onion-só — sinal médio (RAT/C2 dashboards) |
| 4 | `havoc c2 framework` | 13 | 0 | 0 | — | ⏳ onion-só ("Which C2 in 2026" thread) |
| 5 | `"mirai source"` | 0 | 0 | 161 | 205/15 | ⏳ AH-só (full-text forte; dedup cliente) |
| 6 | `"mirai botnet" builder` | 17 | 0 | 0 | — | ⏳ ruído de listing em OL |
| 7 | `mozi botnet` | 17 | 0 | 0 | — | ❌ sem cruzamento; mozi dorme no onion — vigilância apenas |
| 8 | `gafgyt botnet source` | 15 | 0 | 0 | 15 | ⏳ sinal fraco (tutoriais de "C# botnet") |
| 9 | `"redline stealer" builder` | 17 | 0 | 134 | 65 | ✅ cruzado (multi-exploit builder, sinal médio) |
| 10 | `lumma stealer` | 18 | 0 | 0 | 67 | ⏳ sinal bom no OL (crypto-stealer offers) |
| 11 | `vidar stealer source` | 17 | 0 | 0 | — | ⏳ sinal fraco (bitcoin/NFT stealer) |
| 12 | `"quasar rat" source` | 16 | 0 | 0 | 42 | ⏳ sinal bom ("Quasar RAT Golden Edition") |
| 13 | `asyncrat builder` | 17 | 0 | 306 | 100 | ✅ cruzado ×6, mas 5 hosts = ruído (Debian/wix/etc) — sinal baixo |
| 14 | `lockbit builder` | 16 | 0 | 0 | — | ⏳ sinal líder no OL (LockBit 5.0 page + RansomLook) |
| 15 | `"ransomware source"` | 0 | 18 | 172 | ransomware.live vivo | ✅ cruzado via AH+T66 (`darkpb3w7h5…` "for hire" pages) |
| 16 | `esxi encryptor` | 4 | 0 | 0 | — | ⏳ sinal fraco; reformular p/ `esxi_vmware encryptor` |
| 17 | `"0day" exploit forum` | 23 | 4 | 62 | awesome-cve-poc(5) | ✅ cruzado (aggregadores + brutalse), sinal médio |
| 18 | `"cve-2026" exploit` | 20 | 0 | 0 | 5182 | ❌ frase não acende onion — PoC supply p/ Sploitus por-CVE |

**Placar:** 5 ✅ cruzadas · 11 ⏳ onion-só (sinal p/ monitor) · 2 ❌ (nos. 2, 7, 18 — reformulação na rodada 2).
**Prêmios por engine:** frase-exata+ferramenta (✅1/9/15) e nome-venda ("Golden Edition", "FUD", "5.0 Released") são os padrões de melhor rendimento no onionland; AH full-text é o 2º melhor recurso; tor66 não serve para queries técnicas (0–4 orgânicos em 14/18) — mantê-lo só como 2ª fonte barata de cruzamento.
