# DARKWEB — Log de Queries (Rodada 1 do Query Playbook) — 2026-10

**Missão:** m12 · **Data:** 2026-10-20 (rodada executada 01:18–01:36 UTC) · **Operador:** Robin (deep/dark lane)
**Base:** `docs/ROBIN-QUERY-PLAYBOOK.md` §4 (primeira rodada, 6 categorias, queries como estão)
**Regra:** leitura passiva total (v2) · hit válido só com cruzamento de ≥2 fontes · sem PII · sem marketplace/registro

## 1. Execução (resumo)

- **18 queries onion** (c2×4, mirai×4, stealers×3, RAT×2, ransomware×3, PoC×2) em **onionland + tor66** (34 corridas, retry ×2 em rc=000).
- **Ahmia em 2 janelas** (≥10 s entre reqs, token vigente): w1 = `"redline stealer" builder`, `"mirai source"`, `"cobalt strike" cracked loader`; w2 = `asyncrat builder`, `"0day" exploit forum`, `"ransomware source"` (6 corridas).
- **Clearnet:** 11 dorks GitHub API (≥2 por categoria) + Sploitus (`CVE-2026`) + ransomware.live (homepage).
- **Evidência:** 47 frames em `/tmp/opencode/darkquarantine` com sha256 pré-análise (`/tmp/opencode/darkweb-m12/m12.sha256`) + entry no MANIFEST.
- **Parser:** `onionland` = extração por result-block (title/link/desc, ads+banners excluídos); `tor66`/`ahmia` = parser genérico m2 (anchors + contexto).

## 2. Metodologia de veredito

- **✅ cruzado** — mesmo host devolvido por ≥2 engines na mesma query (regra de ouro, 2 fontes).
- **⏳ 1 engine** — resultados orgânicos em só 1 engine (não validado; fica como sinal para monitor).
- **❌ sem sinal** — zero resultados orgânicos ou só ruído estrutural (ads/sidebar) em todas as engines.
- Exclusões estruturais: engines self, sidebar I2P (i2poulge), blocos de anúncio recorrentes (label-ad / promos tor66), e host-agregadores presentes em ≥12 das 17 queries do onionland.

## 3. Tabela onion (ts | engine | query | hits | top3 | veredito)

| ts | engine | query | hits | top3 | veredito |
|---|---|---|---|---|---|
| 2026-10-20 01:18Z | onionland | `"cobalt strike" cracked loader` | 15 | Cobalt Strike 4.9 — cracked — working beacon — Dead Drop — Respect OPSEC. Members: 5,665 Posts Today: 373 Onli ;; AceMarket | The #1 Cracked Wallet Market — Become a Vendor Contact The Leading Market in Cracked Wallets Brows ;; Cracked Wallets | High-Balance Crypto Access & Instant Profit — Bit & Buck About Home Cracked Wallets | High-B | ✅ cruzado (1 host em ≥2 engines) |
| - | ahmia | `"cobalt strike" cracked loader` | 9 | "> Cobalt Strike 4.9 — cracked — wor ;; "> s1nkhole < ;; Browse Cracked Software products on Pandorum. 40 products available. pandorumwzudcql6f3ourlqw2voyh332a4tke64x7 | ✅ cruzado (1 host em ≥2 engines) |
| 2026-10-20 01:19Z | onionland | `"malleable c2" profile` | 18 | purplebored/.profile: My Forgejo/Gitea profile - .profile - FSKY Foundry — This website requires JavaScript. E ;; Buy Read Profile: 0.5g Alprazolam Powder Xanax 99% - DarkHub — Listings you might be interested in A1CRACK Rea ;; OrangeFren - User Profile | KYCnot.me — About Swap Compare KYC-free exchange rates Login OrangeFren orangefren | ⏳ hit único de engine |
| 2026-10-20 01:20Z | onionland | `sliver c2 implant` | 17 | añol Français Русский Türkçe Tiếng Việt Português Mandarin Burmese پښتو ภาษาไทย اردو More Translations Index K ;; Pages Multimedia Hide CP Stalker - Advanced Smartphone RAT stalker2fxuaefnkbeqocfoeojbbkvektnsiohshjoxfp7xml7p ;; er-based C2 dashboard and a highly stealthy, persistent payload capable of full device takeover on both Androi | ⏳ hit único de engine |
| 2026-10-20 01:20Z | onionland | `havoc c2 framework` | 13 | añol Français Русский Türkçe Tiếng Việt Português Mandarin Burmese پښتو ภาษาไทย اردو More Translations Index K ;; Which C2 in 2026 — Sliver vs CS vs Havoc — Dead Drop — Respect OPSEC. Members: 5,665 Posts Today: 312 Online:  ;; Arti - Command and Control Framework - Arti Development - Tor Project Forum — Tor Project Forum Arti - Command | ⏳ hit único de engine |
| - | ahmia | `"mirai source"` | 161 | li class="result"> Source code ;; li class="result"> the problem with open source ;; li class="result"> source package impo | ⏳ hit único de engine |
| 2026-10-20 01:21Z | onionland | `"mirai botnet" builder` | 17 | Wix website hosting — Wix website hosting Author: Fenritaxe Date: 24.07.2020 Categories: Hack 2020 You can pur ;; ONIONLIST - Office Exploit Builder - Services — ONION LIST STONKER THAN BEFORE HOME ADD A WEBSITE SEARCH Categ ;; Popular X-Powered-By HTTP headers site-builder, SDWAF, etc. - HiddenWWW — HiddenWWW Docs Pricing Sign Up Log I | ⏳ hit único de engine |
| 2026-10-20 01:21Z | onionland | `mozi botnet` | 17 | v class="desc"> Buy Top List Of Advanced Keyloggers - Clean - Dark0de Reborn http://darkod6mcxq7bxwiup5oxhsrng ;; Botnet Ready setup 2023 - DARKWEB — Order ID Billing email Track DARKWEB Your Number One Web Tools Search for: ;; ONIONLIST - DECIPHER TOR Botnet - Services — HOME ADD A WEBSITE SEARCH Categories Markets Financial Communicat | ⏳ hit único de engine |
| 2026-10-20 01:22Z | onionland | `gafgyt botnet source` | 15 | Botnet Ready setup 2023 - DARKWEB — Order ID Billing email Track DARKWEB Your Number One Web Tools Search for: ;; ONIONLIST - DECIPHER TOR Botnet - Services — HOME ADD A WEBSITE SEARCH Categories Markets Financial Communicat ;; C# Botnet Coding [Full Video Tutorial] — Dashboard Market Wallets Riddler's Wheel Login Register Dashboard Mar | ⏳ hit único de engine |
| 2026-10-20 01:27Z | onionland | `"redline stealer" builder` | 17 | Wix website hosting — Wix website hosting Author: Fenritaxe Date: 24.07.2020 Categories: Hack 2020 You can pur ;; ONIONLIST - Office Exploit Builder - Services — ONION LIST STONKER THAN BEFORE HOME ADD A WEBSITE SEARCH Categ ;; Popular X-Powered-By HTTP headers site-builder, SDWAF, etc. - HiddenWWW — HiddenWWW Docs Pricing Sign Up Log I | ✅ cruzado (1 host em ≥2 engines) |
| - | ahmia | `"redline stealer" builder` | 134 | esult"> ;; esult"> Shop - Page 4 of 10 - An online ca ;; esult"> Botnets Archives | ✅ cruzado (1 host em ≥2 engines) |
| 2026-10-20 01:27Z | onionland | `lumma stealer` | 18 | More info here http://breached65xqh64s7xbkvqgg7bmj4nj7656hcb7x4g42x753r7zmejqd.onion/Thread-Profit-Maker-Pytho ;; Most KCN is used in gold mining, organic synthesis,... http://tamazoncmlw2ohkbsmqxnotudejdd4befrasxuigzzjumqu3 ;; stall Icon Changer Assembly Editor EXE Builder POISON CRYPTO STEALER – STEAL CRYPTO BY REPLACING COPIED WALLET | ⏳ hit único de engine |
| 2026-10-20 01:27Z | onionland | `vidar stealer source` | 17 | More info here http://breached65xqh64s7xbkvqgg7bmj4nj7656hcb7x4g42x753r7zmejqd.onion/Thread-Profit-Maker-Pytho ;; BITCOIN STEALER SOFTWARE - Bitcoin Stealer Tools Download - ⭐ Bitcoin Generator V2.0 — 967.56 BTC already paid ;; Maximize Gains with a High-Performance NFT Stealer — No more manual clicking, no more missed windows of opport | ⏳ hit único de engine |
| 2026-10-20 01:27Z | onionland | `"quasar rat" source` | 16 | Español Français Русский Türkçe Tiếng Việt Português Mandarin Burmese پښتو ภาษาไทย اردو More Translations Inde ;; Quasar RAT Golden Edition [Latest Version] — Dashboard Market Wallets Riddler's Wheel Login Register Dashboard ;; Lintian Tag: source-format — LINTIAN Tags User Manual About source -format This is the source format declared  | ⏳ hit único de engine |
| 2026-10-20 01:27Z | onionland | `asyncrat builder` | 17 | Wix website hosting — Wix website hosting Author: Fenritaxe Date: 24.07.2020 Categories: Hack 2020 You can pur ;; [FUD] AsyncRAT Pro — Dashboard Market Wallets Riddler's Wheel Login Register Dashboard Market Wallets Riddler' ;; ONIONLIST - Office Exploit Builder - Services — ONION LIST STONKER THAN BEFORE HOME ADD A WEBSITE SEARCH Categ | ✅ cruzado (6 host em ≥2 engines) |
| - | ahmia | `asyncrat builder` | 306 | page 24 ;; CERBERU ;; Buy drugs, crystal, meth, ketami | ✅ cruzado (6 host em ≥2 engines) |
| 2026-10-20 01:28Z | onionland | `lockbit builder` | 16 | LockBit 5.0 Released http://lockbitfbinpwhbyomxkiqtwhwiyetrbkb4hnqmshaonqxmsrqwg7yad.onion ;; Lockbit · RansomLook — RansomLook Data Recent Browse Trending Stats Intel URLs Crypto Leaks Notes Analyses Raa ;; LockBit Ransomware: The Dark Net’s Most Prolific Cybercrime Operation — Blog Advertise Directory Blog Advertis | ⏳ hit único de engine |
| 2026-10-20 01:28Z | tor66 | `"ransomware source"` | 18 | 5sxhz7sc534vav7cyvqd.onion" data-tooltip="Site informations">ⓘ http://ckz3voga72xjwbm7gdjpmy763twukj2z5ocz5sxh ;; zfigvsxrrktxicysi2yd.onion" data-tooltip="Site informations">ⓘ http://ransomlookumjrc6erzqn467lkcu2t5h4enjzfig ;; c3ejz6nlitf6wm7cxpqd.onion" data-tooltip="Site informations">ⓘ http://darkxnsugwf66g4zivlj3nfqie5hyc5ylyjpc3ej | ✅ cruzado (1 host em ≥2 engines) |
| - | ahmia | `"ransomware source"` | 172 | ass="result"> RANSOMWARE BUY RANSOMWARE BUY RAN ;; ass="result"> RANSOMWARE FOR HIRE | BUY R ;; ass="result"> Ransomware | ✅ cruzado (1 host em ≥2 engines) |
| 2026-10-20 01:28Z | onionland | `esxi encryptor` | 4 | Metasploit android commands pdf — Workstation through the rtdxrpt3wx3sk7mkp2l2ku7mrvrrgzzpvff7ik76ggss6by434fd ;; Mario Esxi · RansomLook — RansomLook Data Recent Browse Trending Stats Intel URLs Crypto Leaks Notes Analyses  ;; ⭐⭐⭐ Secure & Anonymous Casino on Tor | UNC3886: Espionage Operations Leveraging VMware ESXi... — Explore Raffl | ⏳ hit único de engine |
| 2026-10-20 01:28Z | onionland | `"0day" exploit forum` | 23 | Russian cybercrime forum that has been active since at least 2005 Russian speaking hacking forum Paid registra ;; SEARCH brutalse3fte6y4d6auvcfmt2fplgkiyky3ydn52d6nxlxwvkfse4pyd.onion Open service Search Results for Exploit  ;; Independent AI Model Lab kxchbcaij7r4af2ck2l3nbruzr4bjegqrhezohqhpwwdriuydhhhw3yd.onion Open service State of  | ✅ cruzado (1 host em ≥2 engines) |
| 2026-10-20 01:28Z | tor66 | `"0day" exploit forum` | 4 | awkes Market, UK ONLY DNM. BTC & XMR. Built for long term business. http://fawkesgrixgdi6mepgocuntt34o73okuasa ;; CARDS 🔒 FORUM 🕵️ HACKERS 🔞 PORN 🎁 GIFTS 📱 IPHONES http://marketzhgxyrw5w3q7pnmfg2yb3lgwb5n7m4aownfjoxilx5on75k ;; jhrxpjtkg4brmgqd.onion'>OnionDir OnionDir - Topic links. http://oniodtu6xudkiblcijrwwkduu2tdle3rav7nlszrjhrxpj | ✅ cruzado (1 host em ≥2 engines) |
| - | ahmia | `"0day" exploit forum` | 62 | ss="result"> 0day doc exploit - Blackhat Pak ;; ss="result"> 0day exploit doc - Blackhat Pak ;; ss="result"> | ✅ cruzado (1 host em ≥2 engines) |
| 2026-10-20 01:28Z | onionland | `"cve-2026" exploit` | 20 | SEARCH brutalse3fte6y4d6auvcfmt2fplgkiyky3ydn52d6nxlxwvkfse4pyd.onion Open service Search Results for Exploit  ;; ong> is an extremely long-running Russian cybercrime forum that has been active since at least 2005 Russian sp ;; ONIONLIST - Office Exploit Builder - Services — ONION LIST STONKER THAN BEFORE HOME ADD A WEBSITE SEARCH Categ | ⏳ hit único de engine |

## 4. Tabela clearnet (GitHub / Sploitus / ransomware.live)

| ts | source | query | total | top3 | status |
|---|---|---|---|---|---|
| 2026-10-20 01:34:20Z \| GitHub \| c2-cs \| cobalt-strike in:name,description \| 852 \| zer0yu/Awesome-CobaltStrike — List of Awesome CobaltStrike Resources ;; aleenzz/Cobalt_Strike_wiki — Cobalt Strike系列 ;; Sentinel-One/CobaltStrikeParser —  \| 200 |
| 2026-10-20 01:34:28Z \| GitHub \| c2-mal \| malleable-c2 \| 71 \| threatexpress/malleable-c2 — Cobalt Strike Malleable C2 Design and Reference Guide ;; rsmudge/Malleable-C2-Profiles — Malleable C2 is a domain specific language to redefine indicators in B ;; xx0hcd/Malleable-C2-Profiles — Cobalt Strike - Malleable C2 Profiles.  A collection of profiles used  \| 200 |
| 2026-10-20 01:34:35Z \| GitHub \| c2-sliver \| sliver implant language:go \| 1 \| BishopFox/sliver — Adversary Emulation Framework \| 200 |
| 2026-10-20 01:34:42Z \| GitHub \| mir-core \| mirai in:name language:c \| 205 \| hklcf/Mirai — Source code for the Mirai botnet - Not going anywhere anytime soon ;; Glowman554/mirai — Moved to https://git.toxicfox.de/toxicfox/mirai ;; jgamblin/Mirai-Source-Code — Leaked Mirai Source Code for Research/IoC Development Purposes \| 200 |
| 2026-10-20 01:34:50Z \| GitHub \| mir-bash \| bashlite \| 15 \| hammerzeit/BASHLITE — An archive of BASHLITE source code ;; ghPRao/IoT_Malware_Attacks — Predicting Internet of Things(IoT) Malware Attacks. Door Bells, Thermo ;; bashlite86/bashlite86.github.io —  \| 200 |
| 2026-10-20 01:34:57Z \| GitHub \| st-redline \| redline-stealer \| 65 \| borrcodes/Redline-Stealer —  ;; ivagonzalez1982/RedLineStealer — RedLine stealer Source Code (Decompiled) ;; CrackerCat/RedlineStealer — The cracked panel of redline stealer \| 200 |
| 2026-10-20 01:35:05Z \| GitHub \| st-lumma \| lumma stealer \| 67 \| x86byte/LummaC2-Stealer — LummaC2 extracted binaries by reversing & LummaC2 Stealer Analysis ;; luishuallpa1202-lab/LummaC2-Reverse-Engineering-Lab — LummaC2 Stealer Analysis and Binary Reversing Guide 2026 ;; alumarobalino/lumma-trace-forensics — LummaC2 Stealer Defense and Reverse Engineering Toolkit 2026 \| 200 |
| 2026-10-20 01:35:13Z \| GitHub \| rat-async \| asyncrat \| 100 \| NYAN-x-CAT/AsyncRAT-C-Sharp — Open-Source Remote Administration Tool For Windows C# (RAT) ;; we1h0/ElegyRAT-C-Sharp — Open-Source Remote Administration Tool For Windows C# (Be Based On Asy ;; whobornin1980/AsyncRAT — TCP Asynchronous Socket - Remote Administration Tool \| 200 |
| 2026-10-20 01:35:20Z \| GitHub \| rat-quasar \| quasarrat \| 42 \| baaslaawe/Quasar-RAT — Rat forked from https://github.com/quasar/QuasarRAT. New functionaliti ;; JPCERTCC/QuasarRAT-Analysis — QuasarRAT analysis tools and research report ;; Anton-ai111/QuasarRAT — QuasarRAT \| 200 |
| 2026-10-20 01:36:23Z \| GitHub \| poc-cve2026 \| CVE-2026 in:name,description \| 5182 \| theori-io/copy-fail-CVE-2026-31431 — Copy Fail (CVE-2026-31431): 9-year-old Linux kernel LPE found by Theor ;; Icex0/wp2shell-poc — wp2shell (CVE-2026-63030 & CVE-2026-60137) - full RCE chain ;; YuKongA/ghostlock-app — GhostLock One-Tap Execution App (CVE-2026-43499) \| 200 |
| 2026-10-20 01:36:30Z \| GitHub \| poc-awesome \| awesome-cve-poc \| 5 \| qazbnm456/awesome-cve-poc — ✍️ A curated list of CVE PoCs. ;; xbl3/awesome-cve-poc_qazbnm456 —  ;; hackthacker-sec/Awesome-CVE-POC-Index — A continuously updated CVE PoC index of publicly available proof-of-co \| 200 |
| 2026-10-20 01:36:38Z \| Sploitus \| CVE-2026 \| 5 \| CVE-2026-99999 ;; CVE-2026-99999  ;; CVE-2025-0282 \| - |
| 2026-10-20 01:36:40Z \| RansomwareLive \| homepage \| 21/75/55 \| Ransomware.live 👀 \| 200 |

## 5. Hosts cruzados (regra de 2 fontes)

- **`c2-q1`** — `"cobalt strike" cracked loader` — hosts cruzados: `kzmcudnrse3nbz5dtnqavv…` (ahmia, onionland): ahmia: "> Cobalt Strike 4.9 — cracked — wor ;; onionland: Cobalt Strike 4.9 — cracked — working beacon — Dead Drop — R
- **`st-q1`** — `"redline stealer" builder` — hosts cruzados: `btcx6jx725buaw2fahc4i5…` (ahmia, onionland): onionland: Website Hacking Tool | HACKING TOOLS | Multi Exploit Builder ;; ahmia: esult"> Bitcoin Generator V2.0
- **`rat-q2`** — `asyncrat builder` — hosts cruzados: `btcx6jx725buaw2fahc4i5…` (ahmia, onionland): onionland: Website Hacking Tool | HACKING TOOLS | Multi Exploit Builder ;; ahmia: Bitcoin Generator V2.0; `cuhebenhpxdqskoodifdh5…` (ahmia, onionland): onionland: gtk-builder-tool(1) — libgtk-3-bin — Debian experimental — D ;; ahmia: Contents of Debian t; `publicagv4whofakenfr4b…` (ahmia, onionland): onionland: Popular X-Powered-By HTTP headers site-builder, SDWAF, etc.  ;; ahmia: Popular meta-; `rtdxrpt3wx3sk7mkp2l2ku…` (ahmia, onionland): onionland: Wix website hosting — Wix website hosting Author: Fenritaxe  ;; ahmia: Types of c; `vzwveldr7djnlpg7ujslaq…` (ahmia, onionland): onionland: 2017/05/09 - SquirrelJME — I would say to have a class which ;; ahmia: SquirrelJME - Squirre; `wdo4k4wrpnqcxft7xvkysj…` (ahmia, onionland): onionland: page 24 — WalletWatch About Home Automated Patching vs Hacke ;; ahmia: page 24
- **`rw-q2`** — `"ransomware source"` — hosts cruzados: `darkpb3w7h5mmuzsdkiurl…` (ahmia, tor66): tor66: mlkvxwjgt3ufmrd4sgid.onion" data-tooltip="Site informations" ;; ahmia: ass="result"> Ransomware –
- **`poc-q1`** — `"0day" exploit forum` — hosts cruzados: `btcx6jx725buaw2fahc4i5…` (ahmia, onionland): onionland: 0day doc exploit - Blackhat Pakistan - ⭐ Bitcoin Generator V ;; ahmia: ss="result"> 0day exploit doc - Blackhat Pak


## 6. Veredito por categoria

- **C2 (Cobalt Strike/Sliver)**: `"cobalt strike" cracked loader` ✅ hits(OL/T66/AH=15/0/9) ×cross=1; `"malleable c2" profile` ⏳1 hits(OL/T66/AH=18/0/0); `sliver c2 implant` ⏳1 hits(OL/T66/AH=17/0/0); `havoc c2 framework` ⏳1 hits(OL/T66/AH=13/0/0)
- **Mirai/botnets**: `"mirai source"` ⏳1 hits(OL/T66/AH=0/0/161); `"mirai botnet" builder` ⏳1 hits(OL/T66/AH=17/0/0); `mozi botnet` ⏳1 hits(OL/T66/AH=17/0/0); `gafgyt botnet source` ⏳1 hits(OL/T66/AH=15/0/0)
- **Stealers**: `"redline stealer" builder` ✅ hits(OL/T66/AH=17/0/134) ×cross=1; `lumma stealer` ⏳1 hits(OL/T66/AH=18/0/0); `vidar stealer source` ⏳1 hits(OL/T66/AH=17/0/0)
- **RATs**: `"quasar rat" source` ⏳1 hits(OL/T66/AH=16/0/0); `asyncrat builder` ✅ hits(OL/T66/AH=17/0/306) ×cross=6
- **Ransomware**: `lockbit builder` ⏳1 hits(OL/T66/AH=16/0/0); `"ransomware source"` ✅ hits(OL/T66/AH=0/18/172) ×cross=1; `esxi encryptor` ⏳1 hits(OL/T66/AH=4/0/0)
- **PoC supply**: `"0day" exploit forum` ✅ hits(OL/T66/AH=23/4/62) ×cross=1; `"cve-2026" exploit` ⏳1 hits(OL/T66/AH=20/0/0)


## 7. As 3 mais produtivas

1. **`"cobalt strike" cracked loader`** — ✅ doble-engine; host cruzado `kzmcudnrse3…` = fórum "Dead Drop – Respect OPSEC" (thread CS 4.9 cracked + "Which C2 in 2026 – Sliver vs CS vs Havoc") + oferta em Pandorum (AH). **Sinal forte**: nome-oferta + frase exata.
2. **`"ransomware source"`** — ✅ cruzado via `darkpb3w7h5…` (AH + tor66); AH devolve 172 hosts ("RANSOMWARE FOR HIRE", lockbit pages); RansomLook como fonte cross. **Sinal forte**: vaga de oferta/venda + intel.
3. **`"0day" exploit forum`** — ✅ cruzado (AH + onionland): "Blackhat Pakistan" (0day doc exploit) + blog-audit do brutalse ("Russian cybercrime forum desde 2005") + OnionDir. **Sinal médio**: mais aggregadores que forum POC próprio.

## 8. As 3 que morreram

1. **`"malleable c2" profile`** — ❌ só ruído no onionland (18 hits = foruns JS/whatsapp/perfil pessoal), AH/t66 zero: perfil malleable é tema de **overview/repo clearnet** (GitHub 71), não de oferta onion. Reformular para tabela de "malleable profile github" no clearnet.
2. **`"cve-2026" exploit`** — ⏳ OL 20 mas todo ruído de fórum genérico; AH/t66 zero; GitHub/Sploitus cobre o PoC supply por CVE específico, não por frase. Reformular como "sploitus por CVE nome" em rodada futura.
3. **`mozi botnet`** — ⏳ OL 17 (ofertas/palavras genéricas) sem cruzamento; AH/t66 zero. Mozi está morto/dorme no onion; Gitub úmido p/ familia. Só vale como vigilância a ofertas "Botnet Ready setup" (oferta de renting).

## 9. Notas por engine

- **onionland** = **primária** para oferta/serviço: 15–23 resultados orgânicos/query em frases técnicas; único engine que entregou ofertas reais (cracked CS, FUD AsyncRAT, ransomware for rent, "Botnet Ready setup").
- **ahmia** = melhor full-text para **frase exata** (161–306 hosts em 3 queries composicha); atenção às seções "Related" que inflăm a contagem (dedup por host feito).
- **tor66** = **não é engine de negócio**: 0–4 orgânicos em 14/18 queries técnicas (só chrome + promos); útil como 2ª fonte de cruzamento barato e nos filings rw-q2/poc-q1.
- **GitHub** = fonte primária do *PoC/clearnet supply*: CVE-2026 = 5182 (idem ao banco do maestro ✔️), cobalt-strike 852 (host-atual 305 — cresceu), mirai 205 (com línc. restrictiva: in:name+language:c; o host-detector 7483 é o valor puro "mirai").
- **Sploitus** = fraca por frase; vou usar por CVE específico na próxima rodada (query-Back).
- **ransomware.live** = vivo; homepage com contadores de leak/groups (21/75/55 = vítimas/atores/na página).

## 10. Próximos passos (proposta para o maestro)

1. Passar para rodada 2 do playbook com as 5 queries ×cross confirmadas e mudar as 3 mortas para variações (`"malleable c2" profile github`, sploitus por-CVE, `mirai source github`).
2. Monitor: adicionar `kzmcudnrse…` (Dead Drop) e o tor66 o `darkpb3w7h5…` (pago hire?) à observação (leitura only) p/ PoC supply.
3. Manter os dorks do GitHub dos ratios-cron nas missões do livro (cobalt-strike/mirai/CVE-2026) — contagem atualizada aqui.
4. Catálogo PoC (m9): nenhum thread deste log deve entrar (nenhum PoC released no onion; só ofertas/vaga).
