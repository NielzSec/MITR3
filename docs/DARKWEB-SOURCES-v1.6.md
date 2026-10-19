# DARKWEB-SOURCES-v1.6 — índice curado de fontes .onion (Robin / MITR3)

> Data: 2026-10-19 18:26 UTC · Executor: Robin (lane deep/dark web) · Infra: Tor local (SOCKS 127.0.0.1:9050) + `bin/darkweb.sh`
> Método: requisições GET passivas (sem login/posting/transação), User-Agent Firefox, timeouts 45–100 s;
> M1: 21 buscas no Ahmia (~11 mil pares) e 47 hosts validados por GET (37 v3/v4 + 10 v2). M2: 16 consultas de cruzamento em 6 engines; dread-current confirmado por 2 fontes e validado (48º host). M3: board Exploits do DHZ varrido (2 páginas/30 tópicos) + 3 agregadores clearnet validados; 3ª janela de estabilidade; estudo educado do token Ahmia (6 reqs, ≥10 s). M4: f=13 (Tools) varrido (5 págs/121 tópicos) sem agregador onion; 5ª janela de estabilidade; manutenção dos refs via GitHub API. M5: hunt fora do DHZ (hiddenwiki/daniel/torsearch + 5 engines) sem agregador PoC onion; monitor diário virou procedimento + script. M6: HeLL mapeado (boards públicas) e removido por política (marketplace de carding/RATs); hunt de fóruns em 5 engines sem novo fórum exploit policy-clean. M7: OnionDir varrido (Forums/Hacking/Security) — XSS e Dread confirmados como hosts adicionais, GETs sem resposta. M8: core cross 2 fontes fechado mas GET rc=97 (morto provisório); xsscentral sem endereço em 5 consultas espaçadas; xss.is só menções; política v2 propagada (heLL, torport-news e blackhat-blog voltam marcados); série de hunt encerrada com conclusão consolidada.
> Bodies baixados ficam em `/tmp/opencode/darkquarantine/` com `sha256` registrado **antes** de qualquer análise.
> Regras: `~/MITR3/docs/DEEPDARK-PLAYBOOK.md` (§2) — operação estritamente passiva, sem PII em claro, sem mercado.

## 1. Resumo
- Fontes indexadas: 28 · vivas: 27 · parciais: 1
- Referências clearnet validadas: 3 (agregadores de PoC citados no DHZ — §8).
- Observadas e não indexadas: 11 (mortas/timeout, não validadas ou sem valor de fonte — §9)
- Endereços v2 herdados do `onionsearch` re-testados: 10 (ver §10 — mortos por protocolo Tor v3).
- Baselines (Ahmia/DuckDuckGo) re-verificados com evidência (hashes em §11).

## 2. Registro bruto de validação
| fonte | veredito | evidência |
|---|---|---|
| `ahmia` | **VIVO** | HTTP 200 · 6.716595s · 4735 B · título: Ahmia — Search Tor Hidden Services |
| `ddg` | **VIVO** | HTTP 200 · 7.024956s · 233501 B · título: DuckDuckGo - Protection. Privacy. Peace of mind. |
| `torch` | **VIVO** | HTTP 200 · 12.815204s · 9227 B · título: The Original Dark Web Search Engine | Torch! |
| `onionland` | **VIVO** | HTTP 200 · 19.846481s · 300982 B · título: OnionLand Search Engine - Deep Web and Tor .onion Search |
| `tor66` | **VIVO** | HTTP 200 · 5.432564s · 17603 B · título: Tor66 - Search and Find .onion websites |
| `oss` | parcial (captcha) | HTTP 200 · 9.158043s · 1298 B · título: OSS - Captcha |
| `submarine` | **VIVO** | HTTP 200 · 15.801520s · 8194 B · título: Submarine - Search for Hidden Services |
| `dnreport` | **VIVO** | HTTP 200 · 5.300313s · 16420 B · título: darknet.report — Search indexed Tor services by title, topic, and metadata |
| `hiddenwiki` | **VIVO** | HTTP 200 · 4.296928s · 214337 B · título: The Hidden Wiki |
| `daniel` | **VIVO** | HTTP 200 · 12.399145s · 122845 B · título: Daniel Winzen &#8211; Web- und Server-Experte |
| `torsearch` | **VIVO** | HTTP 200 · 10.159211s · 151398 B · título: Hidden Wiki - Find latest DarkWeb Markets , Search Engines , Forums , Emails and much more |
| `darkhackerzone` | **VIVO** | HTTP 200 · 9.976384s · 40437 B · título: Dark Hacker Zone &bull; Index page |
| `dread-current` | **VIVO** | HTTP 200 · 20.872612s · 257611 B · título: Frontpage - Dread |
| `hellforum` | **VIVO** | HTTP 200 · 52.7s · 97100 B · título: Hell Forum |
| `notrace` | **VIVO** | HTTP 200 · 31.631707s · 1453 B · título: Index of / |
| `libgen` | **VIVO** | HTTP 200 · 9.434293s · 1348 B · título: GenoType.INC |
| `biblionex` | **VIVO** | HTTP 200 · 7.593818s · 9030 B · título: Bibliotheca Nex Alea |
| `gnupg-ftp` | **VIVO** | HTTP 200 · 6.052180s · 4232 B · título: Index of / |
| `glab` | **VIVO** | HTTP 200 · 6.510480s · 2999 B · título: 0xacab - code hosting for friendly people |
| `archive-db` | **VIVO** | HTTP 200 · 2.096814s · 1839 B · título: Index of / |
| `moneroobs` | **VIVO** | HTTP 200 · 7.183527s · 9876 B · título: Monero Observer - Frontpage News |
| `ssd-eff` | **VIVO** | HTTP 200 · 9.382272s · 30134 B · título: Surveillance Self-Defense |
| `btcwiki` | **VIVO** | HTTP 200 · 5.782115s · 58814 B · título: Bitcoin Wiki |
| `wdo-news` | **VIVO** | HTTP 200 · 8.614378s · 16369 B · título: WalletWatch |
| `usb-news` | **VIVO** | HTTP 200 · 8.084485s · 18454 B · título: FlowFinance |
| `wgruul-news` | **VIVO** | HTTP 200 · 2.907754s · 21664 B · título: Vigilant |
| `torport-news` | **VIVO** | HTTP 200 · 5.555767s · 13199 B · título: TorPortal, the Tor market and dark news portal for 2026 |
| `blackhat-blog` | **VIVO** | HTTP 200 · 6.168668s · 33454 B · título: Verified Domain Marketplace | Buy and Sell Trusted Domains |
| `gh-pocingithub` | **VIVO** | HTTP 200 · 5.933s · 292876 B · título: GitHub - nomi-sec/PoC-in-GitHub: 📡 PoC auto collect from GitHub. ⚠️ Be careful Malware. · GitHub |
| `gh-cveintel` | **VIVO** | HTTP 200 · 7.363s · 372584 B · título: GitHub - yadavnikhil17102004/CVE-Intel: Native Go engine for automated aggregation, sanitization, and JSON-exporting of global CVE exploit Proof-of-Concepts. Co |
| `gh-cvemapping` | **VIVO** | HTTP 200 · 4.686s · 333564 B · título: GitHub - rix4uni/cvemapping: This repo Gathers all available cve exploits from github.⚠️ Be careful Malware. · GitHub |
| `haystak` | morto (timeout x2) | sem resposta útil (curl rc=28, 25.001592s) |
| `phobos` | morto (socks x2) | sem resposta útil (curl rc=97, 13.104131s) |
| `darksearchenginer` | morto (timeout x2) | sem resposta útil (curl rc=28, 25.001394s) |
| `dread` | morto (timeout x2) | sem resposta útil (curl rc=28, 25.001729s) |
| `xss` | morto (endereco-55-invalido) | sem resposta útil (curl rc=97, 0.000255s) |
| `hiddenwiki-mirror` | morto (timeout) | sem resposta útil (curl rc=28, 35.001468s) |
| `lantern` | morto (timeout) | sem resposta útil (curl rc=28, 35.001812s) |
| `glitch` | morto (timeout x2) | sem resposta útil (curl rc=28, 45.001732s) |
| `yellowlabs` | **VIVO** | HTTP 200 · 9.865911s · 193829 B · título: 1. The Best Hackers For Hire | Hire a Hacker | #1 Y3llowl4bs |
| `torz-poc` | **VIVO** | HTTP 200 · 8.547388s · 164855 B · título: #1 Mobile Hacker For Hire - Fast Hacking Services For Hire |
| `h2-news` | **VIVO** | HTTP 200 · 5.343479s · 42254 B · título: Hacking Team | Elite Hackers on Deepweb |

## 3. Engines / portais de busca

### ahmia — **VIVO** (2026-10-19)
- **URL**: `http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 6.716595s · 4735 B · título: Ahmia — Search Tor Hidden Services
- **sha256 (frame baixado)**: `734ae9459c1aa207819020d5582ae8dda47e650776d81b1d2e9967b79e78acad` (4735 B)
- **O que oferece**: Indexador do Tor Project (Ahmia/Hermes Center); busca exige token anti-scrape dinâmico (ver §Achados).

### ddg — **VIVO** (2026-10-19)
- **URL**: `https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 7.024956s · 233501 B · título: DuckDuckGo - Protection. Privacy. Peace of mind.
- **sha256 (frame baixado)**: `310d00482c462c5fb769a7bbd6faabbcfebd4899f3fd5fcd63aa9d75011e40b6` (233501 B)
- **O que oferece**: Versão .onion do DuckDuckGo: busca própria + baseline de conectividade Tor.

### torch — **VIVO** (2026-10-19)
- **URL**: `http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 12.815204s · 9227 B · título: The Original Dark Web Search Engine | Torch!
- **sha256 (frame baixado)**: `019e16aa3597bb46867abbb829eedabf267a565d175fd3d4dee2c923412f01d6` (9227 B)
- **O que oferece**: Engine mais antiga em operação ("The Original Dark Web Search Engine"); índice grande, resultados mistos/spam.

### onionland — **VIVO** (2026-10-19)
- **URL**: `http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 19.846481s · 300982 B · título: OnionLand Search Engine - Deep Web and Tor .onion Search
- **sha256 (frame baixado)**: `2fb0fb9ad8760ca365296df2da6d731f773717a39f8a7b687f7097e7457459bd` (300982 B)
- **O que oferece**: Engine moderna com API própria e boa cobertura; também usada como fonte pelo onionsearch.

### tor66 — **VIVO** (2026-10-19)
- **URL**: `http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 5.432564s · 17603 B · título: Tor66 - Search and Find .onion websites
- **sha256 (frame baixado)**: `6d4cf391734598527e2b67c56e2367d0fdbf4d8a670f70f61c0a7211feec87fe` (17603 B)
- **O que oferece**: Portal de busca com categorias e lista de links; instável (falhou na 1ª tentativa, ok na 2ª em 5,4 s).

### oss — parcial (captcha) (2026-10-19)
- **URL**: `http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 9.158043s · 1298 B · título: OSS - Captcha
- **sha256 (frame baixado)**: `72f94a8f45d67cde322ccfb7e0d7fda9759288696137a6ce57ccbe7725001fd7` (1298 B)
- **O que oferece**: OnionSearchServer — backend agregador do onionsearch; erige captcha (recuado sem contornar, registrar).

### submarine — **VIVO** (2026-10-19)
- **URL**: `http://no6m4wzdexe3auiupv2zwif7rm6qwxcyhslkcnzisxgeiw6pvjsgafad.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 15.801520s · 8194 B · título: Submarine - Search for Hidden Services
- **sha256 (frame baixado)**: `e4b2f7bcac10878cd5128bfeb6a64f3fd147abd9b463efeecc21bb16ee50f0dd` (8194 B)
- **O que oferece**: Engine "Submarine" (ex-Torgle); formulário simples de busca, saída HTML.

### dnreport — **VIVO** (2026-10-19)
- **URL**: `http://kgng6hv2o2gtv6rzukdis6s74vpubuvjtknewb3npk7axp442nppxuqd.onion/`
- **Tipo**: engine
- **Evidência**: HTTP 200 · 5.300313s · 16420 B · título: darknet.report — Search indexed Tor services by title, topic, and metadata
- **sha256 (frame baixado)**: `831c326a7ff911f6aacbab0615131d4b0ca0a7e82a12c004f85cfcd7621611ee` (16420 B)
- **O que oferece**: darknet.report — busca serviços Tor indexados por título, tópico e metadados.

## 4. Diretórios e índices de .onion

### hiddenwiki — **VIVO** (2026-10-19)
- **URL**: `http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/`
- **Tipo**: dir
- **Evidência**: HTTP 200 · 4.296928s · 214337 B · título: The Hidden Wiki
- **sha256 (frame baixado)**: `7abc4257112c4689af6174eb547af908ce67958611f53b7b869fee39d2758539` (214337 B)
- **O que oferece**: O Hidden Wiki (oficial): diretório clássico de links .onion por categoria; raiz redireciona para /wiki/; muitos links mortos/isca.

### daniel — **VIVO** (2026-10-19)
- **URL**: `http://danielas3rtn54uwmofdo3x2bsdifr47huasnmbgqzfrec5ubupvtpid.onion/`
- **Tipo**: dir
- **Evidência**: HTTP 200 · 12.399145s · 122845 B · título: Daniel Winzen &#8211; Web- und Server-Experte
- **sha256 (frame baixado)**: `9c1a4a61a2bcb4a25c316c60d21c74b269c176ee7defdf2618b87853f1856030` (122845 B)
- **O que oferece**: Daniel Winzen — hoje site pessoal + mail/GitHub IPv6 proxy; NÃO é mais diretório onion (verificado na m5).

### torsearch — **VIVO** (2026-10-19)
- **URL**: `http://torwikijwqskahohtn35pyfde2uqmgrxgr2fru4mn4rer5muj445dxyd.onion/`
- **Tipo**: dir
- **Evidência**: HTTP 200 · 10.159211s · 151398 B · título: Hidden Wiki - Find latest DarkWeb Markets , Search Engines , Forums , Emails and much more
- **sha256 (frame baixado)**: `0d73e9c42579ae8df6ce9d115810878adaf245715067e3c4b50b3d6a927f1319` (151398 B)
- **O que oferece**: "TorSearch — Hidden Wiki": diretório/portal com listas amplas (inclui mercados — usar só como mapa de descoberta).

## 5. Fóruns de pesquisa e discussão

### darkhackerzone — **VIVO** (2026-10-19)
- **URL**: `http://wk54p5xel7uqhfl5uzpcqrk6npsx5td5jsa4iqrkmquimhynhks7ppyd.onion/`
- **Tipo**: forum
- **Evidência**: HTTP 200 · 9.976384s · 40437 B · título: Dark Hacker Zone &bull; Index page
- **sha256 (frame baixado)**: `c072ce454c0716e18b93d24f589d85fc46dfde9f90170c4777eaa202411035e7` (40437 B)
- **O que oferece**: Dark Hacker Zone — fórum de hackers com área de PoC/CVE (ex.: CVE-2026-1296); leitura p/ threat intel, zero interação.

### dread-current — **VIVO** (2026-10-19)
- **URL**: `http://dreadytu5e57d2xyx2fdgpvqnaf7zxhwr65k5vozpfbotulgv46lc7id.onion/`
- **Tipo**: forum
- **Evidência**: HTTP 200 · 20.872612s · 257611 B · título: Frontpage - Dread
- **sha256 (frame baixado)**: `4b9f64a3dcb6ab22ab5fa9d4362f9fe08492e9b5d383c3aca3a0d4a317410653` (257611 B)
- **O que oferece**: Dread (endereço corrente) — fórum estilo Reddit (/u/Paris); cross-fonte tor66+onionland; leitura passiva apenas.

### hellforum — **VIVO** (2026-10-19)
- **URL**: `http://atlasf35nmxs7734sfd2uv7oeuynekmj2mvs3uqk3p4mbfzbumwsk5qd.onion/`
- **Tipo**: forum
- **Evidência**: HTTP 200 · 52.7s · 97100 B · título: Hell Forum
- **sha256 (frame baixado)**: `1d3725b40d2c6e60db8f6bedbb24c1e11019c314ff866f0e56e8c9eb03b0f21b` (97100 B)
- **O que oferece**: HeLL (Reloaded) — fórum + marketplace pago; só leitura/intel (política v2). Frontpage pública: boards Exploits & Vulnerabilities/Tools & Software, filtros Tutorial/Exploit/Tool; mirror atlasf35 serve as boards, canônico hellfor6lms7 serve a landing; nunca registrar/comprar.

## 6. Acervos e bibliotecas

### notrace — **VIVO** (2026-10-19)
- **URL**: `http://libraryhmny4k3t424tznkzs3776hkn3tw5wijt2bqjvavpwh4544mqd.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 31.631707s · 1453 B · título: Index of /
- **sha256 (frame baixado)**: `85e52408d074236c0446ff607847701abd3ac158ff55ab7cf260bad3adacca5f` (1453 B)
- **O que oferece**: Biblioteca/índice estático (Anarchy, Economics, Guides, Manipulation...) associado ao No Trace Project (opsec anti-vigilância).

### libgen — **VIVO** (2026-10-19)
- **URL**: `http://libgenfrialc7tguyjywa36vtrdcplwpxaw43h6o63dmmwhvavo5rqqd.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 9.434293s · 1348 B · título: GenoType.INC
- **sha256 (frame baixado)**: `191f4ff7c87816f8e472a7e9cb6e1ef2195bbb4882d036de03b038e5d6e86636` (1348 B)
- **O que oferece**: Mirror oficial do Library Genesis em Tor ("GenoType.INC") — livros/artigos técnicos.

### biblionex — **VIVO** (2026-10-19)
- **URL**: `http://urzthcil4cjyfxqbs2jtjgebuyrr6du7oqsrvw2zgqepj5cqnndtkgad.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 7.593818s · 9030 B · título: Bibliotheca Nex Alea
- **sha256 (frame baixado)**: `f1080e97181642f3a89b2f72fd22284bdf2935761dd895dcfea61e0fa36f3a83` (9030 B)
- **O que oferece**: Bibliotheca Nex Alea — biblioteca de designs de fabricação (impressão 3D e improvisos) + field guides; CONTEÚDO SENSÍVEL, referência apenas.

### gnupg-ftp — **VIVO** (2026-10-19)
- **URL**: `http://5gxsihf4vjdhimiotrhchihrfujoanondrplizofwparrtmgbwsafhid.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 6.052180s · 4232 B · título: Index of /
- **sha256 (frame baixado)**: `8be3ca28531875e34b7b2cfaeb179438cdfd2773b8fdee7102e86a019956adad` (4232 B)
- **O que oferece**: Servidor de arquivos (estilo FTP) espelhando repositórios de distros: Arch, BlackArch, Gentoo, AlmaLinux, Endeavour e outros.

### glab — **VIVO** (2026-10-19)
- **URL**: `http://wmj5kiic7b6kjplpbvwadnht2nh2qnkbnqtcv3dyvpqtz7ssbssftxid.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 6.510480s · 2999 B · título: 0xacab - code hosting for friendly people
- **sha256 (frame baixado)**: `27a5cfee4897021f939a05f9183f40874c877abb02bf292e92c3bc42334837e5` (2999 B)
- **O que oferece**: 0xacab — hospedagem de código (GitLab) de coletivos; espelho onion com código-fonte de ferramentas.

### archive-db — **VIVO** (2026-10-19)
- **URL**: `http://e3y5vky4v7snefqyhbn6kcmyl5fo4cnk3a2irh2ttvwua46ww5ubl6qd.onion/`
- **Tipo**: archive
- **Evidência**: HTTP 200 · 2.096814s · 1839 B · título: Index of /
- **sha256 (frame baixado)**: `0a7786c61ea5d221401e70cb4cc60fedb3254c31035c157eece72304557e5fdb` (1839 B)
- **O que oferece**: Mirror HTTP de repositórios Bitcoin (bitcoin-bips, bitcoin-core, secp256k1…), sincronizado 19-Out-2026; estilo git-archive.

## 7. Recursos de pesquisa, notícias e opsec

### moneroobs — **VIVO** (2026-10-19)
- **URL**: `http://ttq5m3lsdhjysspvof6m72lbygclzyeelvn3wgjj7m3fr4djvbgepwyd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 7.183527s · 9876 B · título: Monero Observer - Frontpage News
- **sha256 (frame baixado)**: `089ee28065f17d8d1616a87f6c64feb61019c4d9f579ceb27cb3e595240cc870` (9876 B)
- **O que oferece**: Monero Observer — notícias e pesquisa sobre privacidade/Monero.

### ssd-eff — **VIVO** (2026-10-19)
- **URL**: `http://y7yea4pmqqtznb33qiugvysyn2bob5v62e4pvoadoibrwkq3tsddjeyd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 9.382272s · 30134 B · título: Surveillance Self-Defense
- **sha256 (frame baixado)**: `fb4dfa5ddcb0a7a3b8ca73caae9a5dbf9ec15d80189fa1282a8bde8e869b8bb7` (30134 B)
- **O que oferece**: Surveillance Self-Defense (EFF) — guias de ameaças e opsec; espelho .onion.

### btcwiki — **VIVO** (2026-10-19)
- **URL**: `http://btcwikwfnbp7mn7qhpmnlgbhbe6fyj3lixgkb2kerulumioagu3xzcyd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 5.782115s · 58814 B · título: Bitcoin Wiki
- **sha256 (frame baixado)**: `b7e20d3a98f152e4006bc932a18bf2e532f3884ed2772e172558939e1a6b2c9e` (58814 B)
- **O que oferece**: Bitcoin Wiki — referência técnica (protocolo, software, história).

### wdo-news — **VIVO** (2026-10-19)
- **URL**: `http://wdo4k4wrpnqcxft7xvkysjv5z3gykw2pppuq6zwgohr6hjqdhfpu4lqd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 8.614378s · 16369 B · título: WalletWatch
- **sha256 (frame baixado)**: `16224efa901a8ac419d05f9e24752415f1ddad3173f9c5c90c2d880af7972f94` (16369 B)
- **O que oferece**: WalletWatch — notícias de breaches, ransomware e social engineering.

### usb-news — **VIVO** (2026-10-19)
- **URL**: `http://3rn3tgask2wfxjnn7rcvdd2npsyesv7oxxfjeyx7huvi4rtwvnk2vkyd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 8.084485s · 18454 B · título: FlowFinance
- **sha256 (frame baixado)**: `96ea5b13572bd91860937bbc9a73ff7383d1f84afd048a2e1b7e10502beb5b32` (18454 B)
- **O que oferece**: FlowFinance — blog de notícias cyber (risco, contratos, trabalho).

### wgruul-news — **VIVO** (2026-10-19)
- **URL**: `http://wgruul6cmayc2k2i7gx4nucia2fxgm3kqq4wsapt3pnaqz2x7azcx3yd.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 2.907754s · 21664 B · título: Vigilant
- **sha256 (frame baixado)**: `0190976e1e60cdc13d799190ce6959b069156578448e518b0aeca9655cba7f45` (21664 B)
- **O que oferece**: Vigilant — notícias cyber (IA, breaches, golpes); oscilou na m1, estável nos re-testes m2 (2,9 s).

### torport-news — **VIVO** (2026-10-19)
- **URL**: `http://torportbymf56ref5lqztbbsz7vunmkrkxsn47l67yaayvghmjqz2xid.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 5.555767s · 13199 B · título: TorPortal, the Tor market and dark news portal for 2026
- **sha256 (frame baixado)**: `c1aabe80c47b1831959aed5d3b050f7285c0d54299c3b920227e4ddf10c6b6a9` (13199 B)
- **O que oferece**: "TorPortal" — portal de mercado+notícias darkweb; reavaliado pela política v2 (leitura/intel permitida); só leitura.

### blackhat-blog — **VIVO** (2026-10-19)
- **URL**: `http://wzdmtm4d7pymbx5u46o7ihmqn5hdksmiow2mu5hnjgd57xlomgqg4tid.onion/`
- **Tipo**: res
- **Evidência**: HTTP 200 · 6.168668s · 33454 B · título: Verified Domain Marketplace | Buy and Sell Trusted Domains
- **sha256 (frame baixado)**: `b578d6b3c9e933ab2096b3daff668148bf7be06b9f9b5eca80c1339a4a6b659c` (33454 B)
- **O que oferece**: "Verified Domain Marketplace" — marketplace de domínios; reavaliado pela política v2 (leitura permitida); utilidade: listagens/preços de domínios; só leitura.

## 8. Referências clearnet validadas (agregadores de PoC citados no Dark Hacker Zone)

### gh-pocingithub — **VIVO** (2026-10-19)
- **URL**: `https://github.com/nomi-sec/PoC-in-GitHub`
- **Tipo**: ref
- **Evidência**: HTTP 200 · 5.933s · 292876 B · título: GitHub - nomi-sec/PoC-in-GitHub: 📡 PoC auto collect from GitHub. ⚠️ Be careful Malware. · GitHub
- **sha256 (frame baixado)**: `f4deb37e27023d08d237612b93ff1babbd97075222fc04228c4b2705175bd6c1` (292876 B)
- **O que oferece**: nomi-sec/PoC-in-GitHub — coleta automática de PoCs publicados no GitHub (citado no board Exploits do DHZ, t=411). Clearnet. Manutenção: pushed 2026-10-19T13:50Z · 8.136★ · master · ativo.

### gh-cveintel — **VIVO** (2026-10-19)
- **URL**: `https://github.com/yadavnikhil17102004/CVE_Map_hehe`
- **Tipo**: ref
- **Evidência**: HTTP 200 · 7.363s · 372584 B · título: GitHub - yadavnikhil17102004/CVE-Intel: Native Go engine for automated aggregation, sanitization, and JSON-exporting of global CVE exploit Proof-of-Concepts. Co
- **sha256 (frame baixado)**: `07eedd124876c62552f92ba8211b1b4dfaeb880338b806ef0505834326c5d39f` (372584 B)
- **O que oferece**: yadavnikhil17102004/CVE-Intel (ex-CVE_Map_hehe) — engine Go que agrega/sanitiza PoCs CVE e exporta JSON (DHZ t=410). Clearnet. Manutenção: pushed 2026-10-19T14:47Z · 3★ · main · ativo.

### gh-cvemapping — **VIVO** (2026-10-19)
- **URL**: `https://github.com/rix4uni/cvemapping`
- **Tipo**: ref
- **Evidência**: HTTP 200 · 4.686s · 333564 B · título: GitHub - rix4uni/cvemapping: This repo Gathers all available cve exploits from github.⚠️ Be careful Malware. · GitHub
- **sha256 (frame baixado)**: `ea8f91bc40d69990feef14c1a5c86fef5d68cffa4792b2567c9c64e19f63853d` (333564 B)
- **O que oferece**: rix4uni/cvemapping — reúne exploits CVE publicados no GitHub (DHZ t=400). Clearnet. Manutenção: pushed 2026-10-19T06:04Z · 142★ · main · ativo.

## 9. Observadas em teste e não indexadas (veredito e motivo de exclusão por entrada)

### haystak — morto (timeout x2) (2026-10-19)
- **URL**: `http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 25.001592s)
- **O que oferece**: Indexador amplo; 3 tentativas (45/60/100 s) sem resposta — morto nesta data.

### phobos — morto (socks x2) (2026-10-19)
- **URL**: `http://phobosxilamwcg75xt22id7aywkzol6q6rfl2flipcqoc4e4ahima5id.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=97, 13.104131s)
- **O que oferece**: Engine; SOCKS5 não conecta (2 tentativas).

### darksearchenginer — morto (timeout x2) (2026-10-19)
- **URL**: `http://l4rsciqnpzdndt2llgjx3luvnxip7vbyj6k6nmdy4xs77tx6gkd24ead.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 25.001394s)
- **O que oferece**: Engine; timeout (2 tentativas).

### dread — morto (timeout x2) (2026-10-19)
- **URL**: `http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 25.001729s)
- **O que oferece**: Endereço histórico (dreadytofat…) marcado como "Dread has moved" pelos índices; corrente indexado em Fóruns (dread-current).

### xss — morto (endereco-55-invalido) (2026-10-19)
- **URL**: `http://xssforumv3isucukbxhdhwz67hoa5e2voakcfkuiex4awjtcva5ood.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=97, 0.000255s)
- **O que oferece**: Corrente NÃO confirmado: cruzamento em 6 engines + "xss.is" sem consistência em ≥2 fontes — sem chute.

### hiddenwiki-mirror — morto (timeout) (2026-10-19)
- **URL**: `http://2222222cf2ta5bfavg45rfqbsy7m3viskwofek6sqkciptu5uvbtw5ad.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 35.001468s)
- **O que oferece**: Espelho "2222222..." do Hidden Wiki; timeout — prefixos repetidos são típicos de clones/iscas, não priorizar.

### lantern — morto (timeout) (2026-10-19)
- **URL**: `http://2ucup5hbhurmtvxvhi52nre355ufcft5gd3lefklrq6jmjzon3ay2jad.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 35.001812s)
- **O que oferece**: "Darknet Lantern"; timeout.

### glitch — morto (timeout x2) (2026-10-19)
- **URL**: `http://glitchhsnsy52ba4av7rjo4qvjdnfo75uv3ovbb35owve5emriqergyd.onion/`
- **Tipo**: dead
- **Evidência**: sem resposta útil (curl rc=28, 45.001732s)
- **O que oferece**: glitchhsns… — 2 timeouts nos re-testes m2 (45 s cada); descartado nesta janela.

### yellowlabs — **VIVO** (2026-10-19)
- **URL**: `http://twd6bfktlkhwluhj2ghjthx55pnp2dcuuhf6qqjz7vm2krsmwpz6crad.onion/`
- **Tipo**: dead
- **Evidência**: HTTP 200 · 9.865911s · 193829 B · título: 1. The Best Hackers For Hire | Hire a Hacker | #1 Y3llowl4bs
- **sha256 (frame baixado)**: `d0493d273b2f8355ff840bd428e6c3e84a3f65036caa17090464715b372af33e` (193829 B)
- **O que oferece**: "#1 Y3llowl4bs" — hacker-for-hire; v2: leitura nunca vetada, mas landing hire sem valor de fonte (não indexado).

### torz-poc — **VIVO** (2026-10-19)
- **URL**: `http://torzcd47rw4qh36g4yqxvv2tmifgmu6jjalkyqz4e4lzzwtfdfc7qaqd.onion/`
- **Tipo**: dead
- **Evidência**: HTTP 200 · 8.547388s · 164855 B · título: #1 Mobile Hacker For Hire - Fast Hacking Services For Hire
- **sha256 (frame baixado)**: `e6f50432c5f16086e1e34561819eef5a44270c50dce35a1dadcfbdae179e8d57` (164855 B)
- **O que oferece**: "Mobile Hacker For Hire" — serviço hacker-for-hire; v2: leitura permitida, mas landing hire sem valor de fonte (não indexado).

### h2-news — **VIVO** (2026-10-19)
- **URL**: `http://hackerl2kbkh45lakwjwcpgly4ylfz5iiijqd5gudkaekq322cvgl3qd.onion/`
- **Tipo**: dead
- **Evidência**: HTTP 200 · 5.343479s · 42254 B · título: Hacking Team | Elite Hackers on Deepweb
- **sha256 (frame baixado)**: `9eef09fa130f1d481edc68c959ca0dbce2c5eac3a95fdaf237a405708e2b29ed` (42254 B)
- **O que oferece**: "Hacking Team (Elite Hackers on Deepweb)" — landing hire; v2: leitura permitida, mas sem valor de fonte (não indexado).

## 10. Tabela histórica: engines embutidos no onionsearch (endereços v2, mortos)

`onionsearch` embute endereços **v2** — protocolo aposentado em 2021; todos falham em ~0,0002 s com
`curl rc=97` (SOCKS5 não consegue resolver). Re-testado 2026-10-19 para documentar a defasagem:

| engine (onionsearch) | endereço | resultado |
|---|---|---|
| v2-tordex | `http://tordex7iie7z2wcg.onion/` | morto (socks/inacessivel) |
| v2-tormax | `http://tormaxunodsbvtgo.onion/` | morto (socks/inacessivel) |
| v2-multivac | `http://multivacigqzqqon.onion/` | morto (socks/inacessivel) |
| v2-evosearch | `http://evo7no6twwwrm63c.onion/` | morto (socks/inacessivel) |
| v2-notevil | `http://hss3uro2hsxfogfq.onion/` | morto (socks/inacessivel) |
| v2-torgle1 | `http://torgle5fj664v7pf.onion/` | morto (socks/inacessivel) |
| v2-ose | `http://onionf4j3fwqpeo5.onion/` | morto (socks/inacessivel) |
| v2-deeplink | `http://deeplinkdeatbml7.onion/` | morto (socks/inacessivel) |
| v2-ahmia-old | `http://msydqstlz2kzerdg.onion/` | morto (socks/inacessivel) |
| v2-tor66-old | `http://5u56fjmxu63xcmbk.onion/` | morto (socks/inacessivel) |

## Achados operacionais (anti-scrape e instabilidade)

- **Ahmia exige token anti-scrape**: `GET /search/?q=<termo>` sem o campo dinâmico (`name="290b9f" value="e15aa0"`) responde **302 → home** (corpo vazio). Com o token, 200 e resultados completos. Isso explica o scraper do `onionsearch` retornar 0 resultados (ele não visita a home antes de buscar).
- **Engines enferrujam e oscilam**: `tor66` falhou por timeout (25 s) na 1ª rodada e voltou **VIVO** na 2ª (5,4 s) — sempre re-testar antes de descartar.
- **Haystak**: 3 tentativas (25–60 s de timeout cada) sem resposta — tratado como morto nesta data.
- **Transientes**: circuitos Tor variam; timeouts não devem ser lidos como morte definitiva sem 2ª tentativa.

### Atualização — re-teste (missão 2)

- **Re-teste em 2 janelas** (17:03 e 17:11 UTC): `wgruul` **VIVO** (4,7 s → 2,9 s), `archive-db` **VIVO** (45 s → 2,1 s, mirror de repositórios Bitcoin), `yellowlabs` **VIVO** (12,8 s → 9,9 s; hacker-for-hire — mantido fora do índice), `glitch` 2 timeouts nos re-testes m2 (descartado nesta janela).
- **Dread (endereço corrente)**: o endereço histórico `dreadytofat…` aparece marcado como *“Dread has moved”* nos índices; o candidato `dreadytu5e57…` foi confirmado por **tor66 + onionland**, e no 2º teste respondeu **VIVO** com `Frontpage - Dread` (layout estilo Reddit, /u/Paris) — indexado como `dread-current`. Dezenas de clones `dread*` (títulos spam) detectados e **não** indexados.
- **XSS**: cruzamento em 6 engines (ahmia, onionland, tor66, submarine, dnreport, torsearch) + busca `xss.is` **sem confirmação em ≥2 fontes** — permanece sem endereço corrente; não chutamos (regra da missão).
- **Índices de links/uptime** estilo dark.fail (tor.taxi, TorWatch, dnffmic…) observados durante o cruzamento; **não indexados** (linkam mercados).

### Atualização — missão 3

- **DHZ, board Exploits (f=14)**: 2 páginas / 30 tópicos varridos; a área PoC-CVE aponta para agregadores **clearnet** (GitHub), não onion: `nomi-sec/PoC-in-GitHub` (t=411), `CVE_Map_hehe`→`CVE-Intel` (t=410) e `rix4uni/cvemapping` (t=400) — todos validados por GET 200 via Tor e listados como referências; `Yudis-bit/DeFi-Exploit-PoCs` (t=406) → **404** (morto).
- **Fora de política / não indexados no DHZ**: t=126 “Exploit Packs” (binário em anexo — não baixado nem executado), t=26 “WATCH DOG” (builder de trojan WADOG2) e t=289 (venda de acesso/dados corporativos).
- **Estabilidade (3 janelas, UTC)**: `wgruul` 2,9 s (17:11) → 2,3 s (17:16) → 1,7 s (17:19); `archive-db` 2,1 s → 3,6 s → 1,6 s; `dread-current` 20,9 s → 7,1 s → 5,9 s. Veredito: estáveis; a latência do Dread caiu ao longo das janelas (periodicidade observada ~6–21 s).
- **Token Ahmia (estudo educado: ≤1 req/10 s, sem paralelismo)**: home emite token oculto (observado `69726b=37acce`, estável entre 2 GETs com 11 s); busca com esse token → **200**, aceito e reusado 3×; busca **sem** token → **302** para a home; cada página de resultado emite novo token (`b608fc=b76c19`). Fluxo recomendado: 1 GET da home + buscas espaçadas reusando o token; re-fetch da home quando rotacionar. Sem cookies e sem contorno.

### Atualização — missão 4 (monitoramento)

- **DHZ f=13 (Tools)**: 5 páginas / 121 tópicos listados; 12 tópicos abertos + busca interna por “onion” (3 tópicos — todos de IA). **Nenhum agregador PoC/exploit onion.** O padrão do f=13 é **clearnet/GitHub**: PatrowlHearsData (t=409), pwndbg (t=419), VulnLens (t=458), BugHunter-AI (t=467), mantishack (t=413), lamware (t=405), lattice9 (t=463) e osint-mcp-server (t=480), além de `blackarch.org` (t=211).
- **Onions externos citados no f=13 (2)**: `2e4wuv…` (t=581, serviço de IA “uncensored”) → **morto** (curl rc=97, 2 tentativas); `kxchbcai…` (t=486, lab de modelos de IA para hacking) → **2 timeouts** (50 s / 40 s). Nenhum é agregador de PoC — não indexados.
- **Estabilidade — janelas m4 (UTC)**: `wgruul` 1,6 s (17:23) e `archive-db` 2,1 s (17:23); `dread-current` **timeout 35 s às 17:24** e **vivo em 36,4 s às 17:28** — disponibilidade mantida, latência errática.

| fonte | 17:11 | 17:16 | 17:19 | 17:24 | 17:28 |
|---|---|---|---|---|---|
| `wgruul` | 2,9 s | 2,3 s | 1,7 s | 1,6 s | — |
| `archive-db` | 2,1 s | 3,6 s | 1,6 s | 2,1 s | — |
| `dread-current` | 20,9 s | 7,1 s | 5,9 s | timeout 35 s | 36,4 s |

- **Manutenção dos refs (GitHub API, 17:27 UTC)**: `nomi-sec/PoC-in-GitHub` pushed 2026-10-19T13:50Z · 8.136★ · master; `yadavnikhil17102004/CVE-Intel` pushed 14:47Z · 3★ · main; `rix4uni/cvemapping` pushed 06:04Z · 142★ · main — nenhum arquivado (`archived: false`).

### Atualização — missão 5 (hunt fora do DHZ + monitor)

- **Diretórios**: HiddenWiki → página `/wiki/0day` só aponta `qzbkwswfv5k2oj5d.onion` (**v2, morto** por protocolo); busca do wiki **desativada**. TorSearch → busca por “exploit” devolve 1 cópia de market (0 útil). Daniel → hoje é site pessoal (mail/GitHub IPv6 proxy), **não** é mais diretório.
- **Engines (ahmia, onionland, tor66, dnreport, submarine; query “exploit”)**: dominado por scam de “bitcoin exploit/generator”, hire-a-hacker e markets. Quatro candidatos com ≥2 engines validados por GET: `hdslkc4u…` = **Blue Key**, loja de exploits Office/PDF + RATs/crypters (fora de política); `rtdxrpt3…` = blog spam (“Mulig clothes bar”); `dgquftlj…` = **timeout** (55 s); `atlasf35…` = **Hell Forum** — fórum underground com seção Exploit/Tutorial, acesso pago — indexado como `hellforum`.
- **Conclusão**: não há agregador PoC onion “puro” fora do DHZ nesta varredura; o padrão é fórum com seção de exploit (DHZ, Hell) + GitHub clearnet.

### Monitor diário (rotina 09:30)

Procedimento repetível (passivo):
1. `~/MITR3/bin/darkweb-monitor.sh` — 3 GETs (wgruul, archive-db, dread-current), ≤50 s cada, sem login/paralelismo; log TSV em `~/MITR3/docs/monitor/AAAA-MM-DD.log` (ts, http, rc, tempo, bytes, título, sha256).
2. Classificar: **VIVO** ≤10 s · **LENTO** 10–50 s · **TIMEOUT** (rc=28).
3. 2 dias consecutivos de TIMEOUT → “morto provisório” no doc; retorno → reabilitar.
4. Mudança relevante de título/tamanho → abrir o frame em quarentena (hash já no log), comparar e anotar.
5. Atualizar o doc + selo somente quando houver mudança de estado. Captcha/login/JS → recuar e registrar.

### Atualização — missão 6 (mapa do HeLL + hunt de fóruns)

- **HeLL Forum — categorias públicas** (frontpage, sem registro): boards **General Discussion (15 tópicos) · Exploits & Vulnerabilities (15) · Tools & Software (15) · Cryptocurrency & Blockchain (5) · Marketplace (5)**; filtros **Tutorial / Exploit / Tool / Trade / Request**; exemplos: “Zero-Day in Latest Windows Update”, “SQL Injection Techniques 2025”, “Metasploit Framework Updates”, “Smart Contract Exploits”; tags RCE, Buffer Overflow, XSS, PrivEsc, WAF, DeFi. Navegação interna é JS e o acesso é **pago/invite** (“Buy Access”) — só a frontpage é pública.
- **Identidade e política**: o canônico (`hellfor6lms7…`) e mais 4 hosts “HeLL Forum” (`hellfor6nq3l…`, `helllbtvpp2j…`, `hellfohnrm6…`, `hellccam72…`) servem a landing “HeLL Reloaded”, autodescrita como *“private forum and marketplace for hacking”* — carding, RATs, keyloggers, ransomware, crypters, skimmers, ATM malware e serviços. Por política (**sem marketplace/for-hire**), `hellforum` foi **removido do índice** e movido para §9; o mirror `atlasf35…` (visão de boards) permanece documentado.
- **Hunt de fóruns com seção exploit** (5 engines; “hacking forum” e “exploit forum”; ≥2 fontes + GET): `darkarmy5dhdw5…` = **DARK ARMY**, hacker-for-hire (fora); `moon7pc4y…` = **MoonClub**, carding forum (fora); `tforumcf7j3…` = **TForum** — generalista com seção **Hacking / Opsec** (153 threads), mas com “Darknet Market Noobs” e “Guns” → **não indexado**; `monerokpw…` = Monero Forum e `v236xhqty…` = fórum comunitário Tor (observados, sem seção exploit); `oniodtu6…` = **OnionDir** (diretório, observado).
- **Conclusão**: nenhum fórum policy-clean com seção exploit dedicada além do DHZ/Dread; o padrão “fórum + marketplace” (HeLL, MoonClub, Dark Army) fica fora.

### Atualização — missão 7 (varredura do OnionDir)

- OnionDir (`oniodtu6…`, HTTP 200) varrido passivamente: /cat2 **Forums** (5 verbetes), /cat5 **Hacking** (5), /cat12 **Security** (1); sem paginação.
- cat2: The Stock Insiders (insider trading), CORE FORUM, DarkWebFrench, **XSS** (`xssforumv3isucukbxhdhwz67hoa5e2voakcfkuieq4ch257vsburuid.onion`) e **Dread** (`dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion` — 2º endereço/mirror). cat5: Bitcoin Generator Exploit (scam), Pathfinder RAT, DEF CON, Cryptostorm, Black Hat Chat. cat12: guia de autodefesa/drogas (fora do escopo de intel).
- GETs da m7: xss e core sem resposta; DarkWebFrench 302 sem corpo. Nenhuma validação nova; a política v2 chegou no meio da missão e adiou a reavaliação para a m8.

### Atualização — missão 8 (validações core/xsscentral + propagação da política v2)

- **core** (`ksn5nqaie4bozit…`): cross ≥2 fontes fechado (OnionDir /cat2 + OnionLand “ksn5nqaie4bozit” = 5 ocorrências). GET ×2 em janelas distintas: tentativa 1 falhou sem frame; tentativa 2 `rc=97` (SOCKS não entrega o host) → **não validado; morto provisório** — não indexar até nova janela.
- **xsscentral**: nenhuma engine devolve endereço em 5 consultas espaçadas (onionland/ahmia/dnreport “xsscentral”; tor66 “xsscentral” e “XSS Central” — único hit: Dark Global Wiki `darkgcjwg7x5s…`, sem relação). Sem endereço → sem GET. Se “xsscentral” for o v3 do XSS (`xssforumv3…`), o veredito é o da m7: GET http=000, sem corpo.
- **xss.is — sem GET (regra m8)**: endereço v3 `xssforumv3…` cross-confirmado por 2 fontes (OnionDir /cat2 + OnionLand; OnionLand o marca “Down”; variação `xssforum7mmh3n56…` citada pela mesma engine). Menções registradas em tor66 e onionland (1 consulta por engine, espaçada). Categoria: fórum de cybercrime (malware/carding) — leitura/intel apenas (política v2).
- **Propagação da política v2 (veto = interação; leitura é fonte)**: `hellforum` volta ao índice (§Fóruns, marcado “marketplace pago — só leitura”); `torport-news` e `blackhat-blog` voltam aos recursos (§Recursos, marcados); `yellowlabs`, `torz-poc` e `h2-news` permanecem fora por serem **landings hire sem valor de fonte** (não por mercado); `darkarmy`, MoonClub e Blue Key (achados m5–m6) reavaliados: leitura seria lícita, utilidade baixa — permanecem observados.

### Conclusão consolidada da série de hunt (m5–m8)

- **O que existe**: fóruns de pesquisa com leitura útil — Dark Hacker Zone (área PoC/CVE), Dread (hub de discussão), HeLL (board Exploits & Vulnerabilities na frontpage; acesso pago), TForum (seção Hacking/Opsec), XSS (cybercrime; endereço conhecido, sem GET). Diretórios úteis: OnionDir (curadoria + uptime), OnionSearch, HiddenWiki v3. O volume real de PoC está no clearnet (refs §Agregadores).
- **O que não existe**: nenhum agregador de PoC .onion com cobertura, nem fórum de exploit novo além do DHZ/Dread — cerca de 20 consultas em 7 engines, 3 diretórios e 3 categorias de diretório não devolveram nada comparável.
- **Padrão de hosting**: apps de fórum servidas sob múltiplos hosts (hell* ×6, xssforumv3/xssforum7, tormark/tormarty/torbuy), clones e landings JS com “Buy Access”; endereço canônico diferente do host que serve a app (hellfor6 vs atlasf35); `rc=97` recorrente = host retirado/retirável; v2 mortos por protocolo.
- **Regime a partir daqui**: a série de hunt está encerrada; o monitor diário 09:30 (playbook §Monitoramento) assume a operação de rotina. Reabrir hunt só com alvo novo nomeado pelo maestro.

## 11. Integridade

- Vereditos brutos: `/tmp/opencode/darkweb-m1/m1-validation.tsv` (com `http_code`, `curl_rc`, `time_total`, `size`, `content_type`, `sha256`).
- Bodies em quarentena: `/tmp/opencode/darkquarantine/` — sha256 por fonte listado acima; **nada executado**.
- Selo de integridade deste documento: `~/MITR3/docs/SHA256SUMS` (entrada `DARKWEB-SOURCES-v1.6.md`).

## 12. Próximos passos sugeridos

- Expandir acervos/foruns com novas rodadas de busca (token Ahmia a cada sessão) e validar por lote.
- Re-testar intermitentes (haystak, dse, dread) em outra janela; buscar endereços correntes de fóruns que rotacionam.
- Enviar este doc para indexação no MegaBrain (Gemma4) com o selo.

