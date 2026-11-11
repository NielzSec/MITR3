# Robin — Pesquisa de Ferramentas OSINT
**Data:** 2026-11-11
**Autor:** Robin (agente de pesquisa)
**Escopo:** GitHub + Reddit — ferramentas OSINT/segurança para o time MITR3

---

## Ferramentas Identificadas

### GitHub

| Ferramenta | Repo | Stars | Tipo | Notas |
|---|---|---|---|---|
| **Robin** | [apurvsinghgautam/robin](https://github.com/apurvsinghgautam/robin) | 8k ⭐ | Dark Web OSINT + LLM | Tor-based, multi-model, MCP support, Streamlit UI, Docker-ready |
| **XSSCon** | [menkrep1337/XSSCon](https://github.com/menkrep1337/XSSCon) | 251 ⭐ | XSS Scanner | Python 3.7, crawler, GET/POST forms, multiprocessing, proxy support |
| **darkweb_crawler** | [IntelEyes/darkweb_crawler](https://github.com/IntelEyes/darkweb_crawler) | — | Dark Web Crawler | Python, threat intel, marketplace monitoring |
| **OSINT-Tools** | [yogsec/OSINT-Tools](https://github.com/yogsec/OSINT-Tools) | — | Framework | Categorizado: dark web, breach, social, geolocation |
| **ultimate-osint-toolkit** | [windantara/ultimate-osint-toolkit](https://github.com/windantara/ultimate-osint-toolkit) | — | All-in-one | 300+ tools integrados, menu interativo |
| **OSINT_Recon** | [dorr404/OSINT_Recon](https://github.com/dorr404/OSINT_Recon) | — | Recon multi-source | CLI + Streamlit, JSON/CSV/PDF output |
| **Recon-tool** | [st4ns3c/Recon-tool](https://github.com/st4ns3c/Recon-tool) | — | Bash pipeline | Subdomain → vuln scanning (nuclei, nikto, dalfox) |
| **OSINT-Scan** | [Isalavineth/OSINT-Scan](https://github.com/Isalavineth/OSINT-Scan) | — | Async recon | IP/domain, DNS, WHOIS, port scan, geolocation |
| **osint-recon** | [Abhracodec/osint-recon](https://2.github.com/Abhracodec/osint-recon) | 2 ⭐ | Web app | React/TypeScript, consent-based, rate-limited |
| **recon-ng** | [dmore/recon-ng-osint](https://github.com/dmore/recon-ng-osint) | — | Framework modular | 1028 commits, maduro, extensivo |
| **SpiderFoot** | standalone | — | Framework | 200+ módulos OSINT automatizados |
| **doctorfree/osint** | [doctorfree/osint](https://github.com/doctorfree/osint) | — | Recursos | Compilação de ferramentas e links |

### Reddit (r/cybersecurity, r/OSINT, r/Hacking_Tutorials)

- SpiderFoot, Shodan, theHarvester, Maltego, Recon-ng
- HaveIBeenPwned, AbuseIPDB, urlscan.io, VirusTotal, Hybrid Analysis
- OSINT Framework (osintframework.com) — mapa mental de ferramentas
- IntelX, LeakCheck, DeHashed, Scylla.so (breach search)
- OnionScan, Ahmia, Torch, Haystack (dark web search)
- OnionSearch, TorCrawl.py (onion discovery)
- ExifTool, Google Lens, TinEye (image forensics)
- Holehe, GHunt, Maigret, Sherlock (username/email)

---

## Status de Instalação

| Ferramenta | Caminho | Status |
|---|---|---|
| XSSCon | `/home/nielz/Tools/XSSCon/xsscon.py` | ✅ Instalado |
| Tor | `/usr/bin/tor` v0.4.9.14 | ✅ Instalado |
| Robin | Não instalado | ⬜ Pendente |
| Composio MCP | opencode.json:149-153 | ⚠️ Configurado, tools não carregam |

---

## Limitações

- **Composio MCP:** Tools não expostas no runtime Code Mode. `tools["composio"]` existe mas retorna "Unknown tool" para todas as tentativas. Necessário: autenticação OAuth no dashboard composio.dev ou restart do OpenCode.
- **Deepweb:** Tor instalado mas sem script de busca automatizado ainda.
- **Slack:** Report não postado diretamente.

---

## Próximos Passos

1. Resolver autenticação Composio → postar no Slack
2. Instalar Robin via Docker para investigação dark web
3. Configurar script de busca Tor para fóruns .onion
