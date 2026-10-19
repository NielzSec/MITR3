# WEBAPI-VALIDATION

Lane: WEB/API VALIDATION — localhost only (127.0.0.1). Nenhum host externo foi scanneado.
Data: 2026-10-19 | Executado por: Hermes (MITR3)
Ambiente: Linux 7.2.11-arch1-1

## Setup local (somente 127.0.0.1)
- Servidor: python3 -m http.server 8089 --bind 127.0.0.1  (diretório temp /home/nielz/.hermes/cache/scratch/webapi-val)
- Conteúdo: index.html, admin.html, login.html, data/data.json, secret.txt, wordlist.txt (15 palavras)
- Endpoint sqlmap: http://127.0.0.1:8089/index.html?id=1
- Conectividade validada: HTTP 200 em / e 200 em /data/data.json antes dos testes.

## Resultados

| tool | version | command | result | note |
|------|---------|---------|--------|------|
| nmap | 7.992 | nmap -sT -p8089 127.0.0.1 | 8089/tcp open (unknown) | scaneado somente 127.0.0.1; 1 host up; servidor SimpleHTTP |
| ffuf | 2.1.0-dev | ~/go/bin/ffuf -u http://127.0.0.1:8089/FUZZ -w wordlist.txt -mc 200,301,302,401,403 -t 5 -s | 1 hit: /data (301 redirect p/ /data/) | wordlist própria de 15 termos; ffuf instalado via go install (não existia no sistema) |
| nuclei | v3.11.1 | nuclei -u http://127.0.0.1:8089 -tags tech -silent | 2 finds info: tech-detect:simplehttp, tech-detect:python | -tags tech; alvo único 127.0.0.1; templates/infra local |
| sqlmap | 1.10.10#stable | sqlmap -u "http://127.0.0.1:8089/index.html?id=1" --batch --smart --level 1 --risk 1 --timeout 5 | Not injectable: parâmetro id não dinâmico, heuristic skip | endpoint estático (sem DB); resultado esperado e documentado; exit 0 |
| trivy | 0.76.0 | trivy fs . (no temp webapi-val) | No issues — 0 vulns / 0 secrets | 1ª execução baixou o vulnerability DB (mirror.gcr.io); secret.txt com flag fake não detectado (fora dos padrões) |
| semgrep | 1.181.0 | semgrep --version | 1.181.0 | CLI OK |
| mitmproxy | 12.2.3 | mitmproxy --version | 12.2.3 | CLI OK (Linux x86_64) |
| python3 | 3.14.7 | python3 -m http.server 8089 --bind 127.0.0.1 | SimpleHTTP/0.6 Python/3.14.7 | servidor local usado por todos os testes |

## Falhas / observações
- ffuf instalado via `go install github.com/ffuf/ffuf/v2@latest` — instalação INTENCIONAL (decisão do time), não é falha.
- nuclei apresentou warning de fallback sonic/ast (não-crítico) e não localizou ~/nuclei-templates, mas entregou detecção tech correta mesmo assim.
- sqlmap: esperado "não injetável" — endpoint é arquivo estático servido pelo http.server, get parameter id não é dinâmico. Sem achados (correto).
- trivy: flags de teste não disparam detecção de segredo; usar padrões reais (ex.: ak_/ghp_ para validar secret scanning).
- Nenhum tráfego para hosts externos; todos os alvos restritos a 127.0.0.1.

## Re-run 10:57

Correção: ~/nuclei-templates sincronizado (14.036 templates) -> nuclei re-executado contra 127.0.0.1:8089. Validação de ferramentas que entraram depois da primeira rodada.

| tool | version | command | result | note |
|------|---------|---------|--------|------|
| nuclei (re-run) | v3.11.1 | nuclei -u http://127.0.0.1:8089 -tags tech -silent | 2 matches (info): tech-detect:simplehttp, tech-detect:python | templates presentes: 14.036 arquivos .yaml em ~/nuclei-templates; matching correto |
| apktool | 3.0.3 | apktool --version | 3.0.3 | OK |
| frida | 17.24.3 | frida --version | 17.24.3 | OK |
| nxc | 1.5.1 (build ae683dba - 1108) | nxc --version | 1.5.1 | 1º run criou config padrão (`logs`); OK |
| checksec | pwntools 4.15.0 | pwn version (checksec é subcomando pwn) | Pwntools v4.15.0 | checksec via pwntools; `checksec --version` não é flag válida |
| trivy templates | 0.76.0 | trivy fs --scanners misconfig --severity HIGH,CRITICAL . | 0 misconfigs, exit 0 | templates/policy embutidos OK; alvo é HTML estático sem config cloud |

Observação: sem alteração de resultado do nuclei — novo run entregou os mesmos 2 findings em nível info.

## Conclusão
Pilha WEB/API validada ponta a ponta em ambiente localhost: descoberta (nmap/ffuf), detecção de tecnologia (nuclei), teste de injeção (sqlmap) e varredura de dependências (trivy). Infra pronta.

## Burp Lane (2026-10-19)
Burp Suite Professional 2026.3.3-47134 licenciado (loader v1.18 + JDK21) — operação em `engagements/burp_lane/config.json` + README.

### Lançamento
```
cd ~/MITR3/engagements/burp_lane
DISPLAY=:1 ~/MITR3/bin/burp.sh --config-file=$PWD/config.json --disable-auto-update
```
- Forma `--config-file=<abs>` é obrigatória; com espaço o loader re-injeta args e o Burp falha "Expected a value for option config-file".
- Encerrar: `kill <pid>` obtido via `ss -ltnp | grep :8080` (não usar pkill por pattern).

### Proxy
- Listener `127.0.0.1:8080` (cert per_host). Roteie scanners: `-x http://127.0.0.1:8080`.
- Spider/Scanner habilitados (user_options.misc). Scope por caso em project_options.target.scope.
- Update off via config (`etc.update_interval=0`) + flag `--disable-auto-update`.

### Export de issues e correlação com nuclei/ffuf/codeql
- Export de issues: GUI → Dashboard/Issue Activity → "Export" (ou REST API em User options → Misc → REST API).
- Correlação: tráfego de nuclei/ffuf pelo proxy → conjuntos de hosts/paths vistos no sitemap vs. findings das ferramentas; codeql dá o achado de código; Burp confirma exploitability no runtime; dedupe por host+path+issue class.
- Evidência: `curl -x http://127.0.0.1:8080 http://127.0.0.1:8090/` = 200 (proxy egress confirmado; alvo local).

### Validação (13:35–13:41)
| item | resultado |
|---|---|
| --config-file (estrutura user/project options) | parse OK; listener 8080 aplicado |
| proxy listener 127.0.0.1:8080 | `ss -ltn` → LISTEN [::ffff:127.0.0.1]:8080 |
| proxy egress | `curl -x` → HTTP 200 contra servidor local 8090 |
| GUI no display :1 | janela "Burp Suite Professional v2026.3.3 - Temporary Project - licensed to h3110w0r1d" (xdotool) |
| screenshot | `burp_gui_proof.png` (11 KB) |

Limitação: verificação visual dos toggles (Spider/Scanner na UI) não feita — vision API indisponível neste modelo (`image_url` não suportado). Estado dos toggles via config (não confirmado visualmente).


## Re-run 11:15
- Comando (contagem de templates): `nuclei -tl | wc -l` -> 13.619 templates carregados em ~/nuclei-templates.
- Comando (scan): `nuclei -u http://127.0.0.1:8089 -tags tech -silent` -> 2 achados, ambos info: [tech-detect:simplehttp] [http] e [tech-detect:python] [http] contra 127.0.0.1:8089 (servidor python3 -m http.server 8089, timeout 180, em background; alvo restrito a 127.0.0.1).
- Observação: contagem de templates via `-tl` (13.619) difere do find bruto de arquivos .yaml (14.036) — `-tl` lista apenas templates carregáveis/total efetivamente em uso pelo scanner.

## re-run 11:15 (fechado pelo maestro)

Motivo: o primeiro ciclo deixou um `python3 -m http.server` em foreground e a sessão do
agente travou. O maestro repetiu o ciclo com o servidor em background e pidfile.

Comandos exatos:

```
cd /home/nielz/.hermes/cache/scratch/webapi-val
python3 -m http.server 8089 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > /tmp/srv.pid
sleep 2
nuclei -tl | wc -l
nuclei -u http://127.0.0.1:8089 -tags tech -silent
kill $(cat /tmp/srv.pid)
```

Resultado:

- templates disponíveis: **13.619**
- `-tags tech` contra 127.0.0.1:8089: **2 achados**, ambos info
  - `tech-detect:simplehttp` — http://127.0.0.1:8089
  - `tech-detect:python` — http://127.0.0.1:8089
- servidor encerrado por pidfile; porta 8089 confirmada fechada

Regra que fica: nunca subir servidor de teste em foreground dentro do shell do agente.
