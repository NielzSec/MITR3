# burp_lane — Burp Suite Professional

Lane WEB/API — configurado em 2026-10-19 por Hermes (MITR3).
Burp Pro 2026.3.3-47134 via `~/MITR3/bin/burp.sh` (loader v1.18 + JDK21). Licença ativa; GUI abre no display do host (`DISPLAY=:1`, Xwayland rootless).

## config.json (operação)
- Proxy listener: `127.0.0.1:8080` (cert per_host, MITM local).
- Spider e Scanner: **habilitados** (`user_options.misc.{spider,scanner}.enabled=true`).
- Scope (include/exclude): definido por caso em `project_options.target.scope` (vazio aqui; pinar o alvo do engagement antes de rodar spider/scanner amplo).
- Update checker: off (`etc.update_interval=0` + flag `--disable-auto-update` no launch).

## Lançamento (forma validada)
IMPORTANTE: `--config-file` deve usar a forma `--config-file=<caminho_absoluto>`.
Com espaço, o loader re-injeta args e o Burp falha com "Expected a value for option config-file".

```
cd ~/MITR3/engagements/burp_lane
DISPLAY=:1 ~/MITR3/bin/burp.sh \
  --config-file=$PWD/config.json \
  --disable-auto-update
```
- Para casos com projeto salvo: `--project-file case.burp --unpause-spider-and-scanner`.
- Encerrar: achar pid pelo socket `ss -ltnp | grep :8080` e `kill <pid>` (evitar pkill por pattern que pega o shell do agente).

## Validação runtime (2026-10-19)
- `ss -ltn | grep :8080` → LISTENING (`[::ffff:127.0.0.1]:8080`).
- `curl -x http://127.0.0.1:8080 http://127.0.0.1:8090/` → **200** (proxy egress OK; alvo local throwaway).
- GUI abriu no :1: "Burp Suite Professional v2026.3.3 - Temporary Project - licensed to h3110w0r1d" (xdotool).
- Limitação: verificação visual do estado dos toggles (Spider/Scanner UI) não feita — vision API indisponível neste modelo; estado via config. Screenshot de prova: `burp_gui_proof.png`.

## Uso na correlação (nuclei/ffuf/codeql)
- Roteie o tráfego dos scanners pelo proxy: `-x http://127.0.0.1:8080` (nuclei/ffuf/curl), browser em `127.0.0.1:8080`.
- Export de issues: usar o item de export (ou a API REST se habilitada em User options → Misc → REST API) e cruzar com findings de nuclei/ffuf/codeql. Ver `docs/WEBAPI-VALIDATION.md` → seção Burp Lane.
