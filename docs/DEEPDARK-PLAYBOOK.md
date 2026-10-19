# DEEPDARK-PLAYBOOK — Robin (pesquisa deep/dark web)

> Operado por: Robin (seat de pesquisa profunda) · Supervisão: OpenCode (maestro)
> Criado: 2026-10-19 · Infra: Tor local neste host

## 1. Infraestrutura

| peça | estado | detalhe |
|---|---|---|
| `tor` (systemd) | ativo, autostart | SOCKS5 em `127.0.0.1:9050`; bootstrap confirmado 100% |
| `torsocks` | instalado | `torsocks curl ...` |
| `onionsearch` | instalado (`~/.local/bin`) | busca multi-engine; usar `--proxy 127.0.0.1:9050` (default) |
| `bin/darkweb.sh` | helper do time | `fetch` / `head` / `search` / `status` |

Exemplos:

```bash
curl -s --socks5-hostname 127.0.0.1:9050 --max-time 90 https://<algo>.onion/
~/MITR3/bin/darkweb.sh fetch https://<algo>.onion/
~/MITR3/bin/darkweb.sh search "termo" --engines ahmia --limit 5
journalctl -u tor --since "5 min ago" --no-pager | tail -3   # ou darkweb.sh status
```

Baselines verificados em 2026-10-19 (referência de que o circuito funciona):
- Ahmia onion → HTTP 200 (~5 s)
- DuckDuckGo onion → HTTP 200 (~11 s, primeiro circuito)

**Engines enferrujam.** O smoke `onionsearch --engines ahmia` devolveu 0 resultados em 0,2 s
(scraper quebrado no layout atual, não rede). Regra: todo engine usado precisa de validação
individual — abrir por `darkweb.sh head`, procurar um termo de controle e registrar o veredito
em `DARKWEB-SOURCES` (vivo/morto/parcial + data).

## 2. Regras de operação (não negociáveis)

1. **Passivo por padrão.** Ler e coletar. Sem login, sem postagem, sem cadastro, sem
   transação, sem mensagem a terceiros. Interação só com ordem explícita do maestro.
2. **Anonimato do time.** Nunca usar identidade, e-mail, handle ou credencial real em
   qualquer serviço da rede. Nada de dados do host em requests.
3. **Quarentena.** Qualquer artefato baixado (binário, arquivo, dump) vai para
   `/tmp/opencode/darkquarantine/`, com `sha256sum` ANTES de qualquer análise, e **nunca
   executa** sem autorização explícita do maestro + sandbox. Verificar tipo com `file`
   antes de tudo.
4. **Nada de PII de terceiros em claro** nos relatórios. Vazamentos são citados por
   referência (fonte, data, tamanho, hash), nunca com dados pessoais copiados.
5. **Sem mercado.** Marketplace, cartão, "compras" — fora. O trabalho é conhecimento
   (exploits, PoCs, writeups, fóruns de pesquisa), não aquisição.
6. **Google seats fora da rede.** Conteúdo dark vai para o maestro/Robin/Gemma4 — nunca
   para seats com backend Google (política).

## 3. Objetivo da lane

Encontrar e curar **conhecimento útil para trabalho autorizado MITR3**: exploits e PoCs
(aplicáveis a alvos de engajamento), writeups de 0day/pesquisa, fontes de referência
(agregadores, pastes, fóruns), espelhos de projetos de segurança caídos no clearnet.

## 4. Evidência (padrão do time)

- Toda fonte citada com: URL (onion completo), data/hora UTC de acesso, HTTP status,
  e — para artefatos — `sha256` + tamanho.
- Saídas viram doc `~/MITR3/docs/DARKWEB-SOURCES-vN.md` com selo `SHA256SUMS`.
- Resumo de conhecimento vai para o MegaBrain (via Gemma4 quando em formato de documento).
- Relatório ao maestro: comandos exatos, o que funcionou, o que morreu, próximos passos.

## 5. Segurança do próprio Robin

- Não manter sessões longas contra um mesmo serviço; intervalos entre requisições.
- Se um serviço pedir JS/captcha/login — recuar e registrar, sem tentar contornar.
- Suspeita de armadilha (honeypot/canary): parar, registrar URL, reportar ao maestro.

## 6. Fila inicial (missão 1 do Robin)

1. Validar individualmente ≥8 engines/gateways (vivo/morto/parcial + como validou).
2. Índice `DARKWEB-SOURCES-v1.md`: ≥15 fontes entre engines, agregadores de exploit/PoC,
   fóruns de pesquisa e acervos; cada uma com veredito de alcance e descrição.
3. Reportar ao maestro em ≤8 linhas.

## 7. Anexo A — Fluxo do token anti-scrape do Ahmia (observação passiva, 2026-10-19, missão 3)

Observado em 6 GETs espaçados 11–12 s, sem paralelismo:

- `GET /` (200) devolve campo oculto `name="<6hex>" value="<6hex>"` — o token muda por sessão/circuito (já vistos `290b9f=e15aa0`, `1e92ec=d1e6fa`, `69726b=37acce`).
- Dois GETs da home com 11 s de intervalo devolveram o **mesmo** token na mesma sessão/circuito.
- `GET /search/?q=<termo>&<token>` com o token da home → **200** com resultados; o token foi **reusado 3×** com sucesso.
- `GET /search/?q=<termo>` **sem** token → **302** para a home (corpo vazio) — causa raiz do scraper do `onionsearch` devolver 0 resultados.
- A página de resultados emite um **novo** token (`b608fc=b76c19`), que também aparentou ser aceito.

Protocolo educado adotado: 1 GET da home por sessão para obter o token; buscas espaçadas (≥10 s entre requisições); sem cookies, sem paralelismo, sem forjar/contornar tokens. Se o token expirar, refazer apenas o GET da home.

## 8. Monitoramento diário (rotina 09:30)

Alvos fixos: `wgruul` (Vigilant), `archive-db` (mirror Bitcoin), `dread-current`.

1. Rodar `~/MITR3/bin/darkweb-monitor.sh` (3 GETs passivos, ≤50 s cada, espaçados; sem login/paralelismo).
2. Conferir o resumo; o log TSV fica em `~/MITR3/docs/monitor/AAAA-MM-DD.log` (timestamp, http, rc, tempo, bytes, título, sha256).
3. Classificar: VIVO ≤10 s · LENTO 10–50 s · TIMEOUT (rc=28).
4. Dois dias consecutivos de TIMEOUT → marcar “morto provisório” no doc; se voltar, reabilitar.
5. Título/tamanho mudou de forma relevante → abrir o frame da quarentena (hash já registrado), comparar e anotar.
6. Atualizar doc + selo só quando houver mudança de estado. Captcha/login/JS → recuar e registrar (§5).
