#!/usr/bin/env python3
"""
Testador de autenticação e segurança web — checklist OWASP-inspired.
Escopo: aplicações próprias ou explicitamente autorizadas.
Inclui --self-test para testar a lógica contra um servidor de demonstração local.
Não executa exploração, brute force, fuzzing ou alteração de dados.
"""
import argparse
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urlparse, urljoin
from datetime import datetime
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from playwright.sync_api import sync_playwright

DEFAULT_PORTS = ["8081", "8080", "8000", "5000", "3000"]
results = []
base_for_report = ""

def classify_priority(category, test, status, detail):
    """Triagem heurística; P0 exige confirmação humana e nunca é inferido só por status HTTP."""
    text = f"{category} {test} {detail}".lower()
    if "exposição crítica confirmada" in text:
        return "P0"
    if status in ("PASSOU", "INFO", "PENDENTE", "BLOQUEADO"):
        return "INFO"
    if "senha via get" in text or "https na url configurada" in text:
        return "P1"
    if "dashboard sem sessão" in text and status == "ATENÇÃO":
        return "P1*"  # possível falha de autorização; precisa confirmar se a resposta contém dados privados
    if status in ("ATENÇÃO", "FALHOU"):
        return "P2"
    return "INFO"

def record(category, test, status, detail):
    priority = classify_priority(category, test, status, detail)
    item = {"prioridade": priority, "categoria": category, "teste": test,
            "status": status, "detalhe": detail}
    results.append(item)
    if "output" in globals():
        log(f"[{priority}] [{status}] {category} / {test}: {detail}")
    else:
        print(f"[{priority}] [{status}] {category} / {test}: {detail}")

def assess_login_response(status_code, headers, expected_mode, body_text=""):
    """Valida o contrato HTTP sem registrar corpo, tokens ou credenciais."""
    content_type = headers.get("content-type", "").lower()
    location = headers.get("location", "")
    is_json = "application/json" in content_type
    try:
        json.loads(body_text) if is_json and body_text else None
        valid_json = is_json and bool(body_text)
    except (ValueError, TypeError):
        valid_json = False
    if expected_mode == "Redirecionamento HTTP 302":
        ok = status_code == 302 and bool(location)
        return ok, f"Esperado HTTP 302 com Location; recebido HTTP {status_code}; Location {'presente' if location else 'ausente'}."
    if expected_mode == "JSON HTTP 200":
        ok = status_code == 200 and valid_json
        return ok, f"Esperado HTTP 200 com JSON válido; recebido HTTP {status_code}; Content-Type JSON={'sim' if is_json else 'não'}; JSON válido={'sim' if valid_json else 'não'}."
    if status_code == 302 and location:
        return True, "Detectado fluxo de redirecionamento HTTP 302 com Location."
    if status_code == 200 and valid_json:
        return True, "Detectado HTTP 200 com JSON válido. Isso não prova, por si só, autenticação bem-sucedida."
    return False, f"Contrato não reconhecido automaticamente: HTTP {status_code}; Content-Type JSON={'sim' if is_json else 'não'}; Location {'presente' if location else 'ausente'}."

def log(message):
    output.configure(state="normal")
    output.insert(tk.END, message + "\n")
    output.see(tk.END)
    output.configure(state="disabled")
    root.update_idletasks()

@lru_cache(maxsize=256)
def parse_url_cached(raw):
    """Cache LRU de parsing de URL; não armazena respostas HTTP nem credenciais."""
    return urlparse(raw)

@lru_cache(maxsize=256)
def normalize_headers_cached(items):
    """Normaliza cabeçalhos repetidos sem guardar respostas completas do servidor."""
    return {str(k).lower(): str(v) for k, v in items}

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Informe uma URL.")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = parse_url_cached(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL inválida. Exemplo: http://localhost:8081")
    return raw.rstrip("/")

def base_url():
    if mode_box.get() == "Local":
        host = host_entry.get().strip() or "localhost"
        port = port_box.get().strip()
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Informe uma porta entre 1 e 65535.")
        if "://" in host:
            parsed = urlparse(normalize_url(host))
            return f"{parsed.scheme}://{parsed.hostname}:{port}"
        if "/" in host or " " in host:
            raise ValueError("O host deve ser apenas localhost ou um nome de host.")
        return f"http://{host}:{port}"
    return normalize_url(deploy_entry.get())

def path_value(entry, fallback):
    value = entry.get().strip() or fallback
    return value if value.startswith("/") else "/" + value

def add_port():
    value = port_entry.get().strip()
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        messagebox.showerror("Porta inválida", "Use um número entre 1 e 65535.")
        return
    values = list(port_box["values"])
    if value not in values:
        values.append(value)
        port_box["values"] = values
    port_box.set(value)
    port_entry.delete(0, tk.END)

def update_mode(*_):
    local = mode_box.get() == "Local"
    for widget in (host_entry, port_box, port_entry, add_port_button):
        widget.configure(state="normal" if local else "disabled")
    deploy_entry.configure(state="disabled" if local else "normal")

def inspect_headers(url, headers, status_code):
    h = normalize_headers_cached(tuple(sorted((str(k), str(v)) for k, v in headers.items())))
    secure = parse_url_cached(url).scheme == "https"
    record("Transporte", "HTTPS", "PASSOU" if secure else ("INFO" if mode_box.get() == "Local" else "ATENÇÃO"),
           "HTTPS ativo." if secure else "HTTP detectado; aceitável para localhost, não para produção.")
    for key, label, explanation in [
        ("content-security-policy", "Content-Security-Policy", "Avalie uma política CSP compatível com o site."),
        ("x-content-type-options", "X-Content-Type-Options", "Valor normalmente esperado: nosniff."),
        ("referrer-policy", "Referrer-Policy", "Defina uma política de referência adequada."),
        ("permissions-policy", "Permissions-Policy", "Restrinja recursos do navegador não usados, quando aplicável."),
    ]:
        record("Cabeçalhos", label, "PASSOU" if key in h else "ATENÇÃO",
               f"Presente: {h[key][:140]}" if key in h else f"Ausente. {explanation}")
    if secure:
        record("Cabeçalhos", "Strict-Transport-Security",
               "PASSOU" if "strict-transport-security" in h else "ATENÇÃO",
               "Presente." if "strict-transport-security" in h else "Ausente; avaliar após confirmar HTTPS.")
    else:
        record("Cabeçalhos", "Strict-Transport-Security", "INFO", "Verificar no ambiente HTTPS.")
    csp = h.get("content-security-policy", "").lower()
    protected_frame = "x-frame-options" in h or "frame-ancestors" in csp
    record("Cabeçalhos", "Proteção contra framing", "PASSOU" if protected_frame else "ATENÇÃO",
           "X-Frame-Options ou CSP frame-ancestors detectado." if protected_frame else "Proteção não identificada.")
    record("Cabeçalhos", "Cache-Control", "INFO" if "cache-control" in h else "ATENÇÃO",
           h.get("cache-control", "Ausente; reveja cache em páginas com dados sensíveis."))
    for key in ("server", "x-powered-by"):
        if key in h:
            record("Exposição", key, "INFO", f"Cabeçalho presente: {h[key][:100]}. Avalie reduzir divulgação de tecnologia.")
    record("HTTP", "Status", "PASSOU" if status_code < 400 else "ATENÇÃO", f"HTTP {status_code}.")

def inspect_cookies(cookies, url):
    if not cookies:
        record("Sessão", "Cookies", "INFO", "Nenhum cookie na origem/contexto atual.")
        return
    record("Sessão", "Cookies encontrados", "INFO", f"{len(cookies)} cookie(s); valores omitidos.")
    for c in cookies:
        name = c.get("name", "(sem nome)")
        record("Sessão", f"{name}: HttpOnly",
               "PASSOU" if c.get("httpOnly") else "ATENÇÃO",
               "Ativo." if c.get("httpOnly") else "Ausente; se for cookie de sessão, avalie impedir leitura via JavaScript.")
        if urlparse(url).scheme == "https":
            record("Sessão", f"{name}: Secure", "PASSOU" if c.get("secure") else "ATENÇÃO",
                   "Ativo." if c.get("secure") else "Ausente em HTTPS.")
        else:
            record("Sessão", f"{name}: Secure", "INFO", "Rever no deploy HTTPS.")
        same_site = c.get("sameSite")
        record("Sessão", f"{name}: SameSite",
               "PASSOU" if same_site in ("Lax", "Strict", "None") else "ATENÇÃO",
               str(same_site or "ausente") + "; valide conforme o fluxo do sistema.")

def run():
    global results, base_for_report
    results = []
    output.configure(state="normal")
    output.delete("1.0", tk.END)
    output.configure(state="disabled")
    try:
        base = base_url()
        base_for_report = base
        login_path = path_value(login_entry, "/login")
        dashboard_path = path_value(dashboard_entry, "/dashboard")
        health_path = path_value(health_entry, "/")
        logout_path = path_value(logout_entry, "/logout")
        timeout = int(timeout_entry.get().strip())
        if not 1000 <= timeout <= 120000:
            raise ValueError("Timeout deve ficar entre 1000 e 120000 ms.")
    except Exception as e:
        messagebox.showerror("Configuração inválida", str(e))
        return

    log("TESTADOR OWASP-INSPIRED — CHECKLIST DE VERIFICAÇÕES")
    log(f"Modo: {mode_box.get()} | URL base: {base}")
    log(f"Gerado em: {datetime.now().isoformat(timespec='seconds')}")
    log("Use apenas em sistemas próprios/autorizados. Senhas não são gravadas no relatório.")
    log("")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not visible_var.get())
            ctx = browser.new_context()
            page = ctx.new_page()
            page.set_default_timeout(timeout)

            # 1. Base URL, transport and headers
            log("=== 1. DISPONIBILIDADE E CABEÇALHOS ===")
            try:
                response = page.goto(urljoin(base + "/", health_path.lstrip("/")),
                                     wait_until="domcontentloaded", timeout=timeout)
                if response:
                    inspect_headers(response.url, response.headers, response.status)
                    if mode_box.get() != "Local" and urlparse(base).scheme == "http":
                        record("Deploy", "HTTPS na URL configurada", "ATENÇÃO",
                               "A URL de deploy está em HTTP. Configure HTTPS antes de produção.")
                else:
                    record("Disponibilidade", "Página inicial", "ATENÇÃO", "Navegação sem resposta HTTP.")
            except Exception as e:
                record("Disponibilidade", "Página inicial", "FALHOU", f"{type(e).__name__}: {e}")
                browser.close()
                save_report()
                return

            # 2. DOM / forms / storage, without submitting anything
            log("\n=== 2. FORMULÁRIOS, ARMAZENAMENTO E CONTEÚDO MISTO ===")
            try:
                dom = page.evaluate("""() => ({
                  title: document.title,
                  forms: [...document.forms].map(f => ({
                    method: (f.method || 'get').toUpperCase(),
                    action: f.action,
                    passwordFields: [...f.querySelectorAll('input[type=password]')].length
                  })),
                  insecure: [...document.querySelectorAll('[src], [href]')]
                    .map(e => e.src || e.href)
                    .filter(u => location.protocol === 'https:' && u.startsWith('http://')).slice(0, 15),
                  localKeys: Object.keys(localStorage),
                  sessionKeys: Object.keys(sessionStorage)
                })""")
                record("Página", "Título", "INFO", dom["title"] or "(sem título)")
                record("Formulários", "Contagem", "INFO", str(len(dom["forms"])))
                for i, f in enumerate(dom["forms"], 1):
                    log(f"Formulário {i}: método={f['method']}; campos senha={f['passwordFields']}; ação={f['action']}")
                    if f["passwordFields"] and f["method"] == "GET":
                        record("Formulários", f"Senha via GET no formulário {i}", "ATENÇÃO",
                               "GET pode expor dados na URL/histórico; confirme que credenciais não são enviadas via GET.")
                record("Conteúdo misto", "Recursos HTTP", "ATENÇÃO" if dom["insecure"] else "INFO",
                       "; ".join(dom["insecure"]) if dom["insecure"] else "Nenhum recurso HTTP detectado no DOM inicial.")
                record("Armazenamento", "Local Storage", "INFO",
                       ", ".join(dom["localKeys"]) or "(vazio; valores não lidos)")
                record("Armazenamento", "Session Storage", "INFO",
                       ", ".join(dom["sessionKeys"]) or "(vazio; valores não lidos)")
            except Exception as e:
                record("Página", "Inspeção DOM", "ATENÇÃO", f"{type(e).__name__}: {e}")

            # 3. unauthenticated dashboard check, isolated context
            log("\n=== 3. CONTROLE DE ACESSO SEM SESSÃO ===")
            dash_url = urljoin(base + "/", dashboard_path.lstrip("/"))
            try:
                unauth = p.request.new_context(ignore_https_errors=False, timeout=timeout)
                r = unauth.get(dash_url, max_redirects=5)
                final_path = urlparse(r.url).path.rstrip("/")
                login_norm = login_path.rstrip("/")
                if r.status in (401, 403):
                    record("Autorização", "Dashboard sem sessão", "PASSOU",
                           f"Servidor respondeu HTTP {r.status} sem cookie de sessão.")
                elif final_path == login_norm:
                    record("Autorização", "Dashboard sem sessão", "INFO",
                           f"Redirecionou para login (HTTP {r.status}); confirme que nenhum dado privado foi retornado.")
                elif r.status < 400:
                    record("Autorização", "Dashboard sem sessão", "ATENÇÃO",
                           f"Resposta HTTP {r.status} sem sessão e URL final {r.url}. Pode ser público ou protegido no cliente; confirme manualmente.")
                else:
                    record("Autorização", "Dashboard sem sessão", "INFO",
                           f"Resposta HTTP {r.status}; verifique se corresponde à política esperada.")
                unauth.dispose()
            except Exception as e:
                record("Autorização", "Dashboard sem sessão", "FALHOU", f"{type(e).__name__}: {e}")

            # 4. OPTIONS and CORS hints
            log("\n=== 4. OPTIONS / CORS (INSPEÇÃO BÁSICA) ===")
            for label, path in (("Login", login_path), ("Dashboard", dashboard_path)):
                try:
                    r = ctx.request.fetch(urljoin(base + "/", path.lstrip("/")),
                                          method="OPTIONS", timeout=timeout)
                    allow = r.headers.get("allow", "(não informado)")
                    origin = r.headers.get("access-control-allow-origin", "(não informado)")
                    record("CORS/HTTP", f"{label} OPTIONS", "INFO",
                           f"HTTP {r.status}; Allow={allow}; Access-Control-Allow-Origin={origin}")
                    if origin == "*":
                        record("CORS", f"{label} wildcard", "ATENÇÃO",
                               "Origem wildcard detectada; não é automaticamente vulnerável, avalie credenciais e necessidade.")
                except Exception as e:
                    record("CORS/HTTP", f"{label} OPTIONS", "INFO", f"Não foi possível verificar: {type(e).__name__}")

            # 5. Cookie checks on unauthenticated context and main browser context
            log("\n=== 5. COOKIES ===")
            inspect_cookies(ctx.cookies(), base)

            # 6. Optional credentialed login test; user chooses payload format/field names.
            if login_test_var.get():
                log("\n=== 6. TESTE DE LOGIN COM CONTA DE TESTE ===")
                user = username_entry.get()
                password = password_entry.get()
                user_key = username_key_entry.get().strip() or "username"
                pass_key = password_key_entry.get().strip() or "password"
                if not user or not password:
                    record("Autenticação", "Login com credenciais", "BLOQUEADO",
                           "Preencha usuário e senha de teste; nenhum login foi enviado.")
                else:
                    login_url = urljoin(base + "/", login_path.lstrip("/"))
                    auth_ctx = p.request.new_context(ignore_https_errors=False, timeout=timeout)
                    payload = {user_key: user, pass_key: password}
                    try:
                        if login_format_box.get() == "JSON":
                            auth_resp = auth_ctx.post(login_url, data=json.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
                        else:
                            auth_resp = auth_ctx.post(login_url, form=payload, max_redirects=0)
                        expected_mode = expected_login_box.get()
                        matched, contract_detail = assess_login_response(
                            auth_resp.status, auth_resp.headers, expected_mode, auth_resp.text()
                        )
                        record("Autenticação", "Contrato HTTP do login", "PASSOU" if matched else "ATENÇÃO",
                               contract_detail + " O status/JSON não prova identidade nem autorização; confira o dashboard com a sessão.")
                        auth_cookies = auth_ctx.storage_state().get("cookies", [])
                        inspect_cookies(auth_cookies, base)
                        auth_dash = auth_ctx.get(dash_url, max_redirects=5)
                        auth_final_path = urlparse(auth_dash.url).path.rstrip("/")
                        if auth_dash.status in (401, 403) or auth_final_path == login_path.rstrip("/"):
                            record("Autenticação", "Dashboard após login", "ATENÇÃO",
                                   f"Continua bloqueado/redirecionado (HTTP {auth_dash.status}); confirme formato do login/cookies.")
                        elif auth_dash.status < 400:
                            record("Autenticação", "Dashboard após login", "INFO",
                                   f"Acessível após requisição de login (HTTP {auth_dash.status}); confira conteúdo e identidade do usuário manualmente.")
                        else:
                            record("Autenticação", "Dashboard após login", "ATENÇÃO",
                                   f"HTTP {auth_dash.status}; confira contrato da API.")
                    except Exception as e:
                        record("Autenticação", "Login com credenciais", "FALHOU", f"{type(e).__name__}: {e}")
                    finally:
                        auth_ctx.dispose()
                # Never put password values in reports; clear password field after use.
                password_entry.delete(0, tk.END)

            # 7. Logout is not automatically submitted to avoid mutating unexpected state.
            record("Sessão", "Logout/expiração", "PENDENTE",
                   f"Não enviado automaticamente. Configure/valide manualmente o endpoint {logout_path}, método e política de invalidação.")
            browser.close()
    except Exception as e:
        record("Execução", "Erro inesperado", "FALHOU", f"{type(e).__name__}: {e}")

    log("\n=== RESUMO ===")
    log(f"PASSOU: {sum(x['status'] == 'PASSOU' for x in results)}")
    log(f"ATENÇÃO: {sum(x['status'] == 'ATENÇÃO' for x in results)}")
    log(f"FALHOU: {sum(x['status'] == 'FALHOU' for x in results)}")
    log(f"PENDENTE/BLOQUEADO: {sum(x['status'] in ('PENDENTE', 'BLOQUEADO') for x in results)}")
    log("Triagem: " + " | ".join(f"{p}: {sum(x['prioridade'] == p for x in results)}" for p in ("P0", "P1", "P1*", "P2", "INFO")))
    log("P0 só deve ser marcado após confirmação manual de impacto crítico; P1* indica possível exposição de dashboard ainda não confirmada.")
    url_cache = parse_url_cached.cache_info()
    header_cache = normalize_headers_cached.cache_info()
    log(f"Cache LRU — URLs: {url_cache.hits} acertos / {url_cache.misses} faltas; cabeçalhos: {header_cache.hits} acertos / {header_cache.misses} faltas.")
    log("Cache aplicado apenas ao processamento repetido; respostas HTTP são sempre consultadas novamente para evitar resultados de segurança desatualizados.")
    log("Interprete avisos conforme a arquitetura; isto não é certificação OWASP nem auditoria completa.")
    save_report()

def save_report():
    if not results:
        return
    path = filedialog.asksaveasfilename(
        title="Salvar relatório", defaultextension=".json",
        filetypes=[("Relatório JSON", "*.json"), ("Texto", "*.txt")],
        initialfile="checklist_owasp.json")
    if not path:
        log("Relatório não exportado.")
        return
    try:
        safe_results = results
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"gerado_em": datetime.now().isoformat(timespec="seconds"),
                           "url_base": base_for_report, "modo": mode_box.get(),
                           "criterios_prioridade": {"P0": "Impacto crítico confirmado manualmente; não inferido só por status HTTP.",
                                                     "P1": "Risco alto que exige correção/priorização rápida.",
                                                     "P1*": "Possível falha de autorização; confirmar se dados privados foram retornados.",
                                                     "P2": "Risco moderado ou configuração a revisar.",
                                                     "INFO": "Informativo, passou ou depende de validação manual."},
                           "resultados": safe_results}, f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", encoding="utf-8") as f:
                for item in safe_results:
                    f.write(f"[{item['status']}] {item['categoria']} / {item['teste']}: {item['detalhe']}\n")
        log(f"Relatório salvo em: {path}")
    except OSError as e:
        log(f"Erro ao salvar relatório: {e}")

# Local-only demonstration server for exercising test logic.
class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"<html><title>OWASP Demo</title><body><form method='post'><input name='username'><input type='password' name='password'></form></body></html>")
        elif self.path in ("/login", "/login-redirect", "/login-json"):
            self.send_response(405); self.end_headers()
        elif self.path == "/dashboard":
            self.send_response(401); self.end_headers()
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)  # consume demo request body; never log credentials
        if self.path == "/login-redirect":
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.end_headers()
        elif self.path == "/login-json":
            payload = json.dumps({"ok": True, "demo": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(405); self.end_headers()
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()
    def log_message(self, *_):
        pass

def self_test():
    server = HTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    check_results = []
    parse_url_cached.cache_clear()
    normalize_headers_cached.cache_clear()
    print(f"SELF-TEST LOCAL: {url}")
    try:
        with sync_playwright() as p:
            request = p.request.new_context()
            home = request.get(url + "/")
            check_results.append(("home status 200", home.status == 200))
            check_results.append(("CSP header present", "content-security-policy" in home.headers))
            dashboard = request.get(url + "/dashboard")
            check_results.append(("dashboard without session returns 401", dashboard.status == 401))
            opts = request.fetch(url + "/login", method="OPTIONS")
            check_results.append(("OPTIONS responds", opts.status == 204))
            redirect = request.post(url + "/login-redirect", data="{}", headers={"Content-Type": "application/json"}, max_redirects=0)
            redirect_ok, _ = assess_login_response(redirect.status, redirect.headers, "Redirecionamento HTTP 302", redirect.text())
            check_results.append(("login 302 + Location contract", redirect_ok))
            json_resp = request.post(url + "/login-json", data="{}", headers={"Content-Type": "application/json"}, max_redirects=0)
            json_ok, _ = assess_login_response(json_resp.status, json_resp.headers, "JSON HTTP 200", json_resp.text())
            check_results.append(("login JSON 200 contract", json_ok))
            check_results.append(("P0 requires explicit confirmed finding", classify_priority("Exposição crítica confirmada", "manual", "ATENÇÃO", "impacto confirmado") == "P0"))
            check_results.append(("unauthenticated dashboard warning is P1 review", classify_priority("Autorização", "Dashboard sem sessão", "ATENÇÃO", "resposta 200") == "P1*"))
            check_results.append(("password via GET is P1", classify_priority("Formulários", "Senha via GET no formulário 1", "ATENÇÃO", "GET") == "P1"))
            # Exercise cache twice with the same inputs and confirm cache hits.
            parse_url_cached(url); parse_url_cached(url)
            header_items = (("Content-Security-Policy", "default-src self"),)
            normalize_headers_cached(header_items); normalize_headers_cached(header_items)
            check_results.append(("LRU URL cache records a hit", parse_url_cached.cache_info().hits >= 1))
            check_results.append(("LRU header cache records a hit", normalize_headers_cached.cache_info().hits >= 1))
            request.dispose()
    finally:
        server.shutdown()
        server.server_close()
    for name, ok in check_results:
        print(f"[{'PASSOU' if ok else 'FALHOU'}] {name}")
    print(f"Resultado self-test: {sum(ok for _, ok in check_results)}/{len(check_results)}")
    print(f"Cache LRU — URLs: {parse_url_cached.cache_info()}; cabeçalhos: {normalize_headers_cached.cache_info()}")
    return all(ok for _, ok in check_results)

def launch_gui():
    global root, output, mode_box, host_entry, port_box, port_entry, add_port_button
    global deploy_entry, login_entry, dashboard_entry, health_entry, logout_entry, timeout_entry
    global visible_var, login_test_var, manual_var, login_format_box, username_entry
    global password_entry, username_key_entry, password_key_entry, expected_login_box
    root = tk.Tk()
    root.title("Testador de Segurança Web — OWASP-inspired")
    root.geometry("1100x940")
    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Testador OWASP-inspired — autenticação, sessão, exposição e prioridades P0/P1/P2",
              font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
    ttk.Label(frame, text="Modo:").grid(row=1, column=0, sticky="w")
    mode_box = ttk.Combobox(frame, values=["Local", "Pré-deploy", "Pós-deploy"], state="readonly", width=18)
    mode_box.set("Local"); mode_box.grid(row=1, column=1, sticky="w", padx=6)
    mode_box.bind("<<ComboboxSelected>>", update_mode)
    ttk.Label(frame, text="Host local:").grid(row=2, column=0, sticky="w", pady=3)
    host_entry = ttk.Entry(frame, width=25); host_entry.insert(0, "localhost")
    host_entry.grid(row=2, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Porta:").grid(row=2, column=2, sticky="e")
    port_box = ttk.Combobox(frame, values=DEFAULT_PORTS, state="readonly", width=10)
    port_box.set("8081"); port_box.grid(row=2, column=3, sticky="w")
    ttk.Label(frame, text="Adicionar porta:").grid(row=3, column=0, sticky="w", pady=3)
    port_entry = ttk.Entry(frame, width=10); port_entry.grid(row=3, column=1, sticky="w", padx=6)
    add_port_button = ttk.Button(frame, text="Adicionar", command=add_port); add_port_button.grid(row=3, column=2, sticky="w")
    ttk.Label(frame, text="URL pré/pós-deploy:").grid(row=4, column=0, sticky="w", pady=3)
    deploy_entry = ttk.Entry(frame, width=48); deploy_entry.insert(0, "https://seu-dominio.example")
    deploy_entry.grid(row=4, column=1, columnspan=3, sticky="we", padx=6)
    fields = [
        ("Endpoint login:", "/login"),
        ("Endpoint dashboard:", "/dashboard"),
        ("Endpoint disponibilidade:", "/"),
        ("Endpoint logout (referência):", "/logout"),
    ]
    entries = []
    for row, (label, default) in enumerate(fields, start=5):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ent = ttk.Entry(frame, width=25); ent.insert(0, default)
        ent.grid(row=row, column=1, sticky="w", padx=6); entries.append(ent)
    login_entry, dashboard_entry, health_entry, logout_entry = entries
    ttk.Label(frame, text="Timeout (ms):").grid(row=9, column=0, sticky="w", pady=3)
    timeout_entry = ttk.Entry(frame, width=12); timeout_entry.insert(0, "15000")
    timeout_entry.grid(row=9, column=1, sticky="w", padx=6)
    visible_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, text="Abrir navegador visível", variable=visible_var).grid(row=10, column=0, sticky="w", pady=3)
    login_test_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, text="Enviar um login com conta de teste", variable=login_test_var).grid(row=10, column=1, sticky="w", pady=3)
    ttk.Label(frame, text="Formato do envio:").grid(row=11, column=0, sticky="w")
    login_format_box = ttk.Combobox(frame, values=["JSON", "Formulário"], state="readonly", width=14)
    login_format_box.set("JSON"); login_format_box.grid(row=11, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Resposta esperada:").grid(row=11, column=2, sticky="e")
    expected_login_box = ttk.Combobox(frame, values=["Automático", "Redirecionamento HTTP 302", "JSON HTTP 200"], state="readonly", width=25)
    expected_login_box.set("Automático"); expected_login_box.grid(row=11, column=3, sticky="w", padx=6)
    ttk.Label(frame, text="Nome do campo usuário:").grid(row=12, column=0, sticky="w", pady=3)
    username_key_entry = ttk.Entry(frame, width=18); username_key_entry.insert(0, "username")
    username_key_entry.grid(row=12, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Nome do campo senha:").grid(row=13, column=0, sticky="w", pady=3)
    password_key_entry = ttk.Entry(frame, width=18); password_key_entry.insert(0, "password")
    password_key_entry.grid(row=13, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Usuário de teste:").grid(row=14, column=0, sticky="w", pady=3)
    username_entry = ttk.Entry(frame, width=24); username_entry.grid(row=14, column=1, sticky="w", padx=6)
    ttk.Label(frame, text="Senha de teste (não é salva no relatório):").grid(row=15, column=0, sticky="w", pady=3)
    password_entry = ttk.Entry(frame, width=24, show="*"); password_entry.grid(row=15, column=1, sticky="w", padx=6)
    ttk.Button(frame, text="Executar checklist", command=run).grid(row=16, column=0, columnspan=2, sticky="w", pady=8)
    ttk.Label(frame, text="Resultados:").grid(row=17, column=0, columnspan=4, sticky="w")
    output = tk.Text(frame, height=19, wrap="word", state="disabled")
    output.grid(row=18, column=0, columnspan=4, sticky="nsew", pady=6)
    scroll = ttk.Scrollbar(frame, command=output.yview); scroll.grid(row=18, column=4, sticky="ns")
    output.configure(yscrollcommand=scroll.set)
    frame.columnconfigure(1, weight=1); frame.rowconfigure(18, weight=1)
    update_mode()
    root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Testador OWASP-inspired de aplicações próprias/autorizadas.")
    parser.add_argument("--self-test", action="store_true", help="testa verificações básicas em servidor local de demonstração")
    args = parser.parse_args()
    if args.self_test:
        raise SystemExit(0 if self_test() else 1)
    launch_gui()
