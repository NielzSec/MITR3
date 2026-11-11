#!/usr/bin/env python3
"""
MITR3 Live Browser Traffic Interceptor & Agent Event Feed — Phase 1 (SEC-BROW-002)

Phase 1 Scope & Architecture:
- Sanitized event feed for consuming agents: method, origin/path (NO query values),
  status, type, sizes, field names, and indicators.
- STRICTLY EXCLUDES: Cookie, Authorization, Set-Cookie, tokens, PII, postData raw, and raw response bodies.
- Scope enforcement: approved origins/hosts only; blocks unapproved egress, redirects, and subresources.
- Single-reader event loop for CDP (no concurrent socket recv).
- Zero eval: --eval and eval commands removed from agent paths.
- Signatures treated as candidates/indicators (never confirmed vulnerabilities).
- Evidence written to local checkout with 0700 dir / 0600 files and SHA-256 digest sealing.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

MAX_FRAME = 32 * 1024 * 1024
TEXT_MIME = ('text/', 'json', 'javascript', 'xml', 'x-www-form-urlencoded', 'html')

# Sensitive keys to drop unconditionally
SENSITIVE_HEADER_KEYS = re.compile(
    r'(?i)^(cookie|set-cookie|authorization|proxy-authorization|x-csrf-token|csrf-token|'
    r'x-api-key|api-key|x-auth-token|session|token|x-amz-security-token|secret|bearer)$'
)

# Safe structural header keys permitted in metadata
SAFE_METADATA_HEADERS = {
    'content-type',
    'content-length',
    'accept',
    'origin',
    'user-agent',
    'host',
    'cache-control'
}

# Heuristic Indicator Signatures (Treated as Candidates / Indicators ONLY)
CANDIDATE_PARAM_RCE = re.compile(r'(?i)\b(cmd|command|exec|shell|run|eval|code|system|ping|payload|script|process)\b')
CANDIDATE_PARAM_LFI = re.compile(r'(?i)\b(file|path|dir|page|include|doc|folder|template|load|view)\b')
CANDIDATE_PARAM_SSRF = re.compile(r'(?i)\b(url|uri|dest|target|redirect|proxy|link|src|domain|webhook|feed|api|callback)\b')
CANDIDATE_PARAM_IDOR = re.compile(r'(?i)\b(id|user_id|account_id|uuid|account|profile|order_id|ticket_id|doc_id)\b')

DIAGNOSTIC_BODY_PATTERNS = [
    (re.compile(r'uid=\d+\([a-zA-Z0-9_-]+\)\s+gid=\d+'), "unix_id_pattern", "Unix id command output pattern observed"),
    (re.compile(r'root:x:0:0:root:'), "passwd_root_pattern", "System user database root entry observed"),
    (re.compile(r'Linux\s+[a-zA-Z0-9._-]+\s+\d+\.\d+'), "uname_banner_pattern", "Kernel/OS banner pattern observed"),
    (re.compile(r'Windows\s+IP\s+Configuration'), "win_ipconfig_pattern", "Windows ipconfig banner pattern observed"),
    (re.compile(r'(?:sh|bash|zsh):\s*(?:line\s*\d+:)?\s*.*:\s*command not found'), "shell_error_pattern", "Command shell error output pattern observed"),
    (re.compile(r'Fatal error:.*in\s+.*\.php\s+on\s+line'), "php_fatal_pattern", "PHP fatal error trace pattern observed"),
    (re.compile(r'Traceback\s+\(most recent call last\):'), "python_traceback_pattern", "Python traceback pattern observed"),
    (re.compile(r'java\.[a-z.]+(?:Exception|Error):'), "java_exception_pattern", "Java exception stack trace pattern observed"),
    (re.compile(r'SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}'), "sql_syntax_error_pattern", "Database syntax error pattern observed"),
]


class ScopePolicy:
    """Enforces origin and hostname allowlists for browser requests and redirects."""
    def __init__(self, allowed_origins=None, allowed_hosts=None):
        self.allowed_origins = set()
        self.allowed_hosts = set()
        for o in (allowed_origins or []):
            p = urllib.parse.urlsplit(o.strip().lower())
            if p.scheme in ('http', 'https') and p.netloc:
                self.allowed_origins.add(f"{p.scheme}://{p.netloc}")
        for h in (allowed_hosts or []):
            h_clean = h.strip().lower()
            if h_clean:
                self.allowed_hosts.add(h_clean)

    def is_allowed(self, url: str) -> tuple[bool, str]:
        if not url:
            return False, "EMPTY_URL"
        if url.startswith("about:") or url.startswith("data:"):
            return True, "INTERNAL_BROWSER_SCHEME"
        try:
            p = urllib.parse.urlsplit(url)
        except Exception:
            return False, "MALFORMED_URL"
        if p.scheme not in ('http', 'https'):
            return False, f"UNSUPPORTED_SCHEME_{p.scheme}"
        if p.username or p.password:
            return False, "USERINFO_PROHIBITED"
        if not p.hostname:
            return False, "MISSING_HOSTNAME"
        host = p.hostname.lower()
        origin = f"{p.scheme}://{p.netloc}".lower()
        if self.allowed_origins and origin in self.allowed_origins:
            return True, "ORIGIN_MATCH"
        if self.allowed_hosts and host in self.allowed_hosts:
            return True, "HOST_MATCH"
        return False, f"OUT_OF_SCOPE_DESTINATION_{host}"


class EventSanitizer:
    """Sanitizes HTTP metadata for agent consumption, removing all secrets, values, and raw bodies."""

    @staticmethod
    def sanitize_url(url: str) -> tuple[str, str, list[str]]:
        """Returns (origin, path, sorted_param_names) omitting all query values."""
        if not url or url.startswith("about:"):
            return "", url or "", []
        try:
            p = urllib.parse.urlsplit(url)
            origin = f"{p.scheme}://{p.netloc}"
            path = p.path or "/"
            param_names = sorted(list({k for k, _ in urllib.parse.parse_qsl(p.query, keep_blank_values=True)}))
            return origin, path, param_names
        except Exception:
            return "[invalid-url]", "[invalid-path]", []

    @staticmethod
    def sanitize_headers(headers: dict) -> dict:
        """Strips all cookies, auth, tokens, and retains only safe structural headers."""
        if not headers:
            return {}
        sanitized = {}
        for k, v in headers.items():
            k_lower = str(k).lower()
            if SENSITIVE_HEADER_KEYS.match(k_lower):
                continue
            if k_lower in SAFE_METADATA_HEADERS:
                val = str(v)
                if k_lower == 'content-type':
                    val = val.split(';')[0].strip()
                elif k_lower == 'referer':
                    try:
                        p = urllib.parse.urlsplit(val)
                        val = f"{p.scheme}://{p.netloc}{p.path}"
                    except Exception:
                        val = "[redacted-referer]"
                sanitized[k_lower] = val
        sanitized['_omitted_sensitive_headers_count'] = sum(
            1 for k in headers if SENSITIVE_HEADER_KEYS.match(str(k).lower())
        )
        return sanitized

    @staticmethod
    def extract_field_names(post_data: str, content_type: str = "") -> list[str]:
        """Extracts field names/keys from request payloads without exposing any values."""
        if not post_data or not isinstance(post_data, str):
            return []
        ct = (content_type or "").lower()
        names = set()
        if 'json' in ct or post_data.lstrip().startswith(('{', '[')):
            try:
                parsed = json.loads(post_data)
                if isinstance(parsed, dict):
                    names.update(parsed.keys())
                elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    names.update(parsed[0].keys())
            except Exception:
                pass
        if not names:
            try:
                for k, _ in urllib.parse.parse_qsl(post_data, keep_blank_values=True):
                    names.add(k)
            except Exception:
                pass
        return sorted(list(names))


class IndicatorDetector:
    """Identifies structural attack surface indicators and diagnostic patterns (candidates only)."""

    SIGNATURE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge", "rce_diagnostic_signatures.json")

    @staticmethod
    def load_signature_db(path=None):
        """Loads knowledge/rce_diagnostic_signatures.json; returns (patterns, param_regexes) compiled."""
        path = path or IndicatorDetector.SIGNATURE_DB_PATH
        try:
            db = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            return [], {}
        patterns = []
        for entry in db.get("diagnostic_body_patterns", []):
            try:
                patterns.append((re.compile(entry["regex"]), entry["id"], entry["notes"], entry.get("precision", "medium")))
            except (KeyError, re.error):
                continue  # a bad pattern never disables the rest of the db
        regexes = {k: re.compile(v) for k, v in db.get("param_regexes", {}).items()}
        return patterns, regexes

    @staticmethod
    def check_param_indicators(param_names: list[str]) -> list[dict]:
        indicators = []
        rx_rce, rx_lfi = CANDIDATE_PARAM_RCE, CANDIDATE_PARAM_LFI
        rx_ssrf, rx_idor = CANDIDATE_PARAM_SSRF, CANDIDATE_PARAM_IDOR
        if _DIAGNOSTIC_PARAM_REGEXES:  # knowledge db overrides static heuristics when loadable
            rx_rce = _DIAGNOSTIC_PARAM_REGEXES.get("rce", rx_rce)
            rx_lfi = _DIAGNOSTIC_PARAM_REGEXES.get("lfi", rx_lfi)
            rx_ssrf = _DIAGNOSTIC_PARAM_REGEXES.get("ssrf", rx_ssrf)
            rx_idor = _DIAGNOSTIC_PARAM_REGEXES.get("idor", rx_idor)
        for p in param_names:
            if rx_rce.search(p):
                indicators.append({
                    "category": "candidate_indicator",
                    "type": "param_rce_candidate",
                    "param": p,
                    "detail": f"Parameter '{p}' matches command execution naming heuristics; candidate for targeted probe",
                    "severity": "MEDIUM"
                })
            elif rx_lfi.search(p):
                indicators.append({
                    "category": "candidate_indicator",
                    "type": "param_lfi_candidate",
                    "param": p,
                    "detail": f"Parameter '{p}' matches file/path inclusion naming heuristics; candidate indicator",
                    "severity": "LOW"
                })
            elif rx_ssrf.search(p):
                indicators.append({
                    "category": "candidate_indicator",
                    "type": "param_ssrf_candidate",
                    "param": p,
                    "detail": f"Parameter '{p}' matches URL/redirect retrieval naming heuristics; candidate indicator",
                    "severity": "LOW"
                })
            elif rx_idor.search(p):
                indicators.append({
                    "category": "candidate_indicator",
                    "type": "param_idor_candidate",
                    "param": p,
                    "detail": f"Parameter '{p}' matches identifier naming heuristics; candidate indicator",
                    "severity": "INFO"
                })
        return indicators

    @staticmethod
    def check_response_diagnostics(body: str) -> list[dict]:
        """Scans response body internally for diagnostic patterns; never leaks raw body to agent feed."""
        indicators = []
        if not body or not isinstance(body, str):
            return indicators
        for pat, id_name, desc, precision in DIAGNOSTIC_BODY_PATTERNS_DB:
            if pat.search(body):
                indicators.append({
                    "category": "diagnostic_indicator",
                    "type": id_name,
                    "detail": f"{desc}; requires independent verification",
                    "severity": "HIGH" if precision == "high" else "LOW"
                })
        return indicators


class SingleReaderWSClient:
    """Thread-safe RFC 6455 WebSocket client using a single background reader loop."""
    def __init__(self, url):
        p = urllib.parse.urlsplit(url)
        if p.scheme != 'ws' or p.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('CDP WebSocket must connect to loopback ws://')
        self.sock = socket.create_connection((p.hostname, p.port or 80), timeout=10)
        self.sock.settimeout(0.5)
        key = base64.b64encode(os.urandom(16)).decode()
        path = p.path or '/'
        if p.query:
            path += '?' + p.query
        req = (f'GET {path} HTTP/1.1\r\nHost: {p.hostname}:{p.port or 80}\r\n'
               f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
               f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.sock.sendall(req.encode('ascii'))
        self.buf = bytearray()
        deadline = time.monotonic() + 10
        while b'\r\n\r\n' not in self.buf:
            if time.monotonic() > deadline or len(self.buf) > 16384:
                raise TimeoutError('WebSocket handshake timed out')
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError('WebSocket handshake closed by server')
            self.buf.extend(chunk)
        head, rest = bytes(self.buf).split(b'\r\n\r\n', 1)
        if not head.startswith(b'HTTP/1.1 101'):
            raise ConnectionError('WebSocket handshake rejected')
        self.buf = bytearray(rest)
        self.frame = {'stage': 'header'}
        self.message = bytearray()
        self.fragmented = False
        self.next_id = 0
        self.write_lock = threading.Lock()
        self.pending_calls = {}
        self.event_callbacks = []
        self.running = True
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

    def _take_bytes(self, count):
        while len(self.buf) < count:
            if not self.running:
                raise ConnectionError('Closed')
            try:
                chunk = self.sock.recv(min(65536, max(count - len(self.buf), 4096)))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError('WebSocket stream closed mid-frame')
            self.buf.extend(chunk)
        out = bytes(self.buf[:count])
        del self.buf[:count]
        return out

    def _send_raw_frame(self, opcode, data):
        n = len(data)
        header = bytearray([0x80 | opcode])
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack('!H', n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack('!Q', n))
        mask = os.urandom(4)
        payload = bytes(header) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        with self.write_lock:
            self.sock.sendall(payload)

    def _read_one_message(self):
        while self.running:
            f = self.frame
            if f['stage'] == 'header':
                b1, b2 = self._take_bytes(2)
                if b1 & 0x70 or b2 & 0x80:
                    raise ValueError('Unsupported WebSocket frame bits')
                f.update(fin=bool(b1 & 0x80), opcode=b1 & 15, length=b2 & 127, stage='length')
            if f['stage'] == 'length':
                if f['length'] == 126:
                    f['length'] = struct.unpack('!H', self._take_bytes(2))[0]
                elif f['length'] == 127:
                    f['length'] = struct.unpack('!Q', self._take_bytes(8))[0]
                if f['length'] > MAX_FRAME:
                    raise ValueError('Frame exceeds MAX_FRAME limit')
                f['stage'] = 'payload'
            if f['stage'] == 'payload':
                payload = self._take_bytes(f['length'])
                opcode, fin = f['opcode'], f['fin']
                self.frame = {'stage': 'header'}
                if opcode == 8:
                    raise ConnectionError('WebSocket close frame received')
                if opcode == 9:
                    self._send_raw_frame(10, payload)
                    continue
                if opcode == 10:
                    continue
                if opcode == 1 and not self.fragmented:
                    self.message.extend(payload)
                    self.fragmented = not fin
                elif opcode == 0 and self.fragmented:
                    self.message.extend(payload)
                    self.fragmented = not fin
                else:
                    raise ValueError('Unexpected WebSocket opcode sequence')
                if fin:
                    out = bytes(self.message).decode('utf-8', 'replace')
                    self.message.clear()
                    return out

    def _reader_loop(self):
        """Single reader thread that processes all incoming socket data."""
        while self.running:
            try:
                raw_msg = self._read_one_message()
                if not raw_msg:
                    continue
                data = json.loads(raw_msg)
                if 'id' in data and data['id'] in self.pending_calls:
                    entry = self.pending_calls[data['id']]
                    entry['result'] = data.get('result')
                    entry['error'] = data.get('error')
                    entry['event'].set()
                elif 'method' in data:
                    for cb in self.event_callbacks:
                        try:
                            cb(data)
                        except Exception:
                            pass
            except (ConnectionError, socket.error):
                break
            except Exception:
                time.sleep(0.02)

    def call(self, method: str, params: dict = None, timeout: float = 10.0) -> dict:
        """Sends an RPC method and waits for response via single-reader event signaling."""
        self.next_id += 1
        mid = self.next_id
        ev = threading.Event()
        entry = {'event': ev, 'result': None, 'error': None}
        self.pending_calls[mid] = entry
        try:
            self._send_raw_frame(1, json.dumps({'id': mid, 'method': method, 'params': params or {}}).encode('utf-8'))
            if not ev.wait(timeout):
                raise TimeoutError(f"CDP method {method} timed out after {timeout}s")
            if entry['error']:
                raise RuntimeError(f"CDP method {method} failed: {entry['error']}")
            return entry['result'] or {}
        finally:
            self.pending_calls.pop(mid, None)


class LiveBrowserFeedSession:
    """Manages browser lifecycle, scope filtering, event correlation, and sanitized feed emission."""
    def __init__(self, target_url: str = None, allowed_origins: list = None, allowed_hosts: list = None,
                 headful: bool = False, cdp_port: int = 9224, out_dir: str = None,
                 human_raw_capture: bool = False, quiet: bool = False):
        self.target_url = target_url
        self.scope = ScopePolicy(allowed_origins=allowed_origins, allowed_hosts=allowed_hosts)
        self.headful = headful
        self.cdp_port = cdp_port
        self.out_dir = out_dir or "/home/nielz/MITR3/MITR3/docs/evidence/web-feed"
        self.human_raw_capture = human_raw_capture
        self.quiet = quiet

        self.proc = None
        self.user_data_dir = None
        self.ws = None
        self.running = False
        self.lock = threading.Lock()

        # State correlation maps
        self.requests = {}
        self.order = []
        self.indicators = []
        self.blocked_events = []

        # Ensure directory permissions are 0700
        os.makedirs(self.out_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.out_dir, 0o700)
        except Exception:
            pass

        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        pid = os.getpid()
        self.session_id = f"web_feed_{stamp}_{pid}"
        self.feed_path = os.path.join(self.out_dir, f"{self.session_id}.agent_feed.jsonl")
        self.summary_path = os.path.join(self.out_dir, f"{self.session_id}.summary.json")

        self.human_raw_dir = None
        self.human_raw_path = None
        if self.human_raw_capture:
            self.human_raw_dir = os.path.join(self.out_dir, "human-only")
            os.makedirs(self.human_raw_dir, mode=0o700, exist_ok=True)
            try:
                os.chmod(self.human_raw_dir, 0o700)
            except Exception:
                pass
            self.human_raw_path = os.path.join(self.human_raw_dir, f"{self.session_id}.raw.jsonl")

    def _find_browser_binary(self):
        for candidate in ["/usr/bin/brave", "/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        which = shutil.which("brave") or shutil.which("chromium") or shutil.which("google-chrome")
        if which:
            return which
        raise FileNotFoundError("No Chromium-based browser binary found in system PATH.")

    def start_browser(self):
        bin_path = self._find_browser_binary()
        self.user_data_dir = tempfile.mkdtemp(prefix="mitr3_browser_")
        try:
            os.chmod(self.user_data_dir, 0o700)
        except Exception:
            pass

        # FIX: Always launch to about:blank to avoid initial duplicate navigation
        cmd = [
            bin_path,
            f"--remote-debugging-port={self.cdp_port}",
            f"--user-data-dir={self.user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-background-networking",
            "--disable-component-update",
            "about:blank"
        ]
        if not self.headful:
            cmd.extend(["--headless=new", "--disable-gpu"])
        else:
            if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
                os.environ["DISPLAY"] = ":0.0"

        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for CDP endpoint
        deadline = time.monotonic() + 15
        base_url = f"http://127.0.0.1:{self.cdp_port}"
        connected = False
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{base_url}/json/version", timeout=1) as resp:
                    if resp.status == 200:
                        connected = True
                        break
            except Exception:
                time.sleep(0.25)
        if not connected:
            raise TimeoutError(f"Failed to connect to browser CDP port {self.cdp_port}")

        self._attach_cdp(base_url)

    def _attach_cdp(self, base_url):
        with urllib.request.urlopen(f"{base_url}/json", timeout=5) as resp:
            targets = json.load(resp)
        page_target = next((t for t in targets if t.get('type') == 'page' and t.get('webSocketDebuggerUrl')), None)
        if not page_target:
            with urllib.request.urlopen(f"{base_url}/json/new", timeout=5) as resp:
                page_target = json.load(resp)

        ws_url = page_target['webSocketDebuggerUrl']
        self.ws = SingleReaderWSClient(ws_url)
        self.ws.event_callbacks.append(self._on_cdp_event)
        self.ws.call('Network.enable', {'maxTotalBufferSize': 25000000, 'maxResourceBufferSize': 5000000})
        self.ws.call('Page.enable')
        self.running = True

    def _on_cdp_event(self, msg: dict):
        method = msg.get('method', '')
        params = msg.get('params', {})
        t_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        if method == 'Network.requestWillBeSent':
            rid = str(params.get('requestId'))
            req = params.get('request', {})
            raw_url = req.get('url', '')
            m_method = req.get('method', 'GET')
            rtype = params.get('type', 'Other')
            raw_headers = req.get('headers', {})
            post_data = req.get('postData', '')

            # Scope & allowlist enforcement
            is_allowed, scope_reason = self.scope.is_allowed(raw_url)

            origin, path, param_names = EventSanitizer.sanitize_url(raw_url)
            sanitized_headers = EventSanitizer.sanitize_headers(raw_headers)
            post_field_names = EventSanitizer.extract_field_names(post_data, raw_headers.get('Content-Type', ''))
            param_indicators = IndicatorDetector.check_param_indicators(param_names)

            entry = {
                'request_id': rid,
                'method': m_method,
                'origin': origin,
                'path': path,
                'param_names': param_names,
                'post_field_names': post_field_names,
                'resource_type': rtype,
                'status': None,
                'status_text': None,
                'encoded_data_length': 0,
                'content_type': sanitized_headers.get('content-type', ''),
                'headers': sanitized_headers,
                'indicators': param_indicators,
                'scope_allowed': is_allowed,
                'scope_reason': scope_reason,
                'timestamp_utc': t_utc
            }

            with self.lock:
                self.requests[rid] = entry
                self.order.append(rid)
                self.indicators.extend(param_indicators)
                if not is_allowed:
                    self.blocked_events.append({'request_id': rid, 'origin': origin, 'path': path, 'reason': scope_reason})

            # Emit request event to sanitized feed
            feed_event = {
                'event': 'request' if is_allowed else 'scope_blocked',
                'request_id': rid,
                'timestamp_utc': t_utc,
                'method': m_method,
                'origin': origin,
                'path': path,
                'param_names': param_names,
                'post_field_names': post_field_names,
                'resource_type': rtype,
                'content_type': entry['content_type'],
                'indicators': param_indicators,
                'scope_allowed': is_allowed
            }
            self._write_agent_feed(feed_event)

            # Isolated raw recording for human review only (if explicitly enabled)
            if self.human_raw_capture and is_allowed:
                self._write_human_raw({'raw_event': 'request', 'request_id': rid, 'method': m_method, 'url': raw_url, 'headers': raw_headers, 'post_data_len': len(post_data)})

        elif method == 'Network.responseReceived':
            rid = str(params.get('requestId'))
            resp = params.get('response', {})
            status = resp.get('status', 0)
            status_text = resp.get('statusText', '')
            raw_headers = resp.get('headers', {})
            mime = resp.get('mimeType', '')
            encoded_len = resp.get('encodedDataLength', 0)

            # Check redirect targets
            if 300 <= status < 400 and 'location' in {k.lower(): v for k, v in raw_headers.items()}:
                loc = next(v for k, v in raw_headers.items() if k.lower() == 'location')
                redir_allowed, redir_reason = self.scope.is_allowed(loc)
                if not redir_allowed:
                    with self.lock:
                        self.blocked_events.append({'request_id': rid, 'redirect_target': loc, 'reason': redir_reason})

            sanitized_resp_headers = EventSanitizer.sanitize_headers(raw_headers)

            with self.lock:
                if rid in self.requests:
                    self.requests[rid]['status'] = status
                    self.requests[rid]['status_text'] = status_text
                    self.requests[rid]['content_type'] = mime
                    self.requests[rid]['encoded_data_length'] = encoded_len

            feed_event = {
                'event': 'response',
                'request_id': rid,
                'timestamp_utc': t_utc,
                'status': status,
                'status_text': status_text,
                'content_type': mime,
                'encoded_data_length': encoded_len
            }
            self._write_agent_feed(feed_event)

        elif method == 'Network.loadingFinished':
            rid = str(params.get('requestId'))
            encoded_len = params.get('encodedDataLength', 0)
            with self.lock:
                if rid in self.requests:
                    if encoded_len:
                        self.requests[rid]['encoded_data_length'] = encoded_len

            # In Phase 1, fetch response body internally via single reader loop ONLY to detect diagnostic patterns
            def inspect_body_diagnostics():
                try:
                    res = self.ws.call('Network.getResponseBody', {'requestId': rid}, timeout=3.0)
                    body_raw = res.get('body', '')
                    if res.get('base64Encoded'):
                        try:
                            body_raw = base64.b64decode(body_raw).decode('utf-8', 'ignore')
                        except Exception:
                            body_raw = ""
                    diag_indicators = IndicatorDetector.check_response_diagnostics(body_raw)
                    if diag_indicators:
                        with self.lock:
                            if rid in self.requests:
                                self.requests[rid]['indicators'].extend(diag_indicators)
                            self.indicators.extend(diag_indicators)
                        self._write_agent_feed({
                            'event': 'diagnostic_alert',
                            'request_id': rid,
                            'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                            'indicators': diag_indicators
                        })
                except Exception:
                    pass

            threading.Thread(target=inspect_body_diagnostics, daemon=True).start()

            feed_event = {
                'event': 'completed',
                'request_id': rid,
                'timestamp_utc': t_utc,
                'encoded_data_length': encoded_len
            }
            self._write_agent_feed(feed_event)

        elif method == 'Network.loadingFailed':
            rid = str(params.get('requestId'))
            err_text = params.get('errorText', 'UnknownError')
            canceled = params.get('canceled', False)
            with self.lock:
                if rid in self.requests:
                    self.requests[rid]['error'] = err_text
                    self.requests[rid]['canceled'] = canceled

            feed_event = {
                'event': 'failed',
                'request_id': rid,
                'timestamp_utc': t_utc,
                'error': err_text,
                'canceled': canceled
            }
            self._write_agent_feed(feed_event)

    def _write_agent_feed(self, entry: dict):
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            fd = os.open(self.feed_path, flags, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass

    def _write_human_raw(self, entry: dict):
        if not self.human_raw_path:
            return
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            fd = os.open(self.human_raw_path, flags, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass

    def navigate(self, url: str):
        is_allowed, reason = self.scope.is_allowed(url)
        if not is_allowed:
            raise PermissionError(f"Navigation blocked by scope policy: {reason} ({url})")
        return self.ws.call('Page.navigate', {'url': url})

    def export_sealed_summary(self) -> dict:
        """Generates SHA-256 sealed audit summary without modifying past records."""
        with self.lock:
            hits = list(self.requests.values())
            # Calculate SHA256 over agent feed file
            feed_sha256 = "none"
            feed_bytes = 0
            if os.path.isfile(self.feed_path):
                h = hashlib.sha256()
                with open(self.feed_path, 'rb') as f:
                    content = f.read()
                    feed_bytes = len(content)
                    h.update(content)
                feed_sha256 = h.hexdigest()

            summary = {
                "session_id": self.session_id,
                "utc_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "total_requests": len(hits),
                "scope_blocked_count": len(self.blocked_events),
                "candidate_indicators_count": len(self.indicators),
                "indicators": self.indicators,
                "endpoints_discovered": sorted(list({e['path'] for e in hits if e.get('path')})),
                "status_distribution": {
                    str(s): sum(1 for e in hits if e.get('status') == s)
                    for s in sorted({e.get('status') for e in hits if e.get('status') is not None}, key=str)
                },
                "agent_feed_file": self.feed_path,
                "agent_feed_bytes": feed_bytes,
                "agent_feed_sha256": feed_sha256,
                "security_model": {
                    "raw_bodies_exposed_to_agents": False,
                    "cookies_exposed_to_agents": False,
                    "auth_headers_exposed_to_agents": False,
                    "permissions": "dir_0700_file_0600",
                    "operator_role": "OpenCode_only"
                }
            }
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(self.summary_path, flags, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            return summary

    def stop(self):
        self.running = False
        summary = self.export_sealed_summary()
        if self.ws:
            self.ws.close()
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()
        if self.user_data_dir and os.path.isdir(self.user_data_dir):
            try:
                shutil.rmtree(self.user_data_dir)
            except Exception:
                pass
        return summary



SAFE_REPLAY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_CAPTURE_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_human_request(capture_path: str, request_id: str) -> dict:
    """Load one request from a protected human-only capture without following symlinks."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request_id):
        raise ValueError("Invalid request ID")
    path = Path(capture_path)
    if path.parent.name != "human-only":
        raise PermissionError("Capture must be inside a human-only directory")
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PermissionError("Untrusted human-only capture directory") from exc
    try:
        parent_stat = os.fstat(parent_fd)
        if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise PermissionError("Untrusted human-only capture directory")
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise PermissionError("Untrusted human-only capture file") from exc
        with os.fdopen(fd, "rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != os.geteuid()
                    or stat.S_IMODE(file_stat.st_mode) != 0o600 or file_stat.st_size > MAX_CAPTURE_BYTES):
                raise PermissionError("Untrusted or oversized human-only capture file")
            raw = stream.read(MAX_CAPTURE_BYTES + 1)
    finally:
        os.close(parent_fd)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("Capture exceeds size limit")
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if event.get("raw_event") == "request" and event.get("request_id") == request_id:
            return event
    raise KeyError("Request ID not found in human-only capture")


def _scoped_origin(url: str, scope: ScopePolicy) -> tuple[str, str, str]:
    try:
        parsed = urllib.parse.urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    except Exception as exc:
        raise PermissionError("Malformed target URL") from exc
    allowed, reason = scope.is_allowed(url)
    if not allowed or origin not in scope.allowed_origins:
        raise PermissionError(f"Target is outside an explicitly approved origin: {reason}")
    if parsed.scheme not in ("http", "https") or parsed.fragment:
        raise PermissionError("Only HTTP(S) URLs without fragments can be replayed")
    return origin, parsed.path or "/", parsed.scheme


def _validate_replay_request(request: dict, scope: ScopePolicy) -> tuple[str, str]:
    if not isinstance(request, dict) or request.get("raw_event") != "request":
        raise ValueError("Expected a human-only request capture")
    method = str(request.get("method", "")).upper()
    if method not in SAFE_REPLAY_METHODS:
        raise PermissionError("Only GET, HEAD, and OPTIONS can be replayed")
    url = request.get("url")
    if not isinstance(url, str):
        raise ValueError("Captured request has no URL")
    _scoped_origin(url, scope)
    headers = request.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 64:
        raise ValueError("Invalid captured request headers")
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, float)):
            raise ValueError("Invalid captured request header")
        if "\r" in key or "\n" in key or "\r" in str(value) or "\n" in str(value):
            raise ValueError("Invalid captured request header")
    return method, url


def _probe_pair(request: dict, scope: ScopePolicy, probe_type: str, parameter: str,
                canary_url: str = None) -> tuple[dict, dict, str]:
    method, url = _validate_replay_request(request, scope)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", parameter):
        raise ValueError("Invalid parameter name")
    if probe_type not in ("rce", "ssrf"):
        raise ValueError("Probe type must be rce or ssrf")
    if method not in ("GET", "HEAD"):
        raise PermissionError("Candidate probes support GET and HEAD only")

    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    positions = [i for i, (key, _) in enumerate(pairs) if key == parameter]
    if len(positions) != 1 or len(pairs) != 1:
        raise ValueError("A candidate probe requires a URL with exactly one query parameter, appearing once")
    token = secrets.token_hex(8)
    marker = f"MITR3_{token}"
    control = list(pairs)
    probe = list(pairs)
    control[positions[0]] = (parameter, f"mitr3_control_{token}")

    if probe_type == "rce":
        # Fixed printf canary: no user-supplied command, file access, or network action.
        probe_value = f";printf '%s' '{marker}';#"
    else:
        if not isinstance(canary_url, str):
            raise ValueError("SSRF probes require an explicitly scoped HTTPS canary URL")
        canary = urllib.parse.urlsplit(canary_url)
        canary_host = (canary.hostname or "").lower()
        if (canary.scheme != "https" or canary.username or canary.password or canary.fragment
                or not canary_host or canary_host.endswith((".localhost", ".local", ".internal", ".invalid"))):
            raise ValueError("SSRF canary must be a public HTTPS URL without credentials or fragment")
        try:
            ip = ipaddress.ip_address(canary_host)
        except ValueError:
            ip = None
        if ip is not None and not ip.is_global:
            raise ValueError("SSRF canary cannot use a private or reserved IP address")
        canary_origin, _, _ = _scoped_origin(canary_url, scope)
        target_origin, _, _ = _scoped_origin(url, scope)
        if canary_origin == target_origin:
            raise ValueError("SSRF canary must use a separate allowlisted origin")
        cpairs = urllib.parse.parse_qsl(canary.query, keep_blank_values=True)
        cpairs.append(("mitr3_probe", token))
        probe_value = urllib.parse.urlunsplit((canary.scheme, canary.netloc, canary.path or "/",
                                               urllib.parse.urlencode(cpairs), ""))
        # A reserved .invalid control value cannot cause a real callback.
        control[positions[0]] = (parameter, f"https://mitr3-{token}.invalid/")
    probe[positions[0]] = (parameter, probe_value)

    def changed_url(values):
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                        urllib.parse.urlencode(values), ""))

    base_request = dict(request, url=changed_url(control))
    probe_request = dict(request, url=changed_url(probe))
    return base_request, probe_request, marker


def _http_response(url: str, method: str, headers: dict) -> dict:
    """Fetch one in-scope read-only response; redirects and ambient proxies are disabled."""
    safe_headers = {}
    blocked = {"host", "content-length", "connection", "transfer-encoding", "upgrade",
              "proxy-authorization", "proxy-connection", "accept-encoding"}
    for key, value in headers.items():
        if key.lower() not in blocked and not key.lower().startswith("proxy-"):
            safe_headers[key] = str(value)
    req = urllib.request.Request(url, headers=safe_headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    except Exception:
        raise RuntimeError("HTTP request failed") from None
    try:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("Response exceeds size limit")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        return {
            "status": response.code,
            "content_type": content_type,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body": body.decode("utf-8", "replace")
        }
    finally:
        response.close()


def _public_diff(before: dict, after: dict, marker: str = "") -> dict:
    return {
        "status_changed": before["status"] != after["status"],
        "content_type_changed": before["content_type"] != after["content_type"],
        "body_changed": before["body_sha256"] != after["body_sha256"],
        "body_bytes_delta": after["body_bytes"] - before["body_bytes"],
        "marker_observed": bool(marker and marker in after.get("body", "")),
        "before": {k: before[k] for k in ("status", "content_type", "body_bytes", "body_sha256")},
        "after": {k: after[k] for k in ("status", "content_type", "body_bytes", "body_sha256")}
    }


def run_replay(request: dict, scope: ScopePolicy, transport=_http_response) -> dict:
    method, url = _validate_replay_request(request, scope)
    response = transport(url, method, request.get("headers", {}))
    origin, path, _ = _scoped_origin(url, scope)
    return {
        "event": "replay_result",
        "request_id": request.get("request_id"),
        "method": method,
        "origin": origin,
        "path": path,
        "response": {k: response[k] for k in ("status", "content_type", "body_bytes", "body_sha256")}
    }


def run_probe(request: dict, scope: ScopePolicy, probe_type: str, parameter: str,
              canary_url: str = None, transport=_http_response) -> dict:
    base_request, probe_request, marker = _probe_pair(request, scope, probe_type, parameter, canary_url)
    method, _ = _validate_replay_request(request, scope)
    baseline = transport(base_request["url"], method, request.get("headers", {}))
    result = transport(probe_request["url"], method, request.get("headers", {}))
    origin, path, _ = _scoped_origin(request["url"], scope)
    return {
        "event": "probe_result",
        "probe_type": probe_type,
        "request_id": request.get("request_id"),
        "method": method,
        "origin": origin,
        "path": path,
        "parameter": parameter,
        "canary_correlation": marker.removeprefix("MITR3_") if probe_type == "ssrf" else None,
        "response_diff": _public_diff(baseline, result, marker if probe_type == "rce" else "")
    }


def _write_phase2_evidence(capture_path: str, result: dict) -> tuple[str, str]:
    parent = Path(capture_path).parent
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PermissionError("Untrusted human-only evidence directory") from exc
    try:
        parent_stat = os.fstat(parent_fd)
        if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise PermissionError("Untrusted human-only evidence directory")
        try:
            os.mkdir("probes", mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            out_fd = os.open("probes", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise PermissionError("Untrusted probe evidence directory") from exc
        try:
            out_stat = os.fstat(out_fd)
            if out_stat.st_uid != os.geteuid() or stat.S_IMODE(out_stat.st_mode) != 0o700:
                raise PermissionError("Untrusted probe evidence directory")
            raw = json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()
            sealed = dict(result, evidence_sha256=digest)
            name = f"phase2_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{secrets.token_hex(4)}.json"
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out_fd)
            except OSError as exc:
                raise PermissionError("Could not create sealed probe evidence") from exc
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(sealed, stream, sort_keys=True, ensure_ascii=False)
                stream.write("\n")
            return str(parent / "probes" / name), digest
        finally:
            os.close(out_fd)
    finally:
        os.close(parent_fd)


def _confirm_phase2(action: str, request: dict) -> bool:
    if not sys.stdin.isatty():
        raise PermissionError("Active replay requires an interactive operator terminal")
    method, url = str(request.get("method", "")).upper(), request.get("url", "")
    parsed = urllib.parse.urlsplit(url)
    expected = f"{action} {request.get('request_id')}"
    print(f"{action}: {method} {parsed.scheme}://{parsed.netloc}{parsed.path or '/'}; redirects off; max requests {2 if action == 'PROBE' else 1}.")
    return input(f"Type {expected} to authorize this scoped operation: ") == expected


def phase2_cli(action: str, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=f"MITR3 Live Browser {action.lower()} — scoped, read-only Phase 2")
    parser.add_argument("capture", help="Human-only .raw.jsonl capture (mode 0600 in a mode 0700 directory)")
    parser.add_argument("--request-id", required=True, help="CDP request ID from that capture")
    parser.add_argument("--allow-origin", action="append", required=True, help="Exact approved HTTP(S) origin; repeat for target/canary")
    if action == "PROBE":
        parser.add_argument("--kind", choices=("rce", "ssrf"), required=True)
        parser.add_argument("--param", required=True, help="One query parameter to replace")
        parser.add_argument("--canary-url", help="Required for SSRF; HTTPS origin must also be allowlisted")
    args = parser.parse_args(argv)
    try:
        request = load_human_request(args.capture, args.request_id)
        scope = ScopePolicy(allowed_origins=args.allow_origin)
        _validate_replay_request(request, scope)
        if action == "PROBE":
            if args.kind == "ssrf" and not args.canary_url:
                raise ValueError("SSRF probes require --canary-url")
            _probe_pair(request, scope, args.kind, args.param, getattr(args, "canary_url", None))
        if not _confirm_phase2(action, request):
            raise PermissionError("Operator confirmation did not match")
        result = (run_probe(request, scope, args.kind, args.param, args.canary_url)
                  if action == "PROBE" else run_replay(request, scope))
        evidence_path, digest = _write_phase2_evidence(args.capture, result)
        print(json.dumps(dict(result, evidence_file=evidence_path, evidence_sha256=digest), sort_keys=True))
        return 0
    except Exception as exc:
        print(f"[{action} BLOCKED/FAILED] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

def find_latest_session(search_dir: str) -> tuple[str, str]:
    """Returns (feed_path, summary_path) of the latest session in search_dir."""
    p = Path(search_dir)
    if not p.is_dir():
        return "", ""
    feeds = sorted(p.glob("*.agent_feed.jsonl"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not feeds:
        return "", ""
    feed_path = str(feeds[0])
    summary_path = feed_path.replace(".agent_feed.jsonl", ".summary.json")
    if not os.path.isfile(summary_path):
        summary_path = ""
    return feed_path, summary_path


def inspect_session(target_path: str) -> dict:
    """Inspects a session summary or agent feed file and returns structured analysis."""
    p = Path(target_path)
    summary_data = None
    feed_records = []

    if p.is_dir():
        feed_file, sum_file = find_latest_session(str(p))
        if not feed_file:
            raise FileNotFoundError(f"No agent feed found in directory {target_path}")
        p = Path(sum_file if sum_file else feed_file)

    if p.name.endswith(".summary.json"):
        with open(p, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
        feed_path = summary_data.get("agent_feed_file")
        if feed_path and os.path.isfile(feed_path):
            with open(feed_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            feed_records.append(json.loads(line))
                        except Exception:
                            pass
    elif p.name.endswith(".agent_feed.jsonl"):
        sum_path = str(p).replace(".agent_feed.jsonl", ".summary.json")
        if os.path.isfile(sum_path):
            try:
                with open(sum_path, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)
            except Exception:
                pass
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        feed_records.append(json.loads(line))
                    except Exception:
                        pass
    else:
        raise ValueError(f"Target must be .summary.json or .agent_feed.jsonl: {target_path}")

    # Integrity verification
    sha_verified = None
    feed_file = summary_data.get("agent_feed_file") if summary_data else None
    if not feed_file and p.name.endswith(".agent_feed.jsonl"):
        feed_file = str(p)
    if summary_data and "agent_feed_sha256" in summary_data and feed_file and os.path.isfile(feed_file):
        h = hashlib.sha256()
        with open(feed_file, "rb") as f:
            h.update(f.read())
        sha_verified = (h.hexdigest() == summary_data["agent_feed_sha256"])

    endpoints = set()
    candidates = []
    blocks = []
    for r in feed_records:
        ev = r.get("event")
        if ev == "request":
            if r.get("path"):
                endpoints.add(f"{r.get('method', 'GET')} {r.get('origin', '')}{r.get('path', '')}")
            if r.get("indicators"):
                for ind in r["indicators"]:
                    candidates.append({
                        "request_id": r.get("request_id"),
                        "endpoint": r.get("path"),
                        "category": ind.get("category"),
                        "type": ind.get("type"),
                        "param": ind.get("param"),
                        "detail": ind.get("detail"),
                        "severity": ind.get("severity")
                    })
        elif ev == "scope_blocked":
            blocks.append({
                "request_id": r.get("request_id"),
                "origin": r.get("origin"),
                "path": r.get("path")
            })

    return {
        "target_path": str(p),
        "session_id": summary_data.get("session_id") if summary_data else "unknown",
        "sha256_verified": sha_verified,
        "total_feed_events": len(feed_records),
        "unique_endpoints_count": len(endpoints),
        "endpoints": sorted(list(endpoints)),
        "candidate_indicators_count": len(candidates),
        "candidates": candidates,
        "blocked_events_count": len(blocks),
        "security_model": summary_data.get("security_model") if summary_data else {
            "raw_bodies_exposed_to_agents": False,
            "cookies_exposed_to_agents": False,
            "auth_headers_exposed_to_agents": False,
            "permissions": "dir_0700_file_0600",
            "operator_role": "OpenCode_only"
        }
    }


def tail_feed(feed_path: str, lines: int = 50):
    """Outputs sanitized, formatted feed entries for agent monitoring."""
    if not os.path.isfile(feed_path):
        raise FileNotFoundError(f"Feed file not found: {feed_path}")

    with open(feed_path, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
        selected = all_lines[-lines:] if lines > 0 else all_lines
        for raw in selected:
            if not raw.strip():
                continue
            try:
                ev = json.loads(raw)
                event_type = ev.get("event", "event")
                req_id = ev.get("request_id", "-")
                if event_type == "request":
                    params = ev.get("param_names", [])
                    fields = ev.get("post_field_names", [])
                    p_str = f" params={params}" if params else ""
                    f_str = f" fields={fields}" if fields else ""
                    print(f"[{ev.get('timestamp_utc', '')}] [REQ #{req_id}] {ev.get('method')} {ev.get('path')}{p_str}{f_str}")
                    if ev.get("indicators"):
                        for ind in ev["indicators"]:
                            print(f"    -> INDICATOR ({ind.get('severity')}): {ind.get('type')} on '{ind.get('param')}'")
                elif event_type == "response":
                    print(f"[{ev.get('timestamp_utc', '')}] [RESP #{req_id}] Status: {ev.get('status')} {ev.get('status_text')} ({ev.get('content_type')}, {ev.get('encoded_data_length')}B)")
                elif event_type == "scope_blocked":
                    print(f"[{ev.get('timestamp_utc', '')}] [BLOCKED #{req_id}] {ev.get('method')} {ev.get('origin')}{ev.get('path')} (Scope Policy Egress Blocked)")
                elif event_type == "diagnostic_alert":
                    print(f"[{ev.get('timestamp_utc', '')}] [DIAG #{req_id}] Alert: {ev.get('indicators')}")
                elif event_type == "failed":
                    print(f"[{ev.get('timestamp_utc', '')}] [FAIL #{req_id}] Error: {ev.get('error')}")
            except Exception:
                print(raw.strip())


def main():
    # Dispatch subcommands if provided: probe, replay, inspect, tail, candidates, or default to capture
    argv = sys.argv[1:]
    subcmd = argv[0] if argv and not argv[0].startswith("-") else None

    if subcmd in ("probe", "replay"):
        return phase2_cli(subcmd.upper(), argv[1:])

    if subcmd == "inspect":
        target = argv[1] if len(argv) > 1 else "/home/nielz/MITR3/MITR3/docs/evidence/web-feed"
        try:
            res = inspect_session(target)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
        except Exception as e:
            print(f"[ERROR] Inspect failed: {e}", file=sys.stderr)
            return 1

    elif subcmd == "tail":
        feed_target = None
        limit = 50
        if len(argv) > 1 and not argv[1].startswith("-"):
            feed_target = argv[1]
        if "--lines" in argv:
            idx = argv.index("--lines")
            if idx + 1 < len(argv):
                limit = int(argv[idx + 1])
        if not feed_target:
            feed_target, _ = find_latest_session("/home/nielz/MITR3/MITR3/docs/evidence/web-feed")
            if not feed_target:
                print("[ERROR] No active or past session feeds found.", file=sys.stderr)
                return 1
        try:
            tail_feed(feed_target, lines=limit)
            return 0
        except Exception as e:
            print(f"[ERROR] Tail failed: {e}", file=sys.stderr)
            return 1

    elif subcmd == "candidates":
        target = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else "/home/nielz/MITR3/MITR3/docs/evidence/web-feed"
        try:
            res = inspect_session(target)
            print(json.dumps(res.get("candidates", []), indent=2, ensure_ascii=False))
            return 0
        except Exception as e:
            print(f"[ERROR] Candidates dump failed: {e}", file=sys.stderr)
            return 1

    # Default / 'capture' mode
    if subcmd == "capture":
        argv = argv[1:]

    parser = argparse.ArgumentParser(description="MITR3 Live Browser & Sanitized Agent Event Feed (Phase 1)")
    parser.add_argument("--url", help="Target URL to inspect", default="about:blank")
    parser.add_argument("--allow-origin", action="append", default=[], help="Approved origin (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--allow-host", action="append", default=[], help="Approved hostname (e.g. localhost)")
    parser.add_argument("--visible", "--headful", dest="headful", action="store_true", default=False,
                        help="Launch visible browser window (default: False/headless)")
    parser.add_argument("--port", type=int, default=9224, help="CDP loopback port (default: 9224)")
    parser.add_argument("--out", default="/home/nielz/MITR3/MITR3/docs/evidence/web-feed", help="Evidence output directory")
    parser.add_argument("--timeout", type=int, default=0, help="Autonomous capture timeout in seconds (0 = wait for enter)")
    parser.add_argument("--human-raw-capture", action="store_true", default=False,
                        help="Record separate human-only raw capture (isolated in 0700 human-only dir; never in agent feed)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console logging")
    args = parser.parse_args(argv)

    # Default allowlist includes localhost / loopback if none provided
    allowed_origins = args.allow_origin or ["http://127.0.0.1", "http://localhost"]
    allowed_hosts = args.allow_host or ["127.0.0.1", "localhost"]

    session = LiveBrowserFeedSession(
        target_url=args.url if args.url != "about:blank" else None,
        allowed_origins=allowed_origins,
        allowed_hosts=allowed_hosts,
        headful=args.headful,
        cdp_port=args.port,
        out_dir=args.out,
        human_raw_capture=args.human_raw_capture,
        quiet=args.quiet
    )

    try:
        session.start_browser()
        if args.url and args.url != "about:blank":
            session.navigate(args.url)

        if args.timeout > 0:
            time.sleep(args.timeout)
        else:
            print(f"[MITR3 LIVE BROWSER] Running. Feed: {session.feed_path}. Press Enter to finish...")
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
    finally:
        summary = session.stop()
        print(f"\n[SUMMARY] Total Requests: {summary['total_requests']} | Blocked: {summary['scope_blocked_count']} | Candidates: {summary['candidate_indicators_count']}")
        print(f"          Agent Feed: {summary['agent_feed_file']} (SHA256: {summary['agent_feed_sha256'][:16]}...)")
        print(f"          Summary: {session.summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


# knowledge db: static base patterns first, then the versioned catalog (high precision = HIGH severity)
_DIAGNOSTIC_DB_PATTERNS, _DIAGNOSTIC_PARAM_REGEXES = IndicatorDetector.load_signature_db()
_DIAGNOSTIC_IDS = {i for (_, i, _, _) in _DIAGNOSTIC_DB_PATTERNS}
_STATIC_IDS = {i for (_, i, _) in DIAGNOSTIC_BODY_PATTERNS}
DIAGNOSTIC_BODY_PATTERNS_DB = ([(p, i, d, "medium") for (p, i, d) in DIAGNOSTIC_BODY_PATTERNS if i not in _DIAGNOSTIC_IDS] + _DIAGNOSTIC_DB_PATTERNS)
