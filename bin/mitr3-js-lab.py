#!/usr/bin/env python3
"""MITR3 JS Reverse Lab: bounded collection and offline HAR research (stdlib only)."""
import argparse
import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import signal
import socket
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_to_bytes, urljoin, urlsplit, urlunsplit

VERSION = "0.2.0"
MIB = 1024 * 1024
JS_MIMES = {"application/javascript", "text/javascript", "application/ecmascript",
            "text/ecmascript", "application/x-javascript"}
LIMITS = {"max_requests": (32, 256), "max_file_bytes": (4 * MIB, 16 * MIB),
          "max_bytes": (32 * MIB, 256 * MIB), "max_artifacts": (256, 2000),
          "max_seconds": (120, 600), "min_interval_ms": (250, 10000)}
SECRET_KEY = re.compile(r"token|auth|cookie|session|secret|password|signature|api.?key", re.I)
MAP_REF = re.compile(r"(?://[#@]\s*sourceMappingURL\s*=\s*([^\s]+)|"
                     r"/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)\s*\*/)")
GSAP = re.compile(r"\b(?:gsap\s*\.\s*(?:timeline|to|fromTo|from|set|registerPlugin)|"
                  r"ScrollTrigger\s*\.\s*(?:create|batch))\s*\(")
IMPORTS = re.compile(r"\b(?:import\s*(?:\(\s*)?|require\s*\(\s*)[\"']([^\"'\r\n]{1,512})[\"']"
                     r"|\b(?:import|export)\s+[^;\r\n]{1,512}?\bfrom\s*[\"']([^\"'\r\n]{1,512})[\"']")


class LabError(Exception):
    """Only constant, non-sensitive reason codes cross the CLI boundary."""


class StopRun(LabError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packed(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()


def read_local(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        import stat
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LabError("input-not-regular-file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise LabError("input-too-large")
    return data


def parse_json(data):
    # Reject excessive nesting before handing untrusted JSON to the recursive decoder.
    try:
        text = data if isinstance(data, str) else data.decode("utf-8-sig")
    except UnicodeError:
        raise LabError("invalid-json-encoding") from None
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise LabError("json-depth-quota")
        elif char in "]}":
            depth -= 1
    try:
        def reject_constant(value):
            raise ValueError("invalid-json-constant")
        return json.loads(data, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise LabError("invalid-json") from None


def canonical_url(value):
    if (not isinstance(value, str) or len(value) > 8192 or "\\" in value
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value)):
        raise LabError("invalid-url")
    try:
        p = urlsplit(value)
        host, port = p.hostname, 443 if p.port is None else p.port
        if (p.scheme != "https" or not host or p.username is not None
                or p.password is not None or not 1 <= port <= 65535
                or host.endswith(".") or "." not in host
                or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host)):
            raise LabError("url-policy-denied")
        if any(SECRET_KEY.search(key) for key, _ in parse_qsl(p.query)):
            raise LabError("credential-query-denied")
        netloc = host + (f":{port}" if port != 443 else "")
        return urlunsplit(("https", netloc, p.path or "/", p.query, ""))
    except ValueError:
        raise LabError("invalid-url") from None


def origin(url):
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def url_meta(url):
    # Query values and fragments never enter metadata or audit logs.
    p = urlsplit(url)
    return {"url": urlunsplit((p.scheme, p.netloc, p.path, "", "")),
            "url_id": digest(url.encode())}


class Scope:
    def __init__(self, raw):
        data = parse_json(raw)
        if not isinstance(data, dict):
            raise LabError("invalid-scope")
        self.sha256 = digest(raw)
        self.case_id = data.get("case_id")
        if (not isinstance(self.case_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.case_id)
                or not isinstance(data.get("operator"), str) or not data["operator"].strip()):
            raise LabError("invalid-scope-identity")
        try:
            self.expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            if self.expires.tzinfo is None:
                raise ValueError
        except (KeyError, ValueError, TypeError, AttributeError):
            raise LabError("invalid-scope-expiry") from None
        allowed = data.get("allowed_origins")
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= 32:
            raise LabError("invalid-scope-origins")
        self.origins = set()
        for value in allowed:
            url = canonical_url(value)
            if urlsplit(url).path != "/" or urlsplit(url).query or "#" in value:
                raise LabError("scope-requires-origins")
            self.origins.add(origin(url))
        self.paths = data.get("allowed_paths")
        if (not isinstance(self.paths, dict) or set(self.paths) != self.origins
                or any(not isinstance(paths, list) or not paths or len(paths) > 64
                       or any(not isinstance(p, str) or not p.startswith("/") or ".." in p
                              or "?" in p or "#" in p or "%" in p or "\\" in p for p in paths)
                       for paths in self.paths.values())):
            raise LabError("invalid-scope-paths")
        self.allow_maps = data.get("allow_source_maps", False)
        self.retention_days = data.get("retention_days", 7)
        if (type(self.allow_maps) is not bool or type(self.retention_days) is not int
                or not 1 <= self.retention_days <= 365):
            raise LabError("invalid-data-policy")
        config = data.get("limits", {})
        if not isinstance(config, dict) or set(config) - set(LIMITS):
            raise LabError("invalid-scope-limits")
        self.limits = {}
        for key, (default, ceiling) in LIMITS.items():
            val = config.get(key, default)
            if type(val) is not int or not 1 <= val <= ceiling:
                raise LabError("invalid-scope-limits")
            self.limits[key] = val
        self.deadline = time.monotonic() + self.limits["max_seconds"]
        self.check()

    def check(self):
        if datetime.now(timezone.utc) >= self.expires:
            raise StopRun("scope-expired")
        if time.monotonic() >= self.deadline:
            raise StopRun("time-quota")

    def url(self, value):
        self.check()
        url = canonical_url(value)
        if origin(url) not in self.origins:
            raise LabError("origin-denied")
        try:
            path = unquote(urlsplit(url).path, errors="strict")
        except UnicodeError:
            raise LabError("invalid-path-encoding") from None
        if ("%" in path or "\\" in path or "//" in path
                or any(ord(c) < 32 for c in path) or any(p in {".", ".."} for p in path.split("/"))):
            raise LabError("ambiguous-path-denied")
        if not any(path == p or path.startswith(p if p.endswith("/") else p + "/")
                   for p in self.paths[origin(url)]):
            raise LabError("path-denied")
        return url


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Pin the validated numeric address; TLS still verifies the original hostname.
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class Fetcher:
    def __init__(self, scope):
        self.scope, self.requests, self.bytes = scope, 0, 0
        self.written, self.last_request = 0, 0

    def get(self, value):
        url = self.scope.url(value)
        if self.requests >= self.scope.limits["max_requests"]:
            raise StopRun("request-quota")
        self.requests += 1
        delay = self.scope.limits["min_interval_ms"] / 1000 - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        self.scope.check()
        self.last_request = time.monotonic()
        p = urlsplit(url)
        port = p.port or 443
        try:
            answers = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
            addresses = [a[4][0] for a in answers]
            ips = [ipaddress.ip_address(a) for a in addresses]
            if not ips or any(not a.is_global or a.is_reserved or a.is_multicast
                              or getattr(a, "ipv4_mapped", None)
                              or getattr(a, "sixtofour", None) or getattr(a, "teredo", None)
                              for a in ips):
                raise LabError("dns-address-denied")
            self.scope.check()
            timeout = max(0.01, min(10, self.scope.deadline - time.monotonic()))
            conn = PinnedHTTPS(p.hostname, port, addresses[0], timeout)
            try:
                conn.request("GET", urlunsplit(("", "", p.path, p.query, "")),
                             headers={"User-Agent": f"MITR3-JS-Lab/{VERSION}",
                                      "Accept-Encoding": "identity"})
                response = conn.getresponse()
                if response.status != 200:
                    raise LabError("redirect-denied" if 300 <= response.status < 400 else "http-status-denied")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise LabError("content-encoding-denied")
                cap = min(self.scope.limits["max_file_bytes"],
                          max(0, self.scope.limits["max_bytes"] - self.bytes - self.written))
                chunks, size = [], 0
                while True:
                    self.scope.check()
                    chunk = response.read1(min(65536, cap - size + 1))
                    self.bytes += len(chunk)
                    size += len(chunk)
                    if size > cap:
                        raise StopRun("download-byte-quota")
                    if not chunk:
                        break
                    chunks.append(chunk)
                headers = {k: response.getheader(k, "") for k in ("Content-Type", "SourceMap", "X-SourceMap")}
                return b"".join(chunks), headers
            finally:
                conn.close()
        except (OSError, ValueError, http.client.HTTPException):
            raise LabError("network-or-tls-failure") from None


class PageScripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base, self.refs, self.inline, self.current = None, [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "base" and self.base is None and a.get("href"):
            self.base = a["href"]
        if tag == "script" and (a.get("type") or "").lower() in JS_MIMES | {"", "module"}:
            if a.get("src"):
                self.refs.append(a["src"])
            else:
                self.current = []
        if tag == "link" and ("modulepreload" in (a.get("rel") or "").lower().split()
                              or ("preload" in (a.get("rel") or "").lower().split()
                                  and a.get("as") == "script")) and a.get("href"):
            self.refs.append(a["href"])
        if len(self.refs) + len(self.inline) > 512:
            raise StopRun("html-reference-quota")

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            self.inline.append("".join(self.current).encode())
            self.current = None


def map_url(text, headers):
    value = headers.get("SourceMap") or headers.get("X-SourceMap")
    if value:
        return value.strip()
    matches = list(MAP_REF.finditer(text))
    return next((x for x in matches[-1].groups() if x), None) if matches else None


def inline_map(value, cap):
    if len(value) > cap * 3:
        raise LabError("inline-map-too-large")
    match = re.fullmatch(r"data:application/json(?:;charset=[uU][tT][fF]-8)?(;base64)?,(.*)", value, re.S)
    if not match:
        raise LabError("inline-map-type-denied")
    try:
        raw = base64.b64decode(match[2], validate=True) if match[1] else unquote_to_bytes(match[2])
    except (ValueError, binascii.Error):
        raise LabError("invalid-map-base64") from None
    if len(raw) > cap:
        raise LabError("inline-map-too-large")
    return raw


def original_sources(data, depth=0):
    if depth > 8 or not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 3:
        raise LabError("invalid-source-map")
    if "sections" in data:
        sections = data["sections"]
        if not isinstance(sections, list) or len(sections) > 256:
            raise LabError("invalid-map-sections")
        result, gaps = [], []
        previous_offset = (-1, -1)
        for index, section in enumerate(sections):
            offset = section.get("offset") if isinstance(section, dict) else None
            if (not isinstance(offset, dict) or set(offset) != {"line", "column"}
                    or any(type(v) is not int or v < 0 for v in offset.values())
                    or (offset["line"], offset["column"]) <= previous_offset):
                raise LabError("invalid-map-section-offset")
            previous_offset = (offset["line"], offset["column"])
            if not isinstance(section, dict) or "map" not in section:
                gaps.append("external-or-missing-map-section")
                continue
            sources, missing = original_sources(section["map"], depth + 1)
            result.extend(([index, *source_path], body) for source_path, body in sources)
            gaps.extend(missing)
            if len(result) + len(gaps) > 256:
                raise LabError("map-source-quota")
        return result, gaps
    names, contents = data.get("sources"), data.get("sourcesContent", [])
    if (not isinstance(names, list) or len(names) > 256 or not isinstance(contents, list)
            or len(contents) > len(names)
            or any(n is not None and not isinstance(n, str) for n in names)
            or any(c is not None and not isinstance(c, str) for c in contents)):
        raise LabError("invalid-map-sources")
    if (not isinstance(data.get("mappings"), str) or not isinstance(data.get("names"), list)
            or any(not isinstance(n, str) for n in data["names"])
            or any(k in data and not isinstance(data[k], str) for k in ("sourceRoot", "file"))
            or ("ignoreList" in data and (not isinstance(data["ignoreList"], list)
                or any(type(n) is not int or not 0 <= n < len(names) for n in data["ignoreList"])))):
        raise LabError("invalid-map-schema")
    return ([([index], c.encode()) for index, c in enumerate(contents) if c is not None],
            ["missing-sourcesContent"] if len(contents) < len(names) or None in contents else [])


class Run:
    def __init__(self, out, scope, mode, maps):
        out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.out, self.scope, self.maps = out, scope, maps
        self.artifacts, self.edges, self.gaps = [], [], []
        self.written, self.input_bytes, self.audit_head = 0, 0, "0" * 64
        for name in ("raw", "derived"):
            (out / name).mkdir(mode=0o700)
        self.manifest = {"tool": "MITR3 JS Reverse Lab", "version": VERSION,
                         "schema_version": "mitr3-js-evidence-v1", "run_id": uuid.uuid4().hex,
                         "created_at": datetime.now(timezone.utc).isoformat(),
                         "runtime": {"python": platform.python_version(), "system": platform.system()},
                         "collector_sha256": digest(Path(__file__).read_bytes()),
                         "limits": dict(scope.limits), "retention_days": scope.retention_days,
                         "data_classification": "private-unreviewed",
                         "case_id": scope.case_id, "scope_sha256": scope.sha256,
                         "mode": mode, "untrusted_content": True,
                         "network_requests": 0, "network_bytes": 0,
                         "analysis": "text-heuristics; no AST or execution",
                         "browser_guarded": "not integrated", "artifacts": self.artifacts,
                         "dependency_candidates": self.edges, "gaps": self.gaps}
        self.audit = self.create("audit.jsonl")
        self.event("run-started")

    def create(self, name):
        return os.fdopen(os.open(self.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")

    def event(self, event, **fields):
        try:
            record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event,
                      "previous_sha256": self.audit_head, **fields}
            self.audit_head = digest(packed(record))
            self.audit.write(packed({**record, "sha256": self.audit_head}).replace(b"\n", b"") + b"\n")
            self.audit.flush()
            os.fsync(self.audit.fileno())
        except StopRun:
            # An interrupted commit cannot be certified by a later manifest/checksum.
            raise OSError("evidence-commit-interrupted") from None

    def gap(self, reason):
        self.gaps.append(reason)
        self.event("gap", reason=reason)

    def save(self, kind, raw, url=None, parent=None):
        self.scope.check()
        if len(self.artifacts) >= self.scope.limits["max_artifacts"]:
            raise StopRun("artifact-quota")
        if (len(raw) > self.scope.limits["max_file_bytes"]
                or self.input_bytes + self.written + len(raw) > self.scope.limits["max_bytes"]):
            raise StopRun("artifact-byte-quota")
        sha = digest(raw)
        suffix = {"html": "html", "script": "js", "inline": "js", "map": "js.map", "original": "js.txt"}[kind]
        folder = "derived" if kind == "original" else "raw"
        name = f"{folder}/{kind}-{len(self.artifacts) + 1:04d}-{sha[:16]}.{suffix}"
        try:
            with self.create(name) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            item = {"file": name, "kind": kind, "bytes": len(raw), "sha256": sha}
            if url:
                item.update(url_meta(url))
            if parent:
                item["parent"] = parent
            self.artifacts.append(item)
            self.written += len(raw)
            self.event("artifact-saved", file=name, artifact_sha256=sha)
        except StopRun:
            raise OSError("evidence-commit-interrupted") from None
        return item

    def consume_input(self, size):
        self.input_bytes += size
        if self.input_bytes + self.written > self.scope.limits["max_bytes"]:
            raise StopRun("aggregate-byte-quota")

    def script(self, raw, url, headers, provider, kind="script", parent=None):
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeError:
            raise LabError("unsupported-javascript-encoding") from None
        if b"\x00" in raw or text.lstrip().lower().startswith(("<!doctype", "<html", "<head", "<body")):
            raise LabError("javascript-content-mismatch")
        item = self.save(kind, raw, url, parent)
        self.analyze(item, raw, url)
        if not self.maps:
            return
        if not self.scope.allow_maps:
            raise LabError("source-maps-not-authorized")
        ref = map_url(raw.decode("utf-8", errors="replace"), headers)
        if not ref:
            item["source_map"] = "not-declared"
            return
        try:
            map_target = None
            if ref.startswith("data:"):
                data = inline_map(ref, self.scope.limits["max_file_bytes"])
                self.consume_input(len(data))
            else:
                map_target = self.scope.url(urljoin(url, ref))
                self.event("map-requested", origin=origin(map_target), url_id=digest(map_target.encode()))
                data, _ = provider(map_target)
            mapped = self.save("map", data, map_target, item["file"])
            sources, gaps = original_sources(parse_json(data))
            item["source_map"] = mapped["file"]
            for reason in gaps:
                self.gap(reason)
            for source_path, source in sources:
                original = self.save("original", source, parent=mapped["file"])
                original["source_index_path"] = source_path
                # Original module names aren't safe network bases; don't resolve their imports.
                self.analyze(original, source, None)
        except StopRun:
            raise
        except LabError as exc:
            item["source_map"] = "unrecovered"
            self.gap(str(exc))

    def analyze(self, item, raw, url):
        # shortcut: text matches include comments/strings; use an audited AST parser for semantic claims.
        text = raw.decode("utf-8", errors="replace")
        item["gsap_candidates"] = []
        for match in GSAP.finditer(text):
            if len(item["gsap_candidates"]) >= 128:
                self.gap("gsap-candidate-quota")
                break
            item["gsap_candidates"].append({"api": re.sub(r"\s+", "", match[0])[:-1],
                                             "char_offset": match.start(),
                                             "line": text.count("\n", 0, match.start()) + 1})
        for index, match in enumerate(IMPORTS.finditer(text)):
            if index >= 128 or len(self.edges) >= 2048:
                self.gap("dependency-candidate-quota")
                break
            spec = match[1] or match[2]
            edge = {"from": item["file"], "char_offset": match.start(),
                    "evidence": "text-candidate", "fetched": False,
                    "specifier_sha256": digest(spec.encode())}
            if url and spec.startswith((".", "/", "https:")):
                try:
                    edge.update(url_meta(self.scope.url(urljoin(url, spec))))
                    edge["resolution"] = "in-scope-candidate"
                except StopRun:
                    raise
                except LabError:
                    edge["resolution"] = "denied"
            else:
                edge["resolution"] = "unresolved-module"
            self.edges.append(edge)

    def finish(self, fatal=None):
        if fatal:
            self.gap(fatal)
        status = "partial" if self.gaps else "complete-within-v0.2-limits"
        self.event("run-finished", status=status)
        self.audit.close()
        self.manifest.update(status=status, bytes_written=self.written,
                             input_body_bytes=self.input_bytes,
                             audit_head_sha256=self.audit_head)
        report = ("MITR3 JS Reverse Lab " + VERSION + "\n"
                  + f"Status: {status}\nArtifacts: {len(self.artifacts)}\n"
                  + f"Recovered sources: {sum(x['kind'] == 'original' for x in self.artifacts)}\n"
                  + f"GSAP text candidates: {sum(len(x.get('gsap_candidates', [])) for x in self.artifacts)}\n"
                  + f"Dependency text candidates: {len(self.edges)}\nGaps: {len(self.gaps)}\n\n"
                  + "Untrusted private evidence. Text matches may occur in comments/strings.\n"
                  + "No AST, deobfuscation, module fetching or proof of runtime behavior.\n"
                  + "No browser capture or guarded-browser certification.\n").encode()
        with self.create("report.txt") as stream:
            stream.write(report)
        self.manifest["report_sha256"] = digest(report)
        manifest_data = packed(self.manifest)
        with self.create("manifest.json") as stream:
            stream.write(manifest_data)
        checks = {x["file"]: x["sha256"] for x in self.artifacts}
        checks.update({"manifest.json": digest(manifest_data), "report.txt": digest(report),
                       "audit.jsonl": digest((self.out / "audit.jsonl").read_bytes())})
        with self.create("SHA256SUMS") as stream:
            stream.write("".join(f"{sha}  {name}\n" for name, sha in checks.items()).encode())
        for item in self.artifacts:
            (self.out / item["file"]).chmod(0o400)
        for name in ("raw", "derived"):
            (self.out / name).chmod(0o500)
        return 1 if self.gaps else 0


def collect(run, entry_url):
    fetcher = Fetcher(run.scope)

    def get(url):
        url = run.scope.url(url)
        run.event("get-requested", origin=origin(url), url_id=digest(url.encode()))
        fetcher.written = run.written
        try:
            result = fetcher.get(url)
            run.consume_input(len(result[0]))
            return result
        finally:
            run.manifest["network_requests"] = fetcher.requests
            run.manifest["network_bytes"] = fetcher.bytes

    entry_url = run.scope.url(entry_url)
    raw, headers = get(entry_url)
    if headers["Content-Type"].split(";")[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
        raise LabError("expected-html")
    page = run.save("html", raw, entry_url)
    parser = PageScripts()
    parser.feed(raw.decode("utf-8", errors="replace"))
    parser.close()
    base = run.scope.url(urljoin(entry_url, parser.base)) if parser.base else entry_url
    seen = set()
    for ref in parser.refs:
        try:
            url = run.scope.url(urljoin(base, ref))
            if url in seen:
                continue
            seen.add(url)
            data, hdrs = get(url)
            mime = hdrs["Content-Type"].split(";")[0].strip().lower()
            if mime not in JS_MIMES | {"text/plain", "application/octet-stream"}:
                raise LabError("expected-javascript")
            run.script(data, url, hdrs, get, parent=page["file"])
        except StopRun:
            raise
        except LabError as exc:
            run.gap(str(exc))
    for data in parser.inline:
        run.script(data, base, {}, get, kind="inline", parent=page["file"])


def har_body(entry, scope):
    request, response = entry.get("request", {}), entry.get("response", {})
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise LabError("invalid-har-entry")
    if request.get("method") != "GET" or response.get("status") != 200:
        raise LabError("har-method-or-status-denied")
    if request.get("cookies") or response.get("cookies") or request.get("postData"):
        raise LabError("har-session-entry-denied")
    headers = {}
    for owner in (request, response):
        values = owner.get("headers", [])
        if not isinstance(values, list):
            raise LabError("invalid-har-headers")
        for header in values:
            if not isinstance(header, dict) or not isinstance(header.get("name"), str) or not isinstance(header.get("value"), str):
                raise LabError("invalid-har-headers")
            name = header["name"].lower()
            if name in {"cookie", "set-cookie", "authorization", "proxy-authorization"} or SECRET_KEY.search(name):
                raise LabError("har-session-entry-denied")
            if owner is response and name in {"sourcemap", "x-sourcemap"}:
                headers["SourceMap" if name == "sourcemap" else "X-SourceMap"] = header["value"]
    scope.url(request.get("url"))
    content = response.get("content")
    if not isinstance(content, dict) or not isinstance(content.get("text"), str):
        raise LabError("har-body-missing")
    text = content["text"]
    if len(text) > scope.limits["max_file_bytes"] * 2:
        raise LabError("har-body-too-large")
    try:
        encoding = content.get("encoding")
        if encoding not in (None, "base64"):
            raise LabError("har-encoding-denied")
        raw = base64.b64decode(text, validate=True) if encoding else text.encode()
    except (ValueError, binascii.Error):
        raise LabError("invalid-har-base64") from None
    if len(raw) > scope.limits["max_file_bytes"]:
        raise LabError("har-body-too-large")
    return raw, headers


def import_har(run, path):
    raw = read_local(path, 64 * MIB)
    doc = parse_json(raw)
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or len(entries) > 1024:
        raise LabError("invalid-har-or-entry-quota")
    run.manifest["har_sha256"] = digest(raw)
    index = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            run.gap("invalid-har-entry")
            continue
        try:
            url = run.scope.url(entry["request"].get("url"))
            if url in index:
                run.gap("duplicate-har-url-first-used")
            else:
                index[url] = entry
        except StopRun:
            raise
        except LabError as exc:
            run.gap(str(exc))

    def get(url):
        run.scope.url(url)
        if url not in index:
            raise LabError("map-not-in-har")
        result = har_body(index[url], run.scope)
        run.consume_input(len(result[0]))
        return result

    for url, entry in index.items():
        response = entry.get("response")
        content = response.get("content", {}) if isinstance(response, dict) else {}
        mime = content.get("mimeType", "") if isinstance(content, dict) else ""
        if not isinstance(mime, str):
            run.gap("invalid-har-mime")
            continue
        mime = mime.split(";")[0].strip().lower()
        if mime not in JS_MIMES and not (urlsplit(url).path.endswith((".js", ".mjs"))
                                       and mime in {"", "text/plain", "application/octet-stream"}):
            continue
        try:
            data, headers = get(url)
            run.script(data, url, headers, get)
        except StopRun:
            raise
        except LabError as exc:
            run.gap(str(exc))
    run.manifest["network_requests"] = 0
    run.manifest["network_bytes"] = 0
    if not any(x["kind"] == "script" for x in run.artifacts):
        run.gap("no-javascript-imported")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, source in (("collect", "url"), ("import-har", "har")):
        sub = commands.add_parser(name)
        sub.add_argument(source)
        sub.add_argument("--scope", required=True, type=Path)
        sub.add_argument("--out", required=True, type=Path, help="New private directory; refuses overwrite")
        sub.add_argument("--maps", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("evidence", type=Path)
    return parser.parse_args(argv)


def verify_package(path, expected_scope=None, expected_har_sha256=None, expected_maps=None):
    if any(p.is_symlink() for p in (path.absolute(), *path.absolute().parents)):
        raise LabError("evidence-symlink-denied")
    manifest = parse_json(read_local(path / "manifest.json", 8 * MIB))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "mitr3-js-evidence-v1":
        raise LabError("invalid-manifest-schema")
    artifacts = manifest.get("artifacts")
    limits = manifest.get("limits")
    if (not isinstance(limits, dict) or set(limits) != set(LIMITS)
            or any(type(limits[k]) is not int or not 1 <= limits[k] <= LIMITS[k][1] for k in LIMITS)):
        raise LabError("invalid-manifest-limits")
    if (not isinstance(artifacts, list)
            or len(artifacts) > limits.get("max_artifacts", 0)):
        raise LabError("invalid-manifest-artifacts")
    if (type(manifest.get("input_body_bytes")) is not int or manifest["input_body_bytes"] < 0
            or type(manifest.get("bytes_written")) is not int or manifest["bytes_written"] < 0
            or not isinstance(manifest.get("run_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", manifest["run_id"])
            or manifest.get("data_classification") != "private-unreviewed"
            or manifest.get("version") != VERSION
            or manifest.get("status") not in {"partial", "complete-within-v0.2-limits"}
            or not isinstance(manifest.get("gaps"), list) or len(manifest["gaps"]) > 4096
            or any(not isinstance(g, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", g) for g in manifest["gaps"])):
        raise LabError("invalid-manifest-metadata")
    if expected_scope is not None:
        if (limits != expected_scope.limits or manifest.get("scope_sha256") != expected_scope.sha256
                or manifest.get("case_id") != expected_scope.case_id
                or manifest.get("retention_days") != expected_scope.retention_days
                or manifest.get("mode") != "import-har"
                or manifest.get("collector_sha256") != digest(Path(__file__).read_bytes())
                or manifest.get("network_requests") != 0 or manifest.get("network_bytes") != 0):
            raise LabError("manifest-policy-mismatch")
    if expected_har_sha256 is not None and manifest.get("har_sha256") != expected_har_sha256:
        raise LabError("manifest-input-mismatch")
    expected = {"manifest.json", "report.txt", "audit.jsonl"}
    size, kinds = 0, {}
    formats = {"html": ("raw", "html"), "script": ("raw", "js"), "inline": ("raw", "js"),
               "map": ("raw", "js.map"), "original": ("derived", "js.txt")}
    for item in artifacts:
        if (not isinstance(item, dict) or not isinstance(item.get("file"), str)
                or not isinstance(item.get("kind"), str) or item["kind"] not in formats
                or item["file"] in expected or type(item.get("bytes")) is not int
                or not 0 <= item["bytes"] <= limits["max_file_bytes"]
                or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])):
            raise LabError("invalid-artifact-record")
        kind = item["kind"]
        folder, suffix = formats[kind]
        if not re.fullmatch(rf"{folder}/{kind}-\d{{4}}-{item['sha256'][:16]}\.{re.escape(suffix)}", item["file"]):
            raise LabError("artifact-kind-path-mismatch")
        parent_kind = kinds.get(item.get("parent")) if isinstance(item.get("parent"), str) else None
        if ((kind == "map" and parent_kind not in {"script", "inline"})
                or (kind == "original" and parent_kind != "map")
                or (kind in {"script", "inline"} and "parent" in item and parent_kind != "html")
                or (kind == "html" and "parent" in item)):
            raise LabError("artifact-parent-mismatch")
        if kind == "original":
            source_path = item.get("source_index_path")
            if (not isinstance(source_path, list) or not 1 <= len(source_path) <= 9
                    or any(type(index) is not int or not 0 <= index < 256 for index in source_path)):
                raise LabError("invalid-source-index")
        if expected_scope is not None:
            if item.get("url"):
                expected_scope.url(item["url"])
            if item.get("kind") in {"map", "original"} and (not expected_scope.allow_maps or expected_maps is False):
                raise LabError("unauthorized-derived-artifact")
        size += item["bytes"]
        expected.add(item["file"])
        kinds[item["file"]] = kind
    if size != manifest["bytes_written"] or size + manifest["input_body_bytes"] > limits["max_bytes"]:
        raise LabError("manifest-byte-quota")
    for item in artifacts:
        data = read_local(path / item["file"], limits["max_file_bytes"])
        if len(data) != item["bytes"] or digest(data) != item["sha256"]:
            raise LabError("artifact-integrity-failure")
    actual = set()
    for file in path.rglob("*"):
        if file.is_symlink():
            raise LabError("evidence-symlink-denied")
        if file.is_file():
            actual.add(file.relative_to(path).as_posix())
        elif not file.is_dir() or file.relative_to(path).as_posix() not in {"raw", "derived"}:
            raise LabError("unexpected-evidence-entry")
    if actual != expected | {"SHA256SUMS"}:
        raise LabError("unexpected-evidence-file")
    checks = {}
    for line in read_local(path / "SHA256SUMS", MIB).decode("ascii").splitlines():
        sha, name = line.split("  ")
        if name in checks or name not in expected or not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise LabError("invalid-checksums")
        checks[name] = sha
        if digest(read_local(path / name, 8 * MIB if name not in {a['file'] for a in artifacts} else limits["max_file_bytes"])) != sha:
            raise LabError("checksum-mismatch")
    if set(checks) != expected:
        raise LabError("incomplete-checksums")
    previous, last_event = "0" * 64, None
    for line in read_local(path / "audit.jsonl", 8 * MIB).splitlines():
        item = parse_json(line)
        if not isinstance(item, dict):
            raise LabError("invalid-audit")
        sha = item.pop("sha256", None)
        if item.get("previous_sha256") != previous or digest(packed(item)) != sha:
            raise LabError("audit-chain-mismatch")
        previous = sha
        last_event = item
    if manifest.get("audit_head_sha256") != previous:
        raise LabError("audit-head-mismatch")
    if last_event is None or last_event.get("event") != "run-finished" or last_event.get("status") != manifest.get("status"):
        raise LabError("audit-not-finished")
    return manifest


def main(argv=None):
    args = arguments(argv)
    run = None
    try:
        scope = Scope(read_local(args.scope, MIB))
        if args.command == "collect":
            scope.url(args.url)
        run = Run(args.out, scope, args.command, args.maps)
        fatal = None
        # POSIX timer also interrupts blocking DNS/header reads; sealing evidence runs afterward.
        def deadline_expired(signum, frame):
            raise StopRun("time-quota")
        previous_handler = signal.signal(signal.SIGALRM, deadline_expired)
        try:
            remaining = min(scope.deadline - time.monotonic(),
                            (scope.expires - datetime.now(timezone.utc)).total_seconds())
            signal.setitimer(signal.ITIMER_REAL, max(0.001, remaining))
            try:
                collect(run, args.url) if args.command == "collect" else import_har(run, Path(args.har))
            except LabError as exc:
                fatal = str(exc)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
        status = run.finish(fatal)
        print(json.dumps({"status": run.manifest["status"], "artifacts": len(run.artifacts),
                          "gaps": len(run.gaps)}))
        return status
    except (LabError, OSError, UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        if run is not None and not run.audit.closed:
            run.audit.close()
        reason = str(exc) if isinstance(exc, LabError) else "local-io-or-input-failure"
        print(json.dumps({"status": "failed", "reason": reason}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    import importlib.util
    helper = Path(__file__).resolve().parents[1] / "tools/js_lab_sandbox.py"
    spec = importlib.util.spec_from_file_location("js_lab_sandbox", helper)
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    sys.exit(sandbox.launch(sys.modules[__name__]))
