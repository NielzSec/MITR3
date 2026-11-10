#!/usr/bin/env python3
"""MITR3 Gemini Research MCP v1.0.

Scoped Gemini Developer API integration with optional, request-local
HARM_CATEGORY_DANGEROUS_CONTENT/BLOCK_NONE. No unrestricted policy bypass:
model/provider controls still apply. No Google key stored in agent configs.

Commands:
  python3 mitr3-gemini-research-mcp.py            # MCP stdio server
  python3 mitr3-gemini-research-mcp.py status     # offline config only
  python3 mitr3-gemini-research-mcp.py dry-run    # offline payload structure
  python3 mitr3-gemini-research-mcp.py models     # authenticated metadata GET

Environment:
  GEMINI_API_KEY or GOOGLE_API_KEY
Alternatively place a key in ~/.config/mitr3/gemini-api-key with chmod 600.

The MCP does not execute code, scrape websites, attach external tools, or
send prompts to any domain other than Google's API endpoint.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request

VERSION = "1.0.0"
API_ORIGIN = "https://generativelanguage.googleapis.com"
API_ROOT = API_ORIGIN + "/v1beta"
DEFAULT_MODEL = "gemini-3.5-flash-lite"
MODELS = {"gemini-3.5-flash-lite", "gemini-3.6-flash", "gemini-3.8-flash"}
PROFILE_VALUES = {"standard", "authorized_research"}
MAX_PROMPT_CHARS = 6000
MAX_RESPONSE_BYTES = 512 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_OUTPUT_TOKENS = 2048
MAX_CALLS_PER_SESSION = 5
MAX_GENERATED_OUTPUT_TOKENS = 4096
GLOBAL_DAILY_GENERATION_LIMIT = 12
CASE_RE = re.compile(r"^MITR3-[A-Za-z0-9][A-Za-z0-9_-]{2,60}$")
SECRET_LIKE = (
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I),
    re.compile(r"\bAuthorization\s*:\s*Bearer\s+\S+", re.I),
)
AUDIT = Path.home() / ".local/state/mitr3/gemini-research/audit.jsonl"
KEY_FILE = Path.home() / ".config/mitr3/gemini-api-key"


class UserInputError(Exception):
    pass


class ProviderFailure(Exception):
    def __init__(self, status: int | None = None, reason: str = "UPSTREAM_ERROR"):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class NeverRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_api_key(env: dict | None = None, file: Path | None = None) -> str | None:
    source = os.environ if env is None else env
    for label in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        value = source.get(label, "")
        if isinstance(value, str) and 20 <= len(value.strip()) < 512:
            return value.strip()
    p = KEY_FILE if file is None else file
    if not p.exists():
        return None
    if p.is_symlink() or not p.is_file():
        raise UserInputError("KEY_FILE_NOT_REGULAR")
    state = p.stat()
    if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) != 0o600 or state.st_size > 512:
        raise UserInputError("KEY_FILE_UNSAFE_PERMISSIONS")
    value = p.read_text(encoding="utf-8").strip()
    if not (20 <= len(value) < 512):
        raise UserInputError("KEY_FILE_INVALID")
    return value


def check_prompt(text: str, case_id: str):
    if not isinstance(text, str) or not (1 <= len(text.strip()) <= MAX_PROMPT_CHARS):
        raise UserInputError("INVALID_PROMPT_LENGTH")
    if not isinstance(case_id, str) or not CASE_RE.fullmatch(case_id):
        raise UserInputError("CASE_ID_REQUIRED")
    if any(pattern.search(text) for pattern in SECRET_LIKE):
        raise UserInputError("SECRET_LIKE_CONTENT_BLOCKED")
    if "\x00" in text:
        raise UserInputError("INVALID_CONTROL_CHARACTER")


def make_request(prompt: str, case_id: str, *, profile="standard",
                 model=DEFAULT_MODEL, max_output_tokens=384) -> dict:
    check_prompt(prompt, case_id)
    if profile not in PROFILE_VALUES:
        raise UserInputError("PROFILE_NOT_ALLOWED")
    if model not in MODELS:
        raise UserInputError("MODEL_NOT_ALLOWLISTED")
    if type(max_output_tokens) is not int or not 1 <= max_output_tokens <= MAX_OUTPUT_TOKENS:
        raise UserInputError("INVALID_OUTPUT_TOKENS")
    document = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_output_tokens,
            "temperature": 0.2,
        },
    }
    if profile == "authorized_research":
        document["safetySettings"] = [{
            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
            "threshold": "BLOCK_NONE",
        }]
    return document


def _request(method: str, url: str, *, api_key: str, payload: dict | None = None):
    if not url.startswith(API_ROOT + "/") or any(x in url for x in ("@", "\x00", "#")):
        raise ProviderFailure(reason="API_DESTINATION_NOT_ALLOWED")
    data = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if payload is not None else None)
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "x-goog-api-key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "MITR3-GeminiResearch-MCP/1.0",
        },
    )
    client = urllib.request.build_opener(
        NeverRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with client.open(req, timeout=25) as response:
            if response.url != url:
                raise ProviderFailure(reason="UNEXPECTED_API_REDIRECT")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ProviderFailure(reason="RESPONSE_TOO_LARGE")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ProviderFailure(reason="INVALID_API_RESPONSE")
            return result
    except urllib.error.HTTPError as exc:
        # Never copy error body into logs. Some upstream errors echo request text.
        raise ProviderFailure(status=exc.code, reason="API_HTTP_ERROR") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProviderFailure(reason="API_CONNECTION_ERROR") from None
    except (ValueError, UnicodeError):
        raise ProviderFailure(reason="API_JSON_PARSE_ERROR") from None


def api_list_models(api_key: str):
    data = _request("GET", API_ROOT + "/models?pageSize=100", api_key=api_key)
    entries = data.get("models", [])
    if not isinstance(entries, list):
        raise ProviderFailure(reason="MODELS_RESPONSE_INVALID")
    eligible = []
    for row in entries:
        if isinstance(row, dict) and "generateContent" in row.get("supportedGenerationMethods", []):
            ident = row.get("name", "")
            if isinstance(ident, str) and re.fullmatch(r"models/gemini-[a-zA-Z0-9.-]{3,64}", ident):
                eligible.append(ident)
    return eligible[:60]


def api_generate(payload: dict, model: str, api_key: str):
    result = _request("POST", API_ROOT + "/models/" + model + ":generateContent",
                      api_key=api_key, payload=payload)
    finish_reasons = []
    output_parts = []
    for choice in result.get("candidates", [])[:2]:
        if not isinstance(choice, dict):
            continue
        finish_reasons.append(str(choice.get("finishReason", ""))[:40])
        part_list = choice.get("content", {}).get("parts", [])
        for part in part_list[:32]:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                output_parts.append(part["text"])
        if output_parts:
            break
    text = "".join(output_parts)
    usage = result.get("usageMetadata", {})
    usage = usage if isinstance(usage, dict) else {}
    # Do not silently downgrade BLOCK_NONE if provider declines its use.
    if not output_parts:
        raise ProviderFailure(reason="NO_TEXT_CANDIDATE_OR_CONTENT_FILTERED")
    return {
        "text": text[:24000],
        "finish_reasons": finish_reasons,
        "usage": {
            "input_tokens": usage.get("promptTokenCount"),
            "output_tokens": usage.get("candidatesTokenCount"),
            "total_tokens": usage.get("totalTokenCount"),
        },
    }


def append_audit(case_id: str, model: str, profile: str,
                 outcome: str, usage: dict | None = None) -> bool:
    event = {
        "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": case_id if CASE_RE.fullmatch(case_id) else "UNSPECIFIED",
        "model": model if model in MODELS else "UNKNOWN",
        "profile": profile if profile in PROFILE_VALUES else "UNKNOWN",
        "outcome": outcome[:55],
        "input_tokens": (usage or {}).get("input_tokens"),
        "output_tokens": (usage or {}).get("output_tokens"),
    }
    try:
        AUDIT.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if AUDIT.is_symlink():
            return False
        fd = os.open(AUDIT, os.O_RDWR | os.O_APPEND | os.O_CREAT |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                os.fchmod(fd, 0o600)
            length = os.fstat(fd).st_size
            if length > 4 * 1024 * 1024:
                return False
            if outcome == "REQUEST_RESERVED":
                os.lseek(fd, 0, os.SEEK_SET)
                seen = 0
                today = event["utc"][:10]
                for line in os.read(fd, length).splitlines():
                    try:
                        row = json.loads(line)
                    except (ValueError, TypeError):
                        return False
                    if not isinstance(row, dict):
                        return False
                    if row.get("outcome") == "REQUEST_RESERVED" and str(row.get("utc", ""))[:10] == today:
                        seen += 1
                if seen >= GLOBAL_DAILY_GENERATION_LIMIT:
                    return False
            os.write(fd, (json.dumps(event, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        return True
    except OSError:
        return False


def make_result(content: dict):
    return {"content": [{"type": "text", "text": json.dumps(content, ensure_ascii=False)}],
            "isError": bool(content.get("error"))}


def tool_definitions():
    return [
        {
            "name": "gemini_research_status",
            "description": (
                "Read-only local readiness of MITR3's official Gemini Developer API integration; "
                "does not perform inference or disclose API keys."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "gemini_research_models",
            "description": (
                "List Gemini generateContent model IDs supported by your API key. "
                "Metadata request only, no generative tokens."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "gemini_research_generate",
            "description": (
                "Generate a response for a MITR3 authorized lab/research case. "
                "Use profile=authorized_research to configure Google's documented "
                "HARM_CATEGORY_DANGEROUS_CONTENT=BLOCK_NONE filter for THIS request "
                "only. Other provider safeguards and program scope still apply. "
                "No host tools, browser or code execution. Metered API inference; "
                "small prompt/output budgets are strongly recommended."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "maxLength": MAX_PROMPT_CHARS},
                    "case_id": {"type": "string", "pattern": "^MITR3-[A-Za-z0-9][A-Za-z0-9_-]{2,60}$"},
                    "profile": {"type": "string", "enum": ["standard", "authorized_research"], "default": "standard"},
                    "model": {"type": "string", "enum": sorted(MODELS), "default": DEFAULT_MODEL},
                    "max_output_tokens": {"type": "integer", "minimum": 1, "maximum": MAX_OUTPUT_TOKENS, "default": 384},
                },
                "required": ["prompt", "case_id"],
                "additionalProperties": False,
            },
        },
    ]


class Gateway:
    def __init__(self):
        self.initialized = False
        self.calls = 0
        self.output_budget = MAX_GENERATED_OUTPUT_TOKENS

    def handle(self, obj: dict) -> dict | None:
        if not isinstance(obj, dict):
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"}}
        req_id = obj.get("id")
        method = obj.get("method")
        if not isinstance(method, str):
            return self.error(req_id, -32600, "Invalid Request")
        if method == "initialize":
            self.initialized = True
            params = obj.get("params", {})
            pv = params.get("protocolVersion", "2025-06-18") if isinstance(params, dict) else "2025-06-18"
            return self.result(req_id, {
                "protocolVersion": pv,
                "serverInfo": {"name": "mitr3-gemini-research", "version": VERSION},
                "capabilities": {"tools": {"listChanged": False}},
                "instructions": ("MITR3 research assistant only. "
                                 "Provider safety settings apply per call, "
                                 "and policy/scope authorization remain required."),
            })
        if method.startswith("notifications/"):
            return None
        if not self.initialized:
            return self.error(req_id, -32001, "Not initialized")
        if method == "ping":
            return self.result(req_id, {})
        if method == "tools/list":
            return self.result(req_id, {"tools": tool_definitions()})
        if method != "tools/call":
            return self.error(req_id, -32601, "Method not allowed")
        params = obj.get("params", {})
        if not isinstance(params, dict) or set(params) - {"name", "arguments"}:
            return self.error(req_id, -32602, "Invalid tools/call")
        name = params.get("name")
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return self.error(req_id, -32602, "Invalid arguments")
        allowed = next((x for x in tool_definitions() if x["name"] == name), None)
        if allowed is None:
            return self.error(req_id, -32601, "Unknown tool")
        schema = allowed["inputSchema"]
        if set(args) - set(schema.get("properties", {})):
            return self.error(req_id, -32602, "Unknown argument")
        if name == "gemini_research_status":
            if args:
                return self.error(req_id, -32602, "No arguments allowed")
            try:
                present = bool(get_api_key())
                status = {"version": VERSION, "api_key_available": present,
                          "default_model": DEFAULT_MODEL, "model_allowlist": sorted(MODELS),
                          "global_daily_generation_limit": GLOBAL_DAILY_GENERATION_LIMIT,
                          "authorized_research_safety": {
                              "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                              "threshold": "BLOCK_NONE", "per_request_only": True},
                          "network_tested": False}
                return self.result(req_id, make_result(status))
            except UserInputError:
                return self.result(req_id, make_result({"error": "KEY_FILE_INVALID"}))
        if name == "gemini_research_models":
            if args:
                return self.error(req_id, -32602, "No arguments allowed")
            try:
                key = get_api_key()
                if not key:
                    raise UserInputError("API_KEY_NOT_CONFIGURED")
                names = api_list_models(key)
                return self.result(req_id, make_result({"models": names, "inference_calls": 0}))
            except UserInputError as err:
                return self.result(req_id, make_result({"error": str(err)}))
            except ProviderFailure as err:
                return self.result(req_id, make_result({"error": err.reason,
                                                         "http_status": err.status}))
        if name != "gemini_research_generate":
            return self.error(req_id, -32601, "Unknown tool")
        case_id = args.get("case_id", "")
        profile = args.get("profile", "standard")
        model = args.get("model", DEFAULT_MODEL)
        max_tokens = args.get("max_output_tokens", 384)
        if self.calls >= MAX_CALLS_PER_SESSION or self.output_budget < max_tokens:
            return self.result(req_id, make_result({"error": "SESSION_BUDGET_EXHAUSTED"}))
        try:
            body = make_request(args.get("prompt"), case_id, profile=profile,
                                model=model, max_output_tokens=max_tokens)
            key = get_api_key()
            if not key:
                raise UserInputError("API_KEY_NOT_CONFIGURED")
            # Fail closed if audit logging is unavailable, BEFORE billable inference.
            if not append_audit(case_id, model, profile, "REQUEST_RESERVED"):
                raise UserInputError("AUDIT_OR_DAILY_BUDGET_UNAVAILABLE")
            self.calls += 1
            self.output_budget -= max_tokens
            try:
                response = api_generate(body, model, key)
            except ProviderFailure as err:
                append_audit(case_id, model, profile, "UPSTREAM_ERROR")
                return self.result(req_id, make_result({"error": err.reason,
                                                        "http_status": err.status}))
            append_audit(case_id, model, profile, "SUCCESS", response["usage"])
            return self.result(req_id, make_result({
                "model": model, "profile": profile,
                "filter_threshold_requested": ("BLOCK_NONE" if profile == "authorized_research"
                                                else "DEFAULT"),
                **response,
            }))
        except UserInputError as err:
            return self.result(req_id, make_result({"error": str(err)}))

    @staticmethod
    def result(id, payload):
        return {"jsonrpc": "2.0", "id": id, "result": payload}

    @staticmethod
    def error(id, code, message):
        return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def serve():
    gateway = Gateway()
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            break
        if len(line) > MAX_REQUEST_BYTES:
            return 4
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            answer = gateway.handle(obj)
        except (ValueError, TypeError):
            answer = Gateway.error(None, -32700, "Invalid JSON")
        except Exception:
            answer = Gateway.error(None, -32603, "Internal error")
        if answer is not None:
            data = (json.dumps(answer, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    return 0


def cli(argv: list[str]):
    action = argv[1] if len(argv) > 1 else "mcp"
    if action == "mcp":
        return serve()
    if action == "status":
        try:
            status = {"version": VERSION, "provider": "Gemini Developer API",
                      "model": DEFAULT_MODEL, "api_key_available": bool(get_api_key()),
                      "profiles": sorted(PROFILE_VALUES)}
            print(json.dumps(status, ensure_ascii=False))
            return 0
        except UserInputError as exc:
            print("CONFIG_ERROR=" + str(exc))
            return 2
    if action == "dry-run":
        req = make_request("Explicar as principais medidas de defesa OWASP Top 10.",
                           "MITR3-OFFLINE-QA", profile="authorized_research")
        print(json.dumps({"model": DEFAULT_MODEL,
                          "request_fields": sorted(req),
                          "safetySettings": req.get("safetySettings"),
                          "generationConfig": req["generationConfig"],
                          "actual_network_calls": 0}, ensure_ascii=False))
        return 0
    if action == "models":
        try:
            key = get_api_key()
            if not key:
                print("CONFIG_ERROR=API_KEY_NOT_CONFIGURED")
                return 2
            print(json.dumps({"models": api_list_models(key), "inference_calls": 0}))
            return 0
        except ProviderFailure as exc:
            print(json.dumps({"error": exc.reason, "http_status": exc.status}))
            return 2
    print("Expected one of: mcp, status, dry-run, models", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(cli(sys.argv))
