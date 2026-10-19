"""Defensive helpers for the TelegramBot Ollama gateway (review candidate only).

Do not deploy to the running JobHunter service until its owner approves the
route/method allowlist and completes integration tests.
"""
from __future__ import annotations

import hmac
import os
from urllib.parse import unquote


# Only app-required routes should be exposed by the proxy. Confirm with the
# application owner before adding additional Ollama endpoints.
DEFAULT_ROUTES = frozenset({
    "api/tags": frozenset({"GET"}),
    "api/generate": frozenset({"POST"}),
    "api/chat": frozenset({"POST"}),
    "api/embed": frozenset({"POST"}),
    "api/embeddings": frozenset({"POST"}),
    "api/show": frozenset({"POST"}),
}.items())
ROUTES = dict(DEFAULT_ROUTES)
SAFE_UPSTREAM_HEADERS = frozenset({
    "content-type",
    "accept",
    "user-agent",
    "x-request-id",
})


def proxy_secret_from_environment() -> str:
    """Fail closed when the operator has not supplied a real bearer token."""
    key = (os.environ.get("PROXY_TOKEN") or os.environ.get("JOBHUNTER_KAGGLE_KEY") or "").strip()
    if len(key) < 32 or len(set(key)) < 8:
        raise ValueError("PROXY_TOKEN/JOBHUNTER_KAGGLE_KEY must be a strong secret")
    return key


def authenticated(headers: dict[str, str], expected: str) -> bool:
    if not expected:
        return False
    bearer = headers.get("authorization", "")
    supplied = headers.get("x-api-key", "")
    return hmac.compare_digest(bearer, "Bearer " + expected) or hmac.compare_digest(supplied, expected)


def safe_ollama_path(path: str, method: str) -> str:
    """Exact route/method allowlist; rejects encoded traversal and URL tricks."""
    if not isinstance(path, str) or not isinstance(method, str):
        raise ValueError("invalid upstream request")
    candidate = unquote(path).strip()
    if candidate != path or "%" in candidate or candidate.startswith("/") or "\\" in candidate:
        raise ValueError("encoded/absolute path not allowed")
    if candidate not in ROUTES or method.upper() not in ROUTES[candidate]:
        raise ValueError("Ollama route or method not allowed")
    return "/" + candidate


def safe_forward_headers(headers: dict[str, str]) -> dict[str, str]:
    """Never forward gateway auth, cookies or proxy/hop-by-hop headers."""
    return {k: v for k, v in headers.items() if k.lower() in SAFE_UPSTREAM_HEADERS}
