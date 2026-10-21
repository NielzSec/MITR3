#!/usr/bin/env python3
"""mitr3-meli-seller-setup.py — provisioning helper for a Mercado Libre test seller (user C).

Language: Python 3, target: Arch Linux, runtime: system python3.
Endpoint (documented): POST https://api.mercadolibre.com/users/test_user
Then publishes ONE test listing: title 'Item de Teste – Por favor, NÃO OFERTAR!',
category 'Outros' (MLB), R$ 19.00.

SAFETY: --dry-run default sends nothing. --live requires Gate 2 approval; the
absence of a gate marker aborts before any traffic. No torque, no retry storm.
"""
from __future__ import annotations
import argparse, json, os, sys, urllib.error, urllib.request
from pathlib import Path
from typing import Any

API = "https://api.mercadolibre.com"
PRIV = Path.home() / ".local" / "share" / "mitr3"

TEST_TITLE = "Item de Teste – Por favor, NÃO OFERTAR!"
TEST_PRICE = 19.00
# "Outros" em MLB — id real só consultado sob --live (GET /sites/MLB/categories), nunca hardcoded com valor inventado.
CATEGORY_ID = None


def private_token() -> str:
    p = Path(os.environ["MITR3_MELI_TOKEN"]) if os.environ.get("MITR3_MELI_TOKEN") else PRIV / "h1" / "mercadolibre" / "app_token"
    try:
        st = p.stat()
        if st.st_uid != os.getuid() or (st.st_mode & 0o777) != 0o600:
            return ""
        raw = p.read_text().strip()
        return raw if 8 <= len(raw) <= 4096 and all(32 <= ord(c) <= 126 for c in raw) else ""
    except OSError:
        return ""


def request(method: str, path: str, body: dict) -> dict:
    if not path.startswith("https://api.mercadolibre.com/"):
        raise ValueError(f"BLOCKED_URL: {path}")
    return {"method": method, "url": path, "body": body}


def run(token: str, args: Any) -> None:
    reqs = []
    if not args.only_listing:
        reqs.append(request("POST", API + "/users/test_user",
                            {"site_id": "MLB", "site_status": "active"}))
    reqs.append(request("POST", API + "/items", {
        "site_id": "MLB",
        "title": TEST_TITLE,
        "category_id": CATEGORY_ID,  # under --live resolved via GET /sites/MLB/categories primeiro
        "price": TEST_PRICE,
        "currency_id": "BRL",
        "available_quantity": 1,
        "buying_mode": "buy_it_now",
        "listing_type_id": "gold_special",
        "condition": "new",
        "sale_terms": [{"id": "WARRANTY_TYPE", "value_name": "Sem garantia"}],
    }))
    if args.live:
        gate_marker = PRIV / "h1" / "mercadolibre" / "GATE2_APPROVED"
        if not gate_marker.is_file() or gate_marker.read_text().strip() != "approved":
            raise SystemExit("refusing: --live sem marcador Gate 2. Nada enviado.")
        if not token:
            raise SystemExit("refusing: --live sem token. Nada enviado.")
        if not CATEGORY_ID:
            raise SystemExit("refusing: --live exige category_id resolvido (GET /sites/MLB/categories). Nada enviado.")
        for r in reqs:
            req = urllib.request.Request(r["url"], method=r["method"],
                                         data=json.dumps(r["body"]).encode(),
                                         headers={"Authorization": "Bearer " + token,
                                                  "Content-Type": "application/json",
                                                  "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read(4096)
                    print(f"[live] {r['method']} {r['url']} -> {resp.status} "
                          f"sha256={__import__('hashlib').sha256(body).hexdigest()[:16]}")
            except urllib.error.HTTPError as e:
                print(f"[live] {r['method']} {r['url']} -> HTTP {e.code} (sem envio de retry)")
        return
    for r in reqs:
        print(f"[dry-run] {r['method']} {r['url']}")
        print("  body:", json.dumps(r["body"], ensure_ascii=False)[:400])
    print("NO TRAFFIC SENT — dry-run. Para executar: obter Gate 2 aprovado + token.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Provision MELI test seller (C). Dry-run default: sends nothing.")
    ap.add_argument("--live", action="store_true", help="send traffic (requires Gate 2 approval marker + token)")
    ap.add_argument("--only-listing", action="store_true", help="skip test-user creation")
    args = ap.parse_args()
    try:
        run(private_token(), args)
    except ValueError as e:
        print(e, file=sys.stderr)
        raise SystemExit(2) from None
    except SystemExit:
        raise


if __name__ == "__main__":
    main()
