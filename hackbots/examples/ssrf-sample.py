# Amostra sintética de backend para RELAY (MITR3)
import requests

def handle_webhook_preview(webhook_url):
    # VULNERABILIDADE: URL fornecida pelo cliente consumida diretamente
    resp = requests.get(webhook_url, timeout=5)
    return resp.text[:200]
