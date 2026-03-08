from __future__ import annotations

import re

from fastapi.testclient import TestClient


def bootstrap_csrf(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    csrf_token = client.cookies.get("ato_csrf")
    assert csrf_token
    return csrf_token


def extract_hidden_value(html: str, field_name: str) -> str:
    match = re.search(rf'name="{field_name}" value="([^"]+)"', html)
    assert match, f"Could not find hidden field {field_name}"
    return match.group(1)


def extract_secret(html: str) -> str:
    match = re.search(r"<code>([A-Z2-7]+)</code>", html)
    assert match, "Could not find MFA secret"
    return match.group(1)


def extract_backup_codes(html: str) -> list[str]:
    return re.findall(r"<code>([A-F0-9]{4}-[A-F0-9]{4})</code>", html)
