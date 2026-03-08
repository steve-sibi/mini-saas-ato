from __future__ import annotations

import os
from typing import Any

import requests


BASE_URL = os.getenv("ATO_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def new_session(*, ip: str | None = None, device_entropy: str | None = None, **headers: str) -> requests.Session:
    session = requests.Session()
    if ip:
        session.headers["X-Forwarded-For"] = ip
    if device_entropy:
        session.headers["X-Device-Entropy"] = device_entropy
    session.headers.update(headers)
    return session


def bootstrap_csrf(session: requests.Session, path: str = "/auth/login") -> str:
    response = session.get(f"{BASE_URL}{path}")
    response.raise_for_status()
    token = session.cookies.get("ato_csrf")
    if not token:
        raise RuntimeError("Missing ato_csrf cookie")
    return token


def post_form(session: requests.Session, path: str, form_data: dict[str, Any], *, csrf_path: str = "/auth/login") -> requests.Response:
    csrf_token = bootstrap_csrf(session, csrf_path)
    payload = {"csrf_token": csrf_token, **form_data}
    response = session.post(f"{BASE_URL}{path}", data=payload, allow_redirects=False)
    return response
