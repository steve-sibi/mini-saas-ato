from __future__ import annotations

import os
import sys
from typing import Any, Callable

import requests


BASE_URL = os.getenv("ATO_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("ATO_REQUEST_TIMEOUT_SECONDS", "10"))


def new_session(*, ip: str | None = None, device_entropy: str | None = None, **headers: str) -> requests.Session:
    session = requests.Session()
    if ip:
        session.headers["X-Forwarded-For"] = ip
    if device_entropy:
        session.headers["X-Device-Entropy"] = device_entropy
    session.headers.update(headers)
    return session


def bootstrap_csrf(session: requests.Session, path: str = "/auth/login") -> str:
    response = session.get(f"{BASE_URL}{path}", timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    token = session.cookies.get("ato_csrf")
    if not token:
        raise RuntimeError("Missing ato_csrf cookie")
    return token


def post_form(session: requests.Session, path: str, form_data: dict[str, Any], *, csrf_path: str = "/auth/login") -> requests.Response:
    csrf_token = bootstrap_csrf(session, csrf_path)
    payload = {"csrf_token": csrf_token, **form_data}
    response = session.post(
        f"{BASE_URL}{path}",
        data=payload,
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    return response


def get(session: requests.Session, path: str, *, allow_redirects: bool = True) -> requests.Response:
    return session.get(
        f"{BASE_URL}{path}",
        allow_redirects=allow_redirects,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def run_script(main: Callable[[], None], *, label: str) -> None:
    try:
        main()
    except KeyboardInterrupt:
        print(f"{label} interrupted by user.", file=sys.stderr)
        raise SystemExit(130) from None
    except requests.RequestException as exc:
        print(f"{label} request failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
