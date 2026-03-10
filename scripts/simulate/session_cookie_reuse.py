from __future__ import annotations

import time

from scripts.simulate.common import new_session, get, post_form, run_script


def main() -> None:
    email = f"cookie-{int(time.time())}@example.com"
    password = "P@ssw0rd!123"

    legit = new_session(ip="203.0.113.21", device_entropy="trusted-laptop")
    post_form(legit, "/auth/register", {"email": email, "password": password}, csrf_path="/auth/register")
    login_response = post_form(
        legit,
        "/auth/login",
        {"email": email, "password": password, "cf-turnstile-response": "dev-bypass"},
    )
    if login_response.status_code != 303:
        raise RuntimeError(f"Unexpected login status: {login_response.status_code}")

    sid = legit.cookies.get("ato_sid")
    if not sid:
        raise RuntimeError("Expected ato_sid cookie after login")

    attacker = new_session(
        ip="203.0.113.77",
        device_entropy="attacker-handset",
    )
    attacker.cookies.set("ato_sid", sid)
    security_page = get(attacker, "/account/security", allow_redirects=False)
    print(f"Session reuse status={security_page.status_code} location={security_page.headers.get('location')}")


if __name__ == "__main__":
    run_script(main, label="Session cookie reuse simulation")
