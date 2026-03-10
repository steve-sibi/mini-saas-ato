from __future__ import annotations

import time

from scripts.simulate.common import BASE_URL, new_session, post_form, run_script


def main() -> None:
    email = f"traveler-{int(time.time())}@example.com"
    password = "P@ssw0rd!123"

    seed = new_session(
        ip="198.51.100.33",
        device_entropy="chicago-laptop",
        **{
            "X-Debug-Country": "US",
            "X-Debug-City": "Chicago",
            "X-Debug-Latitude": "41.8781",
            "X-Debug-Longitude": "-87.6298",
        },
    )
    post_form(seed, "/auth/register", {"email": email, "password": password}, csrf_path="/auth/register")
    post_form(seed, "/auth/login", {"email": email, "password": password, "cf-turnstile-response": "dev-bypass"})

    second = new_session(
        ip="203.0.113.88",
        device_entropy="tokyo-phone",
        **{
            "X-Debug-Country": "JP",
            "X-Debug-City": "Tokyo",
            "X-Debug-Latitude": "35.6764",
            "X-Debug-Longitude": "139.6500",
        },
    )
    response = post_form(
        second,
        "/auth/login",
        {"email": email, "password": password, "cf-turnstile-response": "dev-bypass"},
    )
    print(f"Second login status={response.status_code} against {BASE_URL}.")


if __name__ == "__main__":
    run_script(main, label="Impossible travel simulation")
