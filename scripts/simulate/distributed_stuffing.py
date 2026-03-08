from __future__ import annotations

from scripts.simulate.common import BASE_URL, new_session, post_form


def main() -> None:
    target_email = "target@example.com"
    for index in range(8):
        attacker = new_session(
            ip=f"198.51.100.{50 + index}",
            device_entropy=f"botnet-node-{index}",
        )
        post_form(
            attacker,
            "/auth/login",
            {
                "email": target_email,
                "password": "bad-password",
                "cf-turnstile-response": "dev-bypass",
            },
        )
    print(f"Sent distributed stuffing attempts against {target_email} at {BASE_URL}.")


if __name__ == "__main__":
    main()
