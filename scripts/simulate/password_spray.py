from __future__ import annotations

from scripts.simulate.common import BASE_URL, new_session, post_form, run_script


def main() -> None:
    attacker = new_session(ip="198.51.100.17", device_entropy="sprayer-laptop")
    for index in range(20):
        email = f"victim{index}@example.com"
        post_form(
            attacker,
            "/auth/login",
            {
                "email": email,
                "password": "wrong-password",
                "cf-turnstile-response": "dev-bypass",
            },
        )
    print(f"Sent 20 failed login attempts to {BASE_URL} from one IP.")


if __name__ == "__main__":
    run_script(main, label="Password spray simulation")
