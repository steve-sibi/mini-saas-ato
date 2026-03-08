# ATO Sentinel

ATO Sentinel is a resume-grade **Account Takeover detection platform** built as a single FastAPI app. It combines a user auth portal, an account security center, an analyst view, inline risk detections, and Datadog-ready telemetry.

## What the project does

- **User auth flows**: register, sign in, sign out, enable TOTP MFA, use single-use backup codes.
- **Real session control**: sessions are stored in Postgres with revocation by `sid`, device binding, expiry, and last-seen metadata.
- **Inline risk detections**:
  - `ATO-001` Password Spray (`T1110.003`)
  - `ATO-002` Session Cookie Reuse (`T1550.004`)
  - `ATO-003` Impossible Travel / Valid Accounts Abuse (`T1078`, `T1078.004`)
  - `ATO-004` Distributed Credential Stuffing (`T1110.004`)
- **Containment**:
  - IP or account challenge mode via `challenge_rules`
  - direct session revocation
  - account step-up enforcement for risky travel
- **Analyst workflow**: minimal detections list and detail view with linked auth events, containment actions, MITRE IDs, and runbooks.
- **Cloud-ready telemetry**: structured JSON logs to stdout, Datadog RUM support, and Datadog monitor JSON artifacts.

## Stack

- **Backend**: FastAPI, Jinja2, HTMX
- **Database**: Postgres, SQLAlchemy 2.0, Alembic
- **Security**: Argon2id, TOTP, backup codes, CSRF tokens, Turnstile challenge mode
- **Detection**: in-app risk logic with Datadog alerting/webhook integration
- **GeoIP**: MaxMind GeoLite2-City with graceful degradation when unavailable
- **Runtime**: Python `3.13`, `pyproject.toml`, `uv`

## Repo layout

```text
.
├── ato_sentinel/               # FastAPI app package
├── alembic/                    # Schema migrations
├── infra/datadog/monitors/     # Datadog monitor JSON
├── runbooks/                   # Detection runbooks
├── scripts/simulate/           # Demo attack simulations
├── static/                     # App JS + styles
├── templates/                  # Server-rendered UI
├── tests/                      # Pytest suite
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── Procfile
└── pyproject.toml
```

## Local development

Recommended workflow: **hybrid local dev**.

- Run Postgres in Docker for parity.
- Run the FastAPI app on the host with auto-reload for the inner loop.

### 1. Prerequisites

- Python `3.13`
- `uv`
- Docker Desktop or a Docker-compatible engine

If `uv` is not installed yet:

```bash
python3 -m pip install uv
```

### 2. Start Postgres

```bash
docker compose up db
```

### 3. Create an environment file

```bash
cp .env.example .env
```

The default `DATABASE_URL` already points at the Compose Postgres instance.

### 4. Install dependencies and migrate

```bash
uv sync
uv run alembic upgrade head
```

### 5. Run the app

```bash
uv run uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Open `http://127.0.0.1:8000`.

### Full-stack Docker path

If you want the zero-setup path instead of the hybrid workflow:

```bash
docker compose up --build
```

## GeoIP setup

GeoIP enrichment is optional. The app still runs without it.

- If `GEOIP_DB_PATH` exists, the app uses it.
- Else, if `MAXMIND_LICENSE_KEY` is set, the app downloads GeoLite2-City into `/tmp` at startup.
- Else, impossible-travel analytics degrade gracefully and the rest of the app still works.

To fetch the database locally:

```bash
export MAXMIND_LICENSE_KEY=...
make geoip
```

## Running tests

```bash
uv run pytest
```

The tests use a SQLite database file created inside the test temp directory.

## Demo simulations

All simulation scripts assume the app is reachable at `http://127.0.0.1:8000`. Override with `ATO_BASE_URL` if needed.

```bash
uv run python scripts/simulate/password_spray.py
uv run python scripts/simulate/distributed_stuffing.py
uv run python scripts/simulate/session_cookie_reuse.py
uv run python scripts/simulate/impossible_travel.py
```

Notes:

- The simulation scripts use `X-Forwarded-For` and `X-Device-Entropy` so they can exercise the detection logic without a browser.
- The impossible-travel simulation uses debug geo headers, which are enabled only outside production.

## Datadog integration

### Logs

The app emits structured JSON to stdout. Parse fields like:

- `event_type`
- `outcome`
- `email`
- `session_id`
- `source_ip`
- `device_fingerprint`
- `risk_flags`
- `risk_score`

### RUM

Set:

- `RUM_APP_ID`
- `RUM_CLIENT_TOKEN`
- `DD_SITE`
- `DD_SERVICE`
- `DD_ENV`

### Monitors

Import monitor JSON from `infra/datadog/monitors/`:

- `stuffing.json`
- `session_reuse.json`
- `impossible_travel.json`
- `distributed_stuffing.json`

### Webhook containment

The internal webhook endpoint is:

```text
POST /internal/datadog/contain
```

Two auth modes are implemented:

- **Preferred**: HMAC headers
  - `X-ATO-Timestamp`
  - `X-ATO-Signature = hex(hmac_sha256(secret, timestamp + "." + raw_body))`
- **Datadog-compatible fallback**: static header
  - `X-ATO-Webhook-Token`

The fallback exists because Datadog custom webhooks support custom headers and payloads, but not arbitrary body HMAC signing. The app accepts both so the project is directly deployable without a relay service.

Expected JSON payload:

```json
{
  "alert_id": "unique-alert-id",
  "detection_type": "ATO-001",
  "entity_type": "ip",
  "entity_value": "198.51.100.17",
  "occurred_at": "2026-03-08T12:00:00+00:00",
  "monitor_name": "ATO-001 Password Spray"
}
```

`alert_id` is treated idempotently.

## Heroku deployment

### Runtime

- Use **Heroku Cedar-generation apps** on `heroku-24`
- Use **Heroku Postgres Essential-0**
- Set the Python runtime through `.python-version`

### Procfile

This repo uses:

```text
release: uv run alembic upgrade head
web: uv run uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
```

### Required config vars

```text
DATABASE_URL
APP_SECRET_KEY
CSRF_SECRET_KEY
DATADOG_WEBHOOK_SECRET
TURNSTILE_SITE_KEY
TURNSTILE_SECRET_KEY
DD_SITE
DD_SERVICE
DD_ENV
RUM_APP_ID
RUM_CLIENT_TOKEN
GEOIP_DB_PATH
MAXMIND_LICENSE_KEY
```

### Recommended extras

- Datadog HTTP log drain
- Cloudflare Turnstile site + secret keys

## MITRE ATT&CK mapping

| Detection | ATT&CK |
| --- | --- |
| ATO-001 Password Spray | `T1110.003` |
| ATO-002 Session Cookie Reuse | `T1550.004` |
| ATO-003 Impossible Travel / Valid Accounts Abuse | `T1078`, `T1078.004` |
| ATO-004 Distributed Credential Stuffing | `T1110.004` |

## Current implementation notes

- Analyst routes are intentionally minimal in v1: list view plus detail view.
- GeoIP is optional and degrades cleanly when not configured.
- Turnstile bypasses to `dev-bypass` when no secret key is configured, which keeps local development friction low.
- The legacy `scripts/attack/` directory is still present for reference, but the supported demo scripts live in `scripts/simulate/`.
