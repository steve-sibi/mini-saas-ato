# Mini ATO SaaS - Heroku + Datadog + Azure (end-to-end)

A compact, production-style lab that demonstrates **account takeover (ATO) detection and response**:

- **App**: Flask auth service (register/login, optional TOTP), Postgres (SQLAlchemy), Redis (Flask-Session), server-side device fingerprinting.
    
- **Telemetry**: Structured JSON logs, browser RUM, clean `service`/`env` tagging.
    
- **Detections-as-code**: Datadog log rules for **credential stuffing** and **session reuse** (cookie hijack), plus attack scripts to validate.
    
- **Auto-containment**: Datadog → Webhook → Azure Function (HMAC) → `/contain/revoke` to invalidate risky sessions.
    
- **Docs/Runbooks**: Playbooks and monitor JSON you can import directly.


# Architecture

```
Browser ──(login + RUM)──> Flask (Heroku)
   │                         │
   │      JSON logs          ├──> Heroku Logplex drain ──> Datadog Logs/Cloud SIEM
   └─────────────────────────┘
                                  /\                        │
                                  │  Alerts / Webhook       │
                                  └───── Datadog Monitors <─┘
                                                    │
                                           Azure Function (HMAC)
                                                    │
                                           POST /contain/revoke (Flask)
```

**Key signals**

- `evt`, `outcome`, `email`, `ip`, `usr`, `sid`, `device_hash`, `user-agent` (etc.)
    
- RUM events in **Digital Experience** for UI/behavioral context.

# Repo Layout

```
.
├─ app.py                # Flask app factory, session config, RUM env
├─ auth.py               # Blueprint: register/login/MFA, logging, contain/revoke
├─ db.py                 # SQLAlchemy engine/session
├─ models.py             # User model
├─ device.py             # device_hash() using CH/UA/IP + extra client hints
├─ templates/            # base.html, login.html, register.html, dashboard.html
├─ static/device.js      # lightweight client hints → hidden field
├─ scripts/attack/       # spray.py, session_reuse.py (simulations)
├─ datadog/monitors/     # stuffing.json, session_reuse.json (import into DD)
├─ runbooks/             # ATO-001/2/3.md (investigation & response steps)
├─ Procfile              # web: gunicorn app:app
├─ requirements.txt      # pins incl. bcrypt==3.2.2
├─ README.md             # README for project   
└─ runtime.txt           # python runtime for Heroku
```

# Prerequisites

- Python 3.11+ (local), or just deploy to Heroku.
    
- Datadog account (**us5**) with **DD API key**.
    
- (Optional) Azure Functions (HTTP trigger) if you want auto-containment.

# Quickstart (Local)

```
# 1) Create a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# 2) Install deps
pip install -r requirements.txt

# 3) Env vars (example)
export FLASK_SECRET=$(python -c 'import secrets; print(secrets.token_hex(16))')
export ATO_HMAC_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
# For local dev you can use sqlite + local redis:
export DATABASE_URL="sqlite:///dev.db"
export REDIS_URL="redis://localhost:6379/0"

# 4) Run
python app.py

# open http://localhost:8000
```

The app auto-creates tables via SQLAlchemy on first hit (or at startup depending on your version). If you use Postgres locally, set `DATABASE_URL=postgresql+psycopg2://...`.