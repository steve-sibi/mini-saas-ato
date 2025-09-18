# Mini ATO SaaS - Heroku + Datadog + Azure (end-to-end)

A compact, production-style lab that demonstrates **account takeover (ATO) detection and response**:

- **App**: Flask auth service (register/login, optional TOTP), Postgres (SQLAlchemy), Redis (Flask-Session), server-side device fingerprinting.
    
- **Telemetry**: Structured JSON logs, browser RUM, clean `service`/`env` tagging.
    
- **Detections-as-code**: Datadog log rules for **credential stuffing** and **session reuse** (cookie hijack), plus attack scripts to validate.
    
- **Auto-containment**: Datadog -> Webhook -> Azure Function (HMAC) -> `/contain/revoke` to invalidate risky sessions.
    
- **Docs/Runbooks**: Playbooks and monitor JSON you can import directly.


## Architecture

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

## Repo Layout

```
.
├─ app.py                # Flask app factory, session config, RUM env
├─ auth.py               # Blueprint: register/login/MFA, logging, contain/revoke
├─ db.py                 # SQLAlchemy engine/session
├─ models.py             # User model
├─ device.py             # device_hash() using CH/UA/IP + extra client hints
├─ templates/            # base.html, login.html, register.html, dashboard.html
├─ static/device.js      # lightweight client hints -> hidden field
├─ scripts/attack/       # spray.py, session_reuse.py (simulations)
├─ datadog/monitors/     # stuffing.json, session_reuse.json (import into DD)
├─ runbooks/             # ATO-001/2/3.md (investigation & response steps)
├─ Procfile              # web: gunicorn app:app
├─ requirements.txt      # pins incl. bcrypt==3.2.2
├─ README.md             # README for project   
└─ runtime.txt           # python runtime for Heroku
```

## Prerequisites

- Python 3.11+ (local), or just deploy to Heroku.
    
- Datadog account (**us5**) with **DD API key**.
    
- (Optional) Azure Functions (HTTP trigger) if you want auto-containment.

## Quickstart (Local)

```bash
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

## Deploy to Heroku (via GitHub, not Heroku Git)

1. **Create app** and connect your GitHub repo in the Heroku dashboard (Deploy tab).
    
2. **Add-ons**

```bash
heroku addons:create heroku-postgresql:essential-0 -a <APP>
heroku addons:create heroku-redis:mini -a <APP>    # or hobby/basic if needed
```

3. **Buildpacks (order matters)**

```
heroku buildpacks:clear -a <APP>
heroku buildpacks:add heroku/python -a <APP>
heroku buildpacks:add https://github.com/DataDog/heroku-buildpack-datadog -a <APP>
```

4. **Config vars**  
    Generate secrets locally, then set (adjust `DD_SITE` if not us5):

```bash
heroku config:set -a <APP> \
  FLASK_SECRET=$(python -c 'import secrets; print(secrets.token_hex(16))') \
  ATO_HMAC_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))') \
  DD_API_KEY=<YOUR_DD_API_KEY> \
  DD_SITE=us5.datadoghq.com \
  DD_SERVICE=mini-ato-saas \
  DD_ENV=prod
```
After scouring through documentation, I found out that Postgres/Redis URLs are injected automatically (`DATABASE_URL`, `REDIS_TLS_URL`/`REDIS_URL`).

5. **Datadog logs (Logplex drain)**  
Agent buildpack doesn’t collect router/app logs; add the HTTPS drain:

```bash
SERVICE=mini-ato-saas
heroku drains:add \
"https://http-intake.logs.us5.datadoghq.com/api/v2/logs?dd-api-key=$DD_API_KEY&ddsource=heroku&service=$SERVICE&ddtags=env:prod,service:$SERVICE,usecase:ato" \
 -a <APP>
```

6. **Deploy**  
From the Heroku dashboard -> Deploy tab -> **Deploy Branch**.

7. **Scale & Health**

```bash
heroku ps:scale web=1 -a <APP>
open https://<APP>.herokuapp.com/__health     # -> ok
```

## Datadog setup

### 1) RUM (Browser monitoring)

- In Datadog **Digital Experience -> RUM -> Applications**, create a Browser app (site **us5**).
    
- Copy **applicationId** and **clientToken**.
    
- Set on Heroku:

```bash
heroku config:set -a <APP> RUM_APP_ID=<appId> RUM_CLIENT_TOKEN=<clientToken>
```

- `templates/base.html` already loads the us5 CDN async snippet (copied from Datadog RUM) and initializes RUM using those env vars.

### 2) Parse app logs (JSON -> attributes)

- Go to **Logs -> Configuration -> Pipelines -> New**
    
    - Filter: `service:mini-ato-saas @syslog.appname:app`
        
    - Processor: **Parse -> JSON** (source **message**, merge into root)
        
    - (Optional) **Status remapper** from `level`.
        
- In **Logs -> Explorer**, filter `service:mini-ato-saas @syslog.appname:app` and confirm you see fields like `evt`, `outcome`, `email`, `ip`, `sid`, `device_hash`.
    
- (Optional) Promote facets for `evt`, `outcome`, `ip`, `sid`, `device_hash` (hover field -> gear -> **Create facet**).

### 3) Import detections (monitors)

Import JSON from `datadog/monitors/`:

- **Credential Stuffing** (`stuffing.json`)  
    Query (demo threshold):

```sql
logs('service:mini-ato-saas @syslog.appname:app evt:login AND outcome:fail')
  .index('main').rollup('count').by('@ip').over('last_5m') > 10
```
Set **critical=10** for demos (tune up later).

- **Session Reuse** (`session_reuse.json`)

```sql
logs('service:mini-ato-saas @syslog.appname:app evt:login AND outcome:success')   
    .rollup('cardinality','@device_hash').by('@usr','@sid').over('last_5m') > 1
```
> **Note:** The app logs include a stable `sid` on successful login. If you don’t see it, ensure `auth.py` sets `session["sid"] = secrets.token_hex(16)` and logs it.

### 4) (Optional) Cloud SIEM

Instead of Monitors, you can create **Security -> Cloud SIEM -> Detection Rules (Log)** with the same queries + MITRE metadata to emit **Security Signals**.

## Auto-containment (optional step but recommended)
This was more for my curiosity to understand the use of cloud services (such as Azure) to contain threats with the use of Webhooks.

1) **Azure Function** (HTTP trigger)
    
    - Reads JSON `{ "sid": "...", "usr": "...", "reason": "...", ... }`
        
    - Computes HMAC with `ATO_HMAC_SECRET`
        
    - POST to `https://<APP>.herokuapp.com/contain/revoke` with header `X-ATO-Signature: <hex>`
        
2) **Datadog Webhook**
    
    - **Integrations -> Webhooks**: name `ato-contain`, URL = your Function endpoint.
        
    - Set monitor message to include `@webhook-ato-contain`.
        
    - Example payload (Datadog -> Function):

    ```json
    {
        "sid": "${sid}",
        "usr": "${usr.name}",
        "ip": "${network.client.ip}",
        "reason": "${alert_title}",
        "monitor": "${monitor.name}"
    }
    ```

3) **Flask endpoint**  
`/contain/revoke` verifies HMAC, clears the session, logs `evt:contain action:revoke`.

## Attack Simulations (purple team)
Ran these attacks locally to the cloud instance on Heroku to generate signals:

```bash
# 1) Credential stuffing (30 bad logins) -> should exceed >10 in 5m
python scripts/attack/spray.py

# 2) Session reuse (cookie replay from another device) -> multiple device_hash per sid
python scripts/attack/session_reuse.py
```
Then check **Monitors** and **Logs -> Explorer** (group by `@ip`, `@sid`, `@device_hash`) and RUM sessions.

## Security notes & gotchas

- **Redis TLS**: Some Heroku Redis endpoints present a self-signed CA. The app appends `ssl_cert_reqs=none` to `rediss://` for my lab. For production, I'd suggest a proper CA bundle in an `ssl.SSLContext`.
    
- **bcrypt**: `passlib[bcrypt]==1.7.4` requires **bcrypt < 4**. `requirements.txt` pins `bcrypt==3.2.2`. (planning to update this in the future)
    
- **Heroku Postgres plan**: use `heroku-postgresql:essential-0` (the old `mini` plan is EOL - incase you haven't used Heroku in a while).
    
- **Procfile**: `web: gunicorn app:app` (ensure `gunicorn` is in `requirements.txt`).
    
- **RUM site**: set `DD_SITE=us5.datadoghq.com` to match your Datadog region. (us5 was the case for me, but it can be different for you, so always check this in your browser)
    
- **Facets (Datadog)**: creation isn’t retroactive, generate a few new events after adding these.
