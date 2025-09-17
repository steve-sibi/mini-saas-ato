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