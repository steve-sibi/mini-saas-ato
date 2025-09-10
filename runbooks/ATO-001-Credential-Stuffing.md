# ATO-001: Credential Stuffing

**Trigger:** High failure volume from a single IP across many users in 5m.
**Immediate:** Block IP (temp), enable CAPTCHA, notify on-call.
**Investigate:** Targeted users, any successful logins, ASN reputation.
**Contain:** Force reset for impacted users; revoke sessions.
**Improve:** Tune per-IP/username rate limits; add honeypot usernames.
