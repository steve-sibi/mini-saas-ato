# ATO-003: Impossible Travel

**ATT&CK:** `T1078`, `T1078.004`

**Trigger:** Two successful logins for the same account imply travel speed greater than 900 km/h within 6 hours and the device fingerprint changed.

**Immediate action:** Confirm the account is in step-up mode and that prior active sessions were revoked.

**Containment:** Require MFA on subsequent logins for 24 hours and review the before/after geolocation evidence with the linked auth events.

**Follow-up:** Decide whether the event was benign travel/VPN usage or valid-account abuse and document the rationale.
