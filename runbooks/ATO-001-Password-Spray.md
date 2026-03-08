# ATO-001: Password Spray

**ATT&CK:** `T1110.003`

**Trigger:** One source IP generated at least 15 failed logins across 5 or more accounts inside 10 minutes.

**Immediate action:** Keep IP challenge mode enabled, review ASN reputation, and confirm whether successful logins followed the spray.

**Containment:** Keep the `challenge_rules(scope='ip')` record active for 15 minutes or extend it if the activity continues.

**Follow-up:** Add rate-limit tuning notes, identify targeted accounts, and decide whether IP blocking is warranted upstream.
