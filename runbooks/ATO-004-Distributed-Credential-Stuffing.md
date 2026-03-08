# ATO-004: Distributed Credential Stuffing

**ATT&CK:** `T1110.004`

**Trigger:** One account received at least 8 failed logins from 5 or more source IPs inside 15 minutes.

**Immediate action:** Keep the account in challenge mode and review whether any later success events occurred from a related IP range.

**Containment:** Maintain the `challenge_rules(scope='account')` record, require step-up on the next successful login, and notify the affected user if appropriate.

**Follow-up:** Review bot fingerprints, provider ASN distribution, and whether similar accounts are under active attack.
