# ATO-002: Session Cookie Reuse

**ATT&CK:** `T1550.004`

**Trigger:** An authenticated request presented a valid `sid` from a materially different device fingerprint.

**Immediate action:** Confirm the session is revoked and force a fresh sign-in.

**Containment:** Review linked `containment_actions` for `revoke_session`, then inspect any neighboring auth events for phishing or token theft indicators.

**Follow-up:** Determine whether the account also needs step-up enforcement or password reset guidance.
