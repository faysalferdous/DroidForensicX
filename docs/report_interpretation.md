# Report Interpretation

## Confidence Levels

- `CONFIRMED_INSTALLED`: observed in current package or `dumpsys package` data.
- `CONFIRMED_UNINSTALLED_TRACE`: observed in `pm list packages -u` or strong historical trace.
- `POSSIBLE_PREVIOUSLY_INSTALLED`: observed in usage/logcat/bugreport traces but not current packages.
- `WEAK_TRACE_ONLY`: weak artifact name or low-context trace only.
- `NO_EVIDENCE`: no supporting trace.

## Risk Levels

Risk score is triage guidance, not a final finding. Review each indicator and source evidence before drawing conclusions.

## Credential Evidence

Credential rows come only from lawful imports. Password values are redacted as `********`. Reuse and weak-password indicators are computed internally without printing raw passwords.

