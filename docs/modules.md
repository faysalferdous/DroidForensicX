# Modules

- `init`: creates case folders, manifest, notes, and chain-of-custody starter.
- `check-device`: checks optional tools, `adb devices -l`, and authorization status.
- `acquire-basic`: runs safe ADB read-only commands and stores raw outputs.
- `bugreport`: runs `adb bugreport` when available.
- `androidqf`: runs AndroidQF when installed.
- `mvt`: runs `mvt-android check-androidqf` and `check-bugreport` when inputs exist.
- `app-inventory`: parses package and permission data.
- `app-lifecycle`: confidence-scores installed and uninstalled app traces.
- `media-scan`: indexes lawful shared-storage or imported media.
- `credential-import`: imports official credential CSV exports with password redaction.
- `social-import`: imports lawful chat/browser/social exports.
- `indicators`: generates suspicious indicators and risk score.
- `timeline`: creates unified CSV, Markdown, and HTML timelines.
- `hash`: creates SHA256 manifest.
- `report`: creates Markdown, HTML, and executive summary reports.
- `defence-full`: runs the main workflow gracefully.
- `demo`: creates a synthetic demo case without a real phone.

