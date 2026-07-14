# Setup

DroidForensicX was created by Faysal Ferdous for authorized Android forensic triage workflows.

## Debian, Kali, Parrot

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip android-sdk-platform-tools exiftool mediainfo testdisk
```

If system packages are unavailable, install Android platform-tools from Google and add `adb` to `PATH`.

## DroidForensicX

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

## Optional Tools

- AndroidQF: install from its official repository and ensure `androidqf` is in `PATH`.
- MVT: install with `pipx install mvt` or a dedicated virtual environment, then verify `mvt-android`.
- ALEAPP: clone its official repository and run separately or integrate generated outputs into case notes.
- `exiftool`, `mediainfo`, `photorec/testdisk`: install from distro packages where authorized.
