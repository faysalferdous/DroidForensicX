#!/usr/bin/env bash
set -euo pipefail

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install --upgrade pip wheel
python -m pip install -e .
echo "Installed DroidForensicX. Run: . .venv/bin/activate && droidforensicx --help"
