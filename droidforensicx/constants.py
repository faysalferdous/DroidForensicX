"""Shared constants for DroidForensicX."""

from __future__ import annotations

from pathlib import Path

CASE_DIRS = [
    "00_case",
    "01_raw_adb",
    "02_bugreport",
    "03_androidqf",
    "04_mvt",
    "05_aleapp",
    "06_apps",
    "07_media",
    "08_credentials_sensitive",
    "09_credentials_redacted",
    "10_social_imports",
    "11_indicators",
    "12_timeline",
    "13_hashes",
    "14_reports",
]

DEFAULT_CASES_ROOT = Path("cases")

SECRET_KEYS = ("password", "passwd", "pwd", "token", "api_key", "apikey", "secret")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

SUSPICIOUS_APP_KEYWORDS = (
    "tor",
    "vpn",
    "proxy",
    "vault",
    "calculator",
    "hide",
    "secret",
    "locker",
    "clone",
)

LIMITATIONS = [
    "DroidForensicX performs authorized logical triage only and does not bypass Android security controls.",
    "No-root ADB cannot access most app-private databases or guarantee complete deleted-file recovery.",
    "Android does not guarantee a permanent uninstall history; uninstalled app results are confidence-scored traces.",
    "Credential handling imports lawful official exports only and redacts password values by default.",
    "Absence of evidence in this report is not evidence of absence.",
]

