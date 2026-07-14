"""Synthetic demo case generation."""

from __future__ import annotations

from pathlib import Path

from .analysis import app_inventory, app_lifecycle, build_timeline, hash_case, indicators, import_credentials
from .case import create_case
from .media import scan_media
from .reporting import generate_report
from .social import import_social
from .utils import write_json


def create_demo(case_id: str = "DEMO-ANDROID-FORENSIC") -> dict[str, str]:
    ctx = create_case(case_id, "Synthetic Demo Examiner")
    raw = ctx.subdir("01_raw_adb")
    raw.mkdir(parents=True, exist_ok=True)
    write_json(
        raw / "device_identity.json",
        {
            "ro.product.manufacturer": "Google",
            "ro.product.model": "Pixel Synthetic Demo",
            "ro.build.version.release": "16",
            "ro.build.fingerprint": "google/demo/demo:16/SYNTHETIC:user/release-keys",
        },
    )
    (raw / "pm_list_packages.txt").write_text(
        "\n".join(
            [
                "package:/data/app/com.android.chrome/base.apk=com.android.chrome",
                "package:/data/app/org.telegram.messenger/base.apk=org.telegram.messenger",
                "package:/data/app/com.fake.calculator.vault/base.apk=com.fake.calculator.vault",
                "package:/data/app/com.example.notes/base.apk=com.example.notes",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (raw / "pm_list_packages_u.txt").write_text(
        "\n".join(
            [
                "package:/data/app/com.android.chrome/base.apk=com.android.chrome",
                "package:/data/app/com.fake.calculator.vault/base.apk=com.fake.calculator.vault",
                "package:/data/app/com.shortlived.proxy/base.apk=com.shortlived.proxy",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (raw / "dumpsys_package.txt").write_text(
        """
Package [com.android.chrome] (abc):
  versionName=126.0
  firstInstallTime=2026-06-01 10:00:00
  lastUpdateTime=2026-07-01 10:00:00
  installerPackageName=com.android.vending
  requested permissions:
    android.permission.CAMERA
    android.permission.ACCESS_FINE_LOCATION
Package [com.fake.calculator.vault] (def):
  versionName=2.4
  firstInstallTime=2026-07-10 13:20:00
  lastUpdateTime=2026-07-10 13:20:00
  installerPackageName=unknown.installer
  requested permissions:
    android.permission.READ_SMS
    android.permission.READ_CONTACTS
    android.permission.SYSTEM_ALERT_WINDOW
    android.permission.CAMERA
""".strip(),
        encoding="utf-8",
    )
    (raw / "settings_global.txt").write_text("development_settings_enabled=1\nadb_enabled=1\nservice.adb.tcp.port=5555\n", encoding="utf-8")
    (raw / "settings_secure.txt").write_text("enabled_accessibility_services=com.fake.calculator.vault/.SpyService\n", encoding="utf-8")
    (raw / "dumpsys_usagestats.txt").write_text("package=com.shortlived.proxy lastTimeUsed=2026-07-12T10:20:00Z\n", encoding="utf-8")
    (raw / "logcat_d.txt").write_text("07-12 10:22:01.123  111 222 I PackageManager: PACKAGE_REMOVED com.shortlived.proxy\n", encoding="utf-8")
    demo_csv = ctx.subdir("08_credentials_sensitive") / "synthetic_credentials.csv"
    demo_csv.parent.mkdir(parents=True, exist_ok=True)
    demo_csv.write_text(
        "url,username,password\nhttps://mail.example.test,analyst@example.test,SyntheticReuseValue!\nhttps://cloud.example.test,analyst@example.test,SyntheticReuseValue!\nhttps://bank.example.test,user@example.test,SyntheticUniqueValue!\n",
        encoding="utf-8",
    )
    media_dir = ctx.subdir("07_media") / "synthetic_shared_storage"
    media_dir.mkdir(parents=True, exist_ok=True)
    (media_dir / "Download suspicious-vault.apk").write_text("synthetic apk placeholder\n", encoding="utf-8")
    (media_dir / "Documents case-notes.txt").write_text("synthetic document placeholder\n", encoding="utf-8")
    chat_export = ctx.subdir("10_social_imports") / "synthetic_whatsapp_export.txt"
    chat_export.parent.mkdir(parents=True, exist_ok=True)
    chat_export.write_text(
        "12/07/2026, 10:01 - Analyst Demo: Please send the report when ready\n12/07/2026, 10:05 - Contact Demo: The code is 867530\n",
        encoding="utf-8",
    )
    app_inventory(ctx)
    app_lifecycle(ctx)
    import_credentials(ctx, demo_csv)
    scan_media(ctx, media_dir)
    import_social(ctx, chat_export)
    indicators(ctx)
    build_timeline(ctx)
    hash_case(ctx)
    reports = generate_report(ctx)
    return reports
