from __future__ import annotations

import json
from pathlib import Path

from droidforensicx.analysis import app_inventory, app_lifecycle, build_timeline, hash_case, import_credentials
from droidforensicx.case import create_case
from droidforensicx.parsers import parse_adb_devices, parse_dumpsys_package, parse_pm_packages
from droidforensicx.reporting import generate_report


FIXTURES = Path(__file__).parent / "fixtures"


def test_case_folder_creation(tmp_path: Path) -> None:
    ctx = create_case("CASE-1", "Tester", tmp_path)
    assert ctx.file("00_case", "case_manifest.json").exists()
    assert ctx.subdir("14_reports").exists()


def test_adb_devices_parser() -> None:
    devices = parse_adb_devices((FIXTURES / "adb_devices.txt").read_text())
    assert len(devices) == 2
    assert devices[0].serial == "ABC123"
    assert devices[1].state == "unauthorized"


def test_package_parser() -> None:
    apps, permissions = parse_dumpsys_package((FIXTURES / "dumpsys_package.txt").read_text())
    assert {app["package"] for app in apps} == {"com.example.safe", "com.fake.calculator.vault"}
    assert {"package": "com.fake.calculator.vault", "permission": "android.permission.READ_SMS"} in permissions
    pm = parse_pm_packages("package:/data/app/base.apk=com.example.safe\n")
    assert pm[0]["package"] == "com.example.safe"


def test_app_lifecycle_confidence_logic(tmp_path: Path) -> None:
    ctx = create_case("CASE-LIFE", "Tester", tmp_path)
    raw = ctx.subdir("01_raw_adb")
    raw.joinpath("pm_list_packages.txt").write_text("package:/x=com.example.safe\n")
    raw.joinpath("pm_list_packages_u.txt").write_text("package:/x=com.example.safe\npackage:/x=com.removed.app\n")
    raw.joinpath("dumpsys_package.txt").write_text((FIXTURES / "dumpsys_package.txt").read_text())
    raw.joinpath("dumpsys_usagestats.txt").write_text("package=com.trace.only lastTimeUsed=2026-07-01T00:00:00Z\n")
    raw.joinpath("logcat_d.txt").write_text("")
    summary = app_lifecycle(ctx)
    rows = ctx.file("06_apps", "apps_lifecycle.csv").read_text()
    assert summary["uninstalled_candidates"] >= 2
    assert "CONFIRMED_UNINSTALLED_TRACE" in rows
    assert "POSSIBLE_PREVIOUSLY_INSTALLED" in rows


def test_credential_redaction_and_weak_detection(tmp_path: Path) -> None:
    ctx = create_case("CASE-CRED", "Tester", tmp_path)
    summary = import_credentials(ctx, FIXTURES / "credentials.csv")
    redacted = ctx.file("09_credentials_redacted", "credentials_redacted.csv").read_text()
    weak = ctx.file("09_credentials_redacted", "credential_weak_password_indicators.csv").read_text()
    assert summary["reuse_groups"] == 1
    assert "SyntheticReuseValue!" not in redacted
    assert "SyntheticReuseValue!" not in weak
    assert "********" in redacted


def test_timeline_hash_and_report_generation(tmp_path: Path) -> None:
    ctx = create_case("CASE-REPORT", "Tester", tmp_path)
    raw = ctx.subdir("01_raw_adb")
    raw.joinpath("pm_list_packages.txt").write_text("package:/x=com.example.safe\n")
    raw.joinpath("pm_list_packages_u.txt").write_text("package:/x=com.example.safe\n")
    raw.joinpath("dumpsys_package.txt").write_text((FIXTURES / "dumpsys_package.txt").read_text())
    raw.joinpath("dumpsys_usagestats.txt").write_text("package=com.example.safe lastTimeUsed=2026-07-01T00:00:00Z\n")
    raw.joinpath("logcat_d.txt").write_text("")
    app_inventory(ctx)
    app_lifecycle(ctx)
    build_timeline(ctx)
    hash_summary = hash_case(ctx)
    reports = generate_report(ctx)
    assert hash_summary["hashed_files"] > 0
    assert Path(reports["report_html"]).exists()
    assert "DroidForensicX" in Path(reports["report_md"]).read_text()
    manifest = json.loads(ctx.file("13_hashes", "evidence_manifest.json").read_text())
    assert manifest["files"]
