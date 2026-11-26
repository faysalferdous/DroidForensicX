"""Analysis modules."""

from __future__ import annotations

import csv
import os
from datetime import UTC, datetime
from html import escape
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .case import CaseContext
from .constants import DANGEROUS_PERMISSIONS, LIMITATIONS, SUSPICIOUS_APP_KEYWORDS
from .parsers import parse_dumpsys_package, parse_logcat_package_events, parse_pm_packages, parse_usage_stats
from .utils import read_csv, read_text, redact_mapping, sha256_file, write_csv, write_json


def app_inventory(ctx: CaseContext) -> dict[str, Any]:
    raw = ctx.subdir("01_raw_adb")
    apps, perms = parse_dumpsys_package(read_text(raw / "dumpsys_package.txt"))
    pm_apps = parse_pm_packages(read_text(raw / "pm_list_packages.txt"))
    if not apps:
        apps = [{"package": row["package"], "source_path": row.get("source_path", ""), "installer": "", "first_install_time": "", "last_update_time": "", "version_name": ""} for row in pm_apps]
    dangerous = [row for row in perms if row.get("permission") in DANGEROUS_PERMISSIONS]
    out = ctx.subdir("06_apps")
    write_csv(out / "apps_current.csv", apps)
    write_csv(out / "apps_permissions.csv", perms, ["package", "permission"])
    write_csv(out / "apps_dangerous_permissions.csv", dangerous, ["package", "permission"])
    summary = {"apps_count": len(apps), "permissions_count": len(perms), "dangerous_permissions_count": len(dangerous)}
    write_json(out / "apps_summary.json", summary)
    return summary


def app_lifecycle(ctx: CaseContext) -> dict[str, Any]:
    raw = ctx.subdir("01_raw_adb")
    current = {row["package"] for row in parse_pm_packages(read_text(raw / "pm_list_packages.txt"))}
    historical = {row["package"] for row in parse_pm_packages(read_text(raw / "pm_list_packages_u.txt"))}
    dumpsys_apps, _ = parse_dumpsys_package(read_text(raw / "dumpsys_package.txt"))
    dumpsys_pkgs = {row["package"] for row in dumpsys_apps}
    usage_events = parse_usage_stats(read_text(raw / "dumpsys_usagestats.txt"))
    log_events = parse_logcat_package_events(read_text(raw / "logcat_d.txt"))
    trace_pkgs = {row["package"] for row in usage_events + log_events if row.get("package")}
    packages = sorted(current | historical | dumpsys_pkgs | trace_pkgs)
    rows: list[dict[str, str]] = []
    timeline: list[dict[str, str]] = []
    for package in packages:
        evidence = []
        if package in current or package in dumpsys_pkgs:
            confidence = "CONFIRMED_INSTALLED"
            evidence.append("current package/dumpsys package")
        elif package in historical:
            confidence = "CONFIRMED_UNINSTALLED_TRACE"
            evidence.append("pm list packages -u trace")
        elif package in trace_pkgs:
            confidence = "POSSIBLE_PREVIOUSLY_INSTALLED"
            evidence.append("usage/logcat trace")
        else:
            confidence = "WEAK_TRACE_ONLY"
        rows.append({"package": package, "confidence": confidence, "evidence": "; ".join(evidence)})
    for event in usage_events + log_events:
        timeline.append({"timestamp": event.get("timestamp", ""), "package": event.get("package", ""), "event_type": event.get("event_type", ""), "source": event.get("source", "")})
    uninstalled = [row for row in rows if row["confidence"] in {"CONFIRMED_UNINSTALLED_TRACE", "POSSIBLE_PREVIOUSLY_INSTALLED", "WEAK_TRACE_ONLY"}]
    out = ctx.subdir("06_apps")
    write_csv(out / "apps_lifecycle.csv", rows, ["package", "confidence", "evidence"])
    write_csv(out / "apps_uninstalled_candidates.csv", uninstalled, ["package", "confidence", "evidence"])
    write_csv(out / "apps_lifecycle_timeline.csv", timeline, ["timestamp", "package", "event_type", "source"])
    summary = {"packages_evaluated": len(rows), "uninstalled_candidates": len(uninstalled), "limitation": LIMITATIONS[2]}
    write_json(out / "apps_lifecycle_summary.json", summary)
    return summary


def import_credentials(ctx: CaseContext, csv_path: Path) -> dict[str, Any]:
    sensitive = ctx.subdir("08_credentials_sensitive")
    redacted_dir = ctx.subdir("09_credentials_redacted")
    sensitive.mkdir(parents=True, exist_ok=True)
    redacted_dir.mkdir(parents=True, exist_ok=True)
    stored = sensitive / csv_path.name
    if csv_path.is_symlink() or stored.is_symlink() or not csv_path.is_file():
        raise ValueError("Use a regular credential export without symlinks")
    if os.name == "posix":
        ctx.root.chmod(0o700)
        sensitive.chmod(0o700)
    if csv_path.resolve() != stored.resolve():
        if stored.exists() and sha256_file(stored) != sha256_file(csv_path):
            raise FileExistsError("A different credential export already has this name")
        if not stored.exists():
            with csv_path.open("rb") as source, stored.open("xb") as destination:
                if os.name == "posix":
                    os.fchmod(destination.fileno(), 0o600)
                shutil.copyfileobj(source, destination)
    if os.name == "posix":
        stored.chmod(0o600)
    rows = read_csv(stored)
    normalized: list[dict[str, str]] = []
    passwords: dict[str, list[str]] = defaultdict(list)
    domains = Counter()
    usernames = Counter()
    weak_rows: list[dict[str, str]] = []
    sensitive_domains: list[dict[str, str]] = []
    goals: list[dict[str, str]] = []
    sensitive_terms = ("bank", "mail", "gov", "cloud", "admin", "wallet", "crypto")
    for i, row in enumerate(rows, start=1):
        lowered = {key.lower().strip(): value or "" for key, value in row.items() if key is not None}
        url = lowered.get("url") or lowered.get("origin") or lowered.get("website") or lowered.get("hostname") or ""
        username = lowered.get("username") or lowered.get("login") or lowered.get("email") or ""
        password = lowered.get("password") or lowered.get("passwd") or lowered.get("pwd") or ""
        domain = re.sub(r"^https?://", "", url).split("/")[0].lower()
        redacted = redact_mapping({"row": i, "url": url, "domain": domain, "username": username, "password": password})
        normalized.append(redacted)  # type: ignore[arg-type]
        if domain:
            domains[domain] += 1
        if username:
            usernames[username] += 1
        if password:
            passwords[password].append(str(i))
            reasons = []
            if len(password) < 10:
                reasons.append("short_password")
            if password.lower() in {"password", "passw0rd", "qwerty", "admin"}:
                reasons.append("common_password")
            if reasons:
                weak_rows.append({"row": str(i), "domain": domain, "username": username, "indicators": ";".join(reasons), "password": "********"})
        if any(term in domain for term in sensitive_terms):
            sensitive_domains.append({"domain": domain, "category": "sensitive_keyword", "password": "********"})
        if any(term in (domain + " " + username).lower() for term in ("job", "visa", "travel", "exam", "admin", "cloud")):
            goals.append({"domain": domain, "username": username, "indicator": "possible user goal/intent keyword"})
    reuse_rows = [
        {"reuse_group": f"reuse_{idx}", "rows": ",".join(indices), "count": len(indices), "password": "********"}
        for idx, indices in enumerate(passwords.values(), start=1)
        if len(indices) > 1
    ]
    write_csv(redacted_dir / "credentials_redacted.csv", normalized, ["row", "url", "domain", "username", "password"])
    write_csv(redacted_dir / "credential_domains.csv", [{"domain": k, "count": v} for k, v in domains.most_common()], ["domain", "count"])
    write_csv(redacted_dir / "credential_usernames.csv", [{"username": k, "count": v} for k, v in usernames.most_common()], ["username", "count"])
    write_csv(redacted_dir / "credential_reuse_groups.csv", reuse_rows, ["reuse_group", "rows", "count", "password"])
    write_csv(redacted_dir / "credential_weak_password_indicators.csv", weak_rows, ["row", "domain", "username", "indicators", "password"])
    write_csv(redacted_dir / "credential_sensitive_domains.csv", sensitive_domains, ["domain", "category", "password"])
    write_csv(redacted_dir / "credential_goal_indicators.csv", goals, ["domain", "username", "indicator"])
    summary = {
        "source_file": str(stored),
        "source_sha256": sha256_file(stored),
        "records": len(rows),
        "domains": len(domains),
        "reuse_groups": len(reuse_rows),
        "weak_password_indicators": len(weak_rows),
        "raw_passwords_reported": False,
    }
    write_json(redacted_dir / "credential_risk_summary.json", summary)
    return summary


def indicators(ctx: CaseContext) -> dict[str, Any]:
    raw = ctx.subdir("01_raw_adb")
    settings_global = read_text(raw / "settings_global.txt")
    settings_secure = read_text(raw / "settings_secure.txt")
    apps = read_csv(ctx.file("06_apps", "apps_current.csv")) if ctx.file("06_apps", "apps_current.csv").exists() else []
    dangerous = read_csv(ctx.file("06_apps", "apps_dangerous_permissions.csv")) if ctx.file("06_apps", "apps_dangerous_permissions.csv").exists() else []
    lifecycle = read_csv(ctx.file("06_apps", "apps_uninstalled_candidates.csv")) if ctx.file("06_apps", "apps_uninstalled_candidates.csv").exists() else []
    findings: list[dict[str, Any]] = []
    def add(indicator: str, severity: str, evidence: str, score: int) -> None:
        findings.append({"indicator": indicator, "severity": severity, "evidence": evidence, "score": score})
    if re.search(r"adb[_\.]tcp.*(?:5555|1)|service\.adb\.tcp\.port.*5555", settings_global, re.I):
        add("ADB over TCP indicator", "HIGH", "settings_global contains adb tcp references", 30)
    if re.search(r"development_settings_enabled=1|adb_enabled=1", settings_global + "\n" + settings_secure, re.I):
        add("Developer options or ADB enabled", "MEDIUM", "settings indicate development/ADB enabled", 15)
    for app in apps:
        package = app.get("package", "")
        installer = app.get("installer", "")
        if installer and installer not in {"com.android.vending", "com.google.android.packageinstaller", "com.android.packageinstaller"}:
            add("Unknown/non-store installer", "MEDIUM", f"{package} installer={installer}", 10)
        if any(keyword in package.lower() for keyword in SUSPICIOUS_APP_KEYWORDS):
            add("Suspicious app naming keyword", "MEDIUM", package, 10)
    danger_count = Counter(row["package"] for row in dangerous)
    for package, count in danger_count.items():
        if count >= 3:
            add("Multiple dangerous permissions", "MEDIUM", f"{package} dangerous_permissions={count}", min(20, count * 3))
    for row in lifecycle[:20]:
        add("Recently installed/removed app trace candidate", "LOW", f"{row.get('package')} {row.get('confidence')}", 5)
    out = ctx.subdir("11_indicators")
    write_csv(out / "suspicious_indicators.csv", findings, ["indicator", "severity", "evidence", "score"])
    app_scores: dict[str, int] = defaultdict(int)
    for finding in findings:
        for app in re.findall(r"[A-Za-z0-9_]+\.[A-Za-z0-9_.]+", str(finding["evidence"])):
            app_scores[app] += int(finding["score"])
    write_json(out / "app_risk_score.json", app_scores)
    summary = {"indicator_count": len(findings), "total_score": sum(int(f["score"]) for f in findings), "risk_level": "HIGH" if sum(int(f["score"]) for f in findings) >= 60 else "MEDIUM" if findings else "LOW"}
    write_json(out / "risk_summary.json", summary)
    return summary


def timeline_sort_key(value: str) -> tuple[int, float, str]:
    """Only compare known UTC/offset timestamps; retain uncertain dates as raw text."""
    raw = str(value).strip()
    try:
        if re.fullmatch(r"\d{10}(?:\.\d+)?", raw):
            return (0, float(raw), "")
        if re.fullmatch(r"\d{13}", raw):
            return (0, int(raw) / 1000, "")
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return (0, parsed.astimezone(UTC).timestamp(), "")
    except (ValueError, OverflowError, OSError):
        pass
    return (1, 0.0, raw)


def build_timeline(ctx: CaseContext) -> dict[str, Any]:
    events: list[dict[str, str]] = []
    for path, source in (
        (ctx.file("06_apps", "apps_lifecycle_timeline.csv"), "app_lifecycle"),
        (ctx.file("07_media", "media_timeline.csv"), "media"),
        (ctx.file("10_social_imports", "chat_timeline.csv"), "social"),
    ):
        if path.exists():
            for row in read_csv(path):
                events.append({"timestamp": row.get("timestamp", ""), "source": source, "event_type": row.get("event_type", row.get("type", "")), "artifact": row.get("package", row.get("path", "")), "details": str(row)})
    cred_domains = ctx.file("09_credentials_redacted", "credential_domains.csv")
    if cred_domains.exists():
        for row in read_csv(cred_domains):
            events.append({"timestamp": "", "source": "credentials_import", "event_type": "credential_domain_present", "artifact": row.get("domain", ""), "details": "redacted credential export domain"})
    events.sort(key=lambda row: timeline_sort_key(row.get("timestamp", "")))
    out = ctx.subdir("12_timeline")
    write_csv(out / "timeline.csv", events, ["timestamp", "source", "event_type", "artifact", "details"])
    md = "# Unified Timeline\n\n" + "\n".join(f"- `{e['timestamp']}` **{e['source']}** {e['event_type']} {e['artifact']}" for e in events[:500]) + "\n"
    (out / "timeline.md").write_text(md, encoding="utf-8")
    html = "<html><body><h1>Unified Timeline</h1><table><tr><th>Time</th><th>Source</th><th>Event</th><th>Artifact</th></tr>" + "".join(
        "<tr>" + "".join(f"<td>{escape(str(e[key]))}</td>" for key in ("timestamp", "source", "event_type", "artifact")) + "</tr>" for e in events[:1000]
    ) + "</table></body></html>"
    (out / "timeline.html").write_text(html, encoding="utf-8")
    summary = {"timeline_events": len(events)}
    write_json(out / "timeline_summary.json", summary)
    return summary


def hash_case(ctx: CaseContext) -> dict[str, Any]:
    hashes_dir = ctx.subdir("13_hashes")
    hashes_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(ctx.root.rglob("*")):
        if path.is_file() and not path.is_symlink() and "13_hashes" not in path.relative_to(ctx.root).parts:
            rows.append({"sha256": sha256_file(path), "path": str(path.relative_to(ctx.root)), "size": path.stat().st_size})
    (hashes_dir / "SHA256SUMS.txt").write_text("\n".join(f"{row['sha256']}  {row['path']}" for row in rows) + "\n", encoding="utf-8")
    write_json(hashes_dir / "evidence_manifest.json", {"case_id": ctx.case_id, "files": rows})
    (hashes_dir / "hash_verify.txt").write_text(f"Hashed files: {len(rows)}\nVerification: recompute SHA256 for listed paths.\n", encoding="utf-8")
    return {"hashed_files": len(rows)}
