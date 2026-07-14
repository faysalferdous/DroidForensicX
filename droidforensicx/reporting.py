"""Report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .case import CaseContext
from .constants import LIMITATIONS
from .external import detect_tools
from .utils import read_csv, read_text, write_json


def _json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _csv(path: Path, limit: int = 100) -> list[dict[str, str]]:
    return read_csv(path)[:limit] if path.exists() else []


def build_report_context(ctx: CaseContext) -> dict[str, Any]:
    manifest = _json(ctx.file("00_case", "case_manifest.json"))
    apps = _csv(ctx.file("06_apps", "apps_current.csv"), 200)
    uninstalled = _csv(ctx.file("06_apps", "apps_uninstalled_candidates.csv"), 200)
    dangerous = _csv(ctx.file("06_apps", "apps_dangerous_permissions.csv"), 200)
    indicators = _csv(ctx.file("11_indicators", "suspicious_indicators.csv"), 200)
    credentials = _csv(ctx.file("09_credentials_redacted", "credentials_redacted.csv"), 50)
    timeline = _csv(ctx.file("12_timeline", "timeline.csv"), 200)
    hash_manifest = _json(ctx.file("13_hashes", "evidence_manifest.json"))
    return {
        "case_id": ctx.case_id,
        "tool_version": __version__,
        "manifest": manifest,
        "tools": detect_tools(),
        "device_props": _json(ctx.file("01_raw_adb", "device_identity.json")),
        "apps_summary": _json(ctx.file("06_apps", "apps_summary.json")),
        "lifecycle_summary": _json(ctx.file("06_apps", "apps_lifecycle_summary.json")),
        "risk_summary": _json(ctx.file("11_indicators", "risk_summary.json")),
        "credential_summary": _json(ctx.file("09_credentials_redacted", "credential_risk_summary.json")),
        "social_summary": _json(ctx.file("10_social_imports", "social_report.json")),
        "media_summary": _json(ctx.file("07_media", "media_summary.json")),
        "hash_manifest": hash_manifest,
        "apps": apps,
        "uninstalled": uninstalled,
        "dangerous": dangerous,
        "indicators": indicators,
        "credentials": credentials,
        "timeline": timeline,
        "metrics": {
            "apps": len(apps),
            "uninstalled": len(uninstalled),
            "dangerous_permissions": len(dangerous),
            "indicators": len(indicators),
            "credentials": len(credentials),
            "timeline": len(timeline),
            "hashed_files": len(hash_manifest.get("files", [])) if isinstance(hash_manifest, dict) else 0,
        },
        "limitations": LIMITATIONS,
        "hashes_text": read_text(ctx.file("13_hashes", "SHA256SUMS.txt"))[:20000],
    }


def generate_report(ctx: CaseContext) -> dict[str, str]:
    out = ctx.subdir("14_reports")
    out.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    context = build_report_context(ctx)
    md = env.get_template("report.md.j2").render(**context)
    html = env.get_template("report.html.j2").render(**context)
    executive = env.get_template("executive_summary.md.j2").render(**context)
    (out / "report.md").write_text(md, encoding="utf-8")
    (out / "report.html").write_text(html, encoding="utf-8")
    (out / "executive_summary.md").write_text(executive, encoding="utf-8")
    write_json(out / "report_summary.json", {"report_md": str(out / "report.md"), "report_html": str(out / "report.html")})
    return {"report_md": str(out / "report.md"), "report_html": str(out / "report.html")}
