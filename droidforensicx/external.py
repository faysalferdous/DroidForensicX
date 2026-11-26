"""Optional external tool integrations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import run_command, tool_path, write_json

OPTIONAL_TOOLS = ["adb", "androidqf", "mvt-android", "aleapp", "exiftool", "mediainfo", "photorec", "testdisk", "tsk_recover", "ddrescue", "ffmpeg", "ffprobe", "hashdeep"]


def detect_tools() -> dict[str, dict[str, str | bool]]:
    return {name: {"available": bool(tool_path(name)), "path": tool_path(name) or ""} for name in OPTIONAL_TOOLS}


def run_androidqf(out_dir: Path, timeout: int = 900) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = tool_path("androidqf")
    summary: dict[str, Any] = {"available": bool(exe), "created": False}
    if not exe:
        summary["warning"] = "AndroidQF not found; skipped"
        write_json(out_dir / "androidqf_summary.json", summary)
        return summary
    result = run_command([exe, "-o", str(out_dir / "androidqf_output")], timeout=timeout)
    summary.update({"returncode": result.returncode, "stdout_tail": result.stdout[-2000:], "stderr_tail": result.stderr[-2000:], "created": True})
    write_json(out_dir / "androidqf_summary.json", summary)
    return summary


def run_mvt(case_root: Path, out_dir: Path, timeout: int = 900) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = tool_path("mvt-android")
    summary: dict[str, Any] = {"available": bool(exe), "runs": []}
    if not exe:
        summary["warning"] = "mvt-android not found; skipped"
        write_json(out_dir / "mvt_summary.json", summary)
        return summary
    androidqf_inputs = list((case_root / "03_androidqf").glob("**/*"))
    bugreports = list((case_root / "02_bugreport").glob("*.zip"))
    runs: list[dict[str, Any]] = []
    if androidqf_inputs:
        result = run_command([exe, "check-androidqf", "--output", str(out_dir / "androidqf_check"), str(case_root / "03_androidqf")], timeout=timeout)
        runs.append({"module": "check-androidqf", "returncode": result.returncode, "stderr_tail": result.stderr[-1000:]})
    if bugreports:
        result = run_command([exe, "check-bugreport", "--output", str(out_dir / "bugreport_check"), str(bugreports[0])], timeout=timeout)
        runs.append({"module": "check-bugreport", "returncode": result.returncode, "stderr_tail": result.stderr[-1000:]})
    if not runs:
        summary["warning"] = "No AndroidQF or bugreport inputs found for MVT"
    summary["runs"] = runs
    write_json(out_dir / "mvt_summary.json", summary)
    return summary

