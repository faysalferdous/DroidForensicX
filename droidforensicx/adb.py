"""Safe ADB helpers."""

from __future__ import annotations

from pathlib import Path

from .utils import run_command, tool_path, write_json


ADB_COLLECTIONS = {
    "adb_devices_l.txt": ["adb", "devices", "-l"],
    "getprop.txt": ["adb", "shell", "getprop"],
    "settings_system.txt": ["adb", "shell", "settings", "list", "system"],
    "settings_secure.txt": ["adb", "shell", "settings", "list", "secure"],
    "settings_global.txt": ["adb", "shell", "settings", "list", "global"],
    "dumpsys_package.txt": ["adb", "shell", "dumpsys", "package"],
    "dumpsys_activity.txt": ["adb", "shell", "dumpsys", "activity"],
    "dumpsys_usagestats.txt": ["adb", "shell", "dumpsys", "usagestats"],
    "dumpsys_batterystats.txt": ["adb", "shell", "dumpsys", "batterystats"],
    "dumpsys_netstats.txt": ["adb", "shell", "dumpsys", "netstats"],
    "dumpsys_wifi.txt": ["adb", "shell", "dumpsys", "wifi"],
    "dumpsys_account.txt": ["adb", "shell", "dumpsys", "account"],
    "service_list.txt": ["adb", "shell", "service", "list"],
    "ps_A.txt": ["adb", "shell", "ps", "-A"],
    "ip_addr.txt": ["adb", "shell", "ip", "addr"],
    "ip_route.txt": ["adb", "shell", "ip", "route"],
    "logcat_d.txt": ["adb", "logcat", "-d"],
    "pm_list_packages.txt": ["adb", "shell", "pm", "list", "packages", "-f"],
    "pm_list_packages_u.txt": ["adb", "shell", "pm", "list", "packages", "-u", "-f"],
}


def collect_basic(out_dir: Path, timeout: int = 90) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {"adb_available": bool(tool_path("adb")), "commands": []}
    if not tool_path("adb"):
        summary["warning"] = "adb not found in PATH"
        summary["status"] = "partial_or_failed"
        write_json(out_dir / "acquire_basic_summary.json", summary)
        return summary
    commands: list[dict[str, str | int]] = []
    for filename, args in ADB_COLLECTIONS.items():
        result = run_command(args, timeout=timeout)
        (out_dir / filename).write_text(result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else ""), encoding="utf-8", errors="replace")
        commands.append({"file": filename, "returncode": result.returncode, "command": " ".join(args)})
    summary["commands"] = commands
    summary["status"] = "complete" if all(c["returncode"] == 0 for c in commands) else "partial_or_failed"
    write_json(out_dir / "acquire_basic_summary.json", summary)
    return summary


def run_bugreport(out_dir: Path, timeout: int = 600) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {"adb_available": bool(tool_path("adb")), "created": False}
    if not tool_path("adb"):
        summary["warning"] = "adb not found in PATH"
        write_json(out_dir / "bugreport_summary.json", summary)
        return summary
    target = out_dir / "bugreport.zip"
    result = run_command(["adb", "bugreport", str(target)], timeout=timeout)
    summary.update({"returncode": result.returncode, "created": result.returncode == 0 and target.is_file() and target.stat().st_size > 0, "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]})
    write_json(out_dir / "bugreport_summary.json", summary)
    return summary

