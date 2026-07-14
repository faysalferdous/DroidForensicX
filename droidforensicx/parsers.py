"""Parsers for Android logical triage artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeviceRecord:
    serial: str
    state: str
    details: dict[str, str]


def parse_adb_devices(output: str) -> list[DeviceRecord]:
    devices: list[DeviceRecord] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        details: dict[str, str] = {}
        for part in parts[2:]:
            if ":" in part:
                key, value = part.split(":", 1)
                details[key] = value
        devices.append(DeviceRecord(serial=parts[0], state=parts[1], details=details))
    return devices


def parse_getprop(output: str) -> dict[str, str]:
    props: dict[str, str] = {}
    pattern = re.compile(r"^\[(?P<key>[^\]]+)\]: \[(?P<value>.*)\]$")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            props[match.group("key")] = match.group("value")
    return props


def parse_pm_packages(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        package = line
        source = ""
        if line.startswith("package:"):
            body = line.removeprefix("package:")
            if "=" in body:
                source, package = body.rsplit("=", 1)
            else:
                package = body
        rows.append({"package": package.strip(), "source_path": source.strip()})
    return rows


def parse_dumpsys_package(output: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    apps: list[dict[str, str]] = []
    permissions: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    in_requested = False
    for raw in output.splitlines():
        line = raw.rstrip()
        pkg_match = re.match(r"\s*Package \[([^\]]+)\]", line)
        if pkg_match:
            if current:
                apps.append(current)
            current = {"package": pkg_match.group(1), "installer": "", "first_install_time": "", "last_update_time": "", "version_name": ""}
            in_requested = False
            continue
        if current is None:
            continue
        stripped = line.strip()
        for key, out_key in (
            ("installerPackageName=", "installer"),
            ("firstInstallTime=", "first_install_time"),
            ("lastUpdateTime=", "last_update_time"),
            ("versionName=", "version_name"),
        ):
            if stripped.startswith(key):
                current[out_key] = stripped.split("=", 1)[1]
        if stripped == "requested permissions:":
            in_requested = True
            continue
        if in_requested:
            if not stripped or ":" in stripped:
                in_requested = False
            elif stripped.startswith("android.permission."):
                permissions.append({"package": current["package"], "permission": stripped})
    if current:
        apps.append(current)
    return apps, permissions


def parse_logcat_package_events(output: str) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    pattern = re.compile(r"(?P<date>\d\d-\d\d)\s+(?P<time>\d\d:\d\d:\d\d\.\d+).*?(?P<event>PACKAGE_[A-Z_]+|Installing|Removing).*?(?P<package>[A-Za-z0-9_.]+)")
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            events.append(
                {
                    "timestamp": f"{match.group('date')} {match.group('time')}",
                    "event_type": match.group("event"),
                    "package": match.group("package"),
                    "source": "logcat",
                }
            )
    return events


def parse_usage_stats(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    package = ""
    for line in output.splitlines():
        pkg_match = re.search(r"package=([A-Za-z0-9_.]+)", line)
        if pkg_match:
            package = pkg_match.group(1)
        time_match = re.search(r"(lastTimeUsed|lastTimeVisible|time)=([0-9T:.\-+Z ]+)", line)
        if package and time_match:
            rows.append({"package": package, "event_type": time_match.group(1), "timestamp": time_match.group(2), "source": "usagestats"})
    return rows


def index_files(paths: list[Path]) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    for base in paths:
        if not base.exists():
            continue
        for item in base.rglob("*"):
            if item.is_file():
                stat = item.stat()
                rows.append({"path": str(item), "name": item.name, "size": stat.st_size, "mtime_epoch": int(stat.st_mtime)})
    return rows

