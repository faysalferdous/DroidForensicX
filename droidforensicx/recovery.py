"""Authorized, offline file recovery and logical export import.

Never operates on a live block device or bypasses Android access controls.
"""
from __future__ import annotations

import os
import csv
import json
from collections import Counter
import re
import shutil
import stat
import subprocess
import uuid
import zipfile
from pathlib import Path
from typing import Any

from .case import CaseContext
from .utils import sha256_file, tool_path, utc_now_iso, write_csv, write_json

RECOVERY_DIR = "15_recovery"
FIELDS = ["engine", "path", "size", "sha256", "duplicate_of", "validation", "origin"]


def regular_source(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Supply a regular local image or file, not a device or symlink")
    return path.resolve()


def new_run(ctx: CaseContext) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", ctx.case_id):
        raise ValueError("Use a simple case ID without path separators")
    if ctx.root.is_symlink() or not ctx.file("00_case", "case_manifest.json").is_file():
        raise ValueError("Initialize the case first")
    root = ctx.subdir(RECOVERY_DIR)
    if root.is_symlink():
        raise ValueError("Recovery directory must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run = root / uuid.uuid4().hex
    run.mkdir(mode=0o700)
    return run.resolve()


def files_under(root: Path):
    if root.is_symlink():
        raise ValueError("Unsafe output directory")
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        base = Path(directory)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(files):
            path = base / name
            if not path.is_symlink() and path.is_file():
                yield path


def validation(path: Path) -> str:
    """Lightweight structural checks, not proof of complete recovery."""
    if path.stat().st_size == 0:
        return "empty"
    with path.open("rb") as handle:
        head = handle.read(16)
        handle.seek(max(0, path.stat().st_size - 2048))
        tail = handle.read()
    ext = path.suffix.lower()
    if ext in {".jpg", ".jpeg"}:
        return "basic_pass" if head.startswith(b"\xff\xd8") and tail.endswith(b"\xff\xd9") else "suspect"
    if ext == ".png":
        return "basic_pass" if head.startswith(b"\x89PNG\r\n\x1a\n") and b"IEND" in tail else "suspect"
    if ext == ".pdf":
        return "basic_pass" if head.startswith(b"%PDF-") and b"%%EOF" in tail else "suspect"
    if ext in {".mp4", ".mov", ".m4a", ".m4v", ".3gp"}:
        return "basic_pass" if head[4:8] == b"ftyp" else "not_validated"
    if ext in {".sqlite", ".sqlite3", ".db"}:
        return "basic_pass" if head == b"SQLite format 3\x00" else "not_validated"
    if ext in {".zip", ".docx", ".xlsx", ".pptx", ".apk", ".odt"}:
        return "basic_pass" if zipfile.is_zipfile(path) else "suspect"
    return "not_validated"


def inventory(run: Path, roots: list[tuple[str, Path, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for engine, root, origin in roots:
        for path in files_under(root):
            if engine == "photorec" and path.name in {"report.xml", "photorec.log", "photorec.ses"}:
                continue
            rel = path.relative_to(run).as_posix()
            digest = sha256_file(path)
            rows.append({
                "engine": engine, "path": rel, "size": path.stat().st_size,
                "sha256": digest, "duplicate_of": seen.get(digest, ""),
                "validation": validation(path), "origin": origin,
            })
            seen.setdefault(digest, rel)
    return rows


def finish(run: Path, report: dict[str, Any], roots: list[tuple[str, Path, str]]) -> dict[str, Any]:
    rows = inventory(run, roots)
    report.update({
        "bytes": sum(r["size"] for r in rows),
        "extensions": dict(Counter(Path(r["path"]).suffix.lower() for r in rows)),
        "finished_utc": utc_now_iso(), "run": str(run),
        "files": len(rows), "unique_files": sum(not r["duplicate_of"] for r in rows),
        "suspect_or_empty": sum(r["validation"] in {"suspect", "empty"} for r in rows),
        "validation_note": "Basic checks and hashes do not prove completeness or deleted status.",
    })
    write_csv(run / "files.csv", rows, FIELDS)
    report["manifest_sha256"] = sha256_file(run / "files.csv")
    write_json(run / "recovery_report.json", report)
    return report


def execute(name: str, args: list[str], logs: Path, timeout: int, interactive: bool = False) -> dict[str, Any]:
    exe = tool_path(name)
    if not exe:
        return {"engine": name, "status": "missing"}
    try:
        if interactive:
            result = subprocess.run([exe, *args], cwd=logs, timeout=timeout, check=False)
        else:
            with (logs / (name + ".log")).open("wb") as log:
                result = subprocess.run([exe, *args], cwd=logs, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=timeout, check=False)
        return {"engine": name, "status": "completed" if result.returncode == 0 else "failed",
                "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"engine": name, "status": "timeout"}
    except OSError as error:
        return {"engine": name, "status": "failed", "error": str(error)}


def recover_image(ctx: CaseContext, image: Path, *, timeout: int = 3600,
                  filesystem: str = "other", offset: int | None = None,
                  carve: bool = True) -> dict[str, Any]:
    """Run recovery against a regular image; never pass an original device."""
    source = regular_source(image)
    if filesystem not in {"other", "ext"} or timeout <= 0 or (offset is not None and offset < 0):
        raise ValueError("Invalid filesystem, timeout or sector offset")
    run = new_run(ctx)
    logs = run / "logs"
    logs.mkdir()
    # A private working copy protects the original from external tool writes.
    working = run / "working.img"
    before = sha256_file(source)
    try:
        if shutil.disk_usage(run).free < source.stat().st_size + 16 * 1024 * 1024:
            raise OSError("Insufficient free space for working copy and minimum reserve")
        shutil.copyfile(source, working)
        if sha256_file(working) != before:
            raise ValueError("Working copy hash mismatch; source may have changed")
    except (OSError, ValueError) as error:
        return finish(run, {"mode": "image", "source": str(source), "status": "partial_or_failed",
                            "source_sha256_before": before, "error": str(error)}, [])
    working.chmod(0o400)
    roots = []
    engines = []
    out = run / "sleuthkit"
    out.mkdir()
    args = (["-o", str(offset)] if offset is not None else []) + [str(working), str(out)]
    engines.append(execute("tsk_recover", args, logs, timeout))
    roots.append(("sleuthkit", out, "unallocated_filesystem_candidate"))
    if carve:
        out = run / "photorec"
        out.mkdir()
        # Whole-image carving can include existing files; do not label them deleted.
        options = "options,mode_ext2," if filesystem == "ext" else ""
        command = "partition_none," + options + "fileopt,everything,enable,wholespace,search"
        engines.append(execute("photorec", ["/log", "/d", str(out / "recup"),
                                          "/cmd", str(working), command], logs, timeout, interactive=True))
        for directory in sorted(out.glob("recup.*")):
            if directory.is_dir() and not directory.is_symlink():
                roots.append(("photorec", directory, "whole_image_carved_candidate"))
    try:
        after = sha256_file(source)
        copy_after = sha256_file(working)
    except OSError:
        after = copy_after = None
    report = {"mode": "image", "source": str(source), "source_sha256_before": before,
              "source_sha256_after": after, "source_unchanged": before == after,
              "working_copy_unchanged": before == copy_after, "engines": engines,
              "filesystem": filesystem, "sector_offset": offset,
              "status": "complete" if before == after == copy_after and all(
                  e["status"] == "completed" for e in engines) else "partial_or_failed"}
    return finish(run, report, roots)


def import_export(ctx: CaseContext, source: Path) -> dict[str, Any]:
    """Copy an explicitly selected local export; no deleted-file claim."""
    if source.is_symlink() or not source.exists():
        raise ValueError("Supply an existing local export without symlinks")
    source = source.resolve()
    case_root = ctx.root.resolve()
    if source == case_root or source in case_root.parents or case_root in source.parents:
        raise ValueError("Select an export outside the case directory")
    if not source.is_dir():
        regular_source(source)
    run = new_run(ctx)
    out = run / "export"
    out.mkdir()
    candidates = files_under(source) if source.is_dir() else [source]
    errors = []
    for path in candidates:
        rel = path.relative_to(source) if source.is_dir() else Path(path.name)
        destination = out / rel
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            before = sha256_file(path)
            shutil.copyfile(path, destination)
            if sha256_file(destination) != before or sha256_file(path) != before:
                destination.unlink(missing_ok=True)
                errors.append({"path": str(rel), "error": "hash mismatch or changed source"})
        except OSError as error:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            errors.append({"path": str(rel), "error": str(error)})
    return finish(run, {"mode": "logical_export", "source": str(source),
                        "status": "partial_or_failed" if errors else "complete",
                        "errors": errors}, [("import", out, "existing_export_file")])


def recover_all(ctx: CaseContext, images: list[Path], exports: list[Path], *,
                timeout: int = 3600, filesystem: str = "other", carve: bool = True) -> dict[str, Any]:
    """Run all applicable methods on explicitly selected offline sources."""
    if not images and not exports:
        raise ValueError("Select at least one --image or --input")
    run = new_run(ctx)
    results: list[dict[str, Any]] = []
    for mode, sources in (("image", images), ("export", exports)):
        for source in sources:
            try:
                result = (recover_image(ctx, source, timeout=timeout, filesystem=filesystem, carve=carve)
                          if mode == "image" else import_export(ctx, source))
                results.append(result)
            except (OSError, ValueError) as error:
                results.append({"mode": mode, "source": str(source), "status": "partial_or_failed",
                                "error": str(error)})
    hashes: set[str] = set()
    for result in results:
        if "run" in result:
            manifest = Path(result["run"]) / "files.csv"
            if manifest.is_file():
                with manifest.open(newline="", encoding="utf-8") as handle:
                    hashes.update(row["sha256"] for row in csv.DictReader(handle))
    summary = {"mode": "batch", "run": str(run), "finished_utc": utc_now_iso(),
               "status": "complete" if all(r["status"] == "complete" for r in results) else "partial_or_failed",
               "files": sum(r.get("files", 0) for r in results), "unique_files": len(hashes),
               "runs": results}
    write_json(run / "recovery_report.json", summary)
    return summary


def verify_run(ctx: CaseContext, run_id: str) -> dict[str, Any]:
    """Verify manifest structure, digest, file hashes and unlisted output files."""
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise ValueError("Invalid recovery run ID")
    root = ctx.subdir(RECOVERY_DIR)
    run = root / run_id
    manifest = run / "files.csv"
    report_path = run / "recovery_report.json"
    if any(p.is_symlink() for p in (root, run, manifest, report_path)) or not manifest.is_file() or not report_path.is_file():
        raise ValueError("No safe file manifest for this child run")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Invalid recovery report")
    failures = []
    count = 0
    seen = set()
    expected_digest = report.get("manifest_sha256")
    if not expected_digest or sha256_file(manifest) != expected_digest:
        failures.append({"reason": "manifest digest missing or mismatched; legacy runs require manual verification"})
    with manifest.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != FIELDS:
            raise ValueError("Invalid manifest columns")
        for row in reader:
            count += 1
            rel = row["path"] or ""
            path = run / rel
            if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts or rel in seen:
                failures.append({"path": rel, "reason": "invalid or duplicate manifest path"})
                continue
            seen.add(rel)
            if (not path.resolve().is_relative_to(run.resolve()) or
                    any(p.is_symlink() for p in (path, *path.parents) if p != run and p.is_relative_to(run))
                    or not path.is_file()):
                failures.append({"path": rel, "reason": "missing or unsafe path"})
                continue
            if str(path.stat().st_size) != row["size"] or sha256_file(path) != row["sha256"]:
                failures.append({"path": rel, "reason": "size or hash mismatch"})
    if count != report.get("files"):
        failures.append({"reason": "manifest row count mismatch"})
    for name in ("export", "shared", "salvage", "sleuthkit", "photorec"):
        directory = run / name
        if not directory.exists():
            continue
        for path in files_under(directory):
            if name == "photorec" and path.name in {"report.xml", "photorec.log", "photorec.ses"}:
                continue
            if path.relative_to(run).as_posix() not in seen:
                failures.append({"path": path.relative_to(run).as_posix(), "reason": "unlisted output file"})
    return {"status": "failed" if failures else "verified", "checked": count, "failures": failures}


SHARED_MEDIA_DIRS = frozenset({"DCIM", "Pictures", "Movies", "Music", "Download",
                               "Documents", "Recordings", "Podcasts", "Audiobooks"})


def collect_media(ctx: CaseContext, serial: str, directories: list[str],
                  *, timeout: int = 3600) -> dict[str, Any]:
    """Collect only user-selected standard shared folders via authorized ADB."""
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", serial) or serial.startswith("-"):
        raise ValueError("Specify an exact ADB device serial")
    if not directories or any(d not in SHARED_MEDIA_DIRS for d in directories):
        raise ValueError("Select standard shared media folders, not private or arbitrary paths")
    if timeout <= 0:
        raise ValueError("Timeout must be positive")
    run = new_run(ctx)
    logs = run / "logs"
    logs.mkdir()
    out = run / "shared"
    out.mkdir()
    adb = tool_path("adb")
    results = []
    if not adb:
        return finish(run, {"mode": "adb_shared", "status": "partial_or_failed",
                            "engines": [{"engine": "adb", "status": "missing"}]}, [])
    try:
        state = subprocess.run([adb, "-s", serial, "get-state"], capture_output=True,
                               text=True, timeout=30, check=False)
        if state.returncode != 0 or state.stdout.strip() != "device":
            raise ValueError("Selected device is unavailable or not authorized")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return finish(run, {"mode": "adb_shared", "status": "partial_or_failed",
                            "error": str(error)}, [])
    roots = []
    for directory in dict.fromkeys(directories):
        dest = out / directory
        dest.mkdir()
        with (logs / (directory + ".log")).open("wb") as log:
            try:
                result = subprocess.run([adb, "-s", serial, "pull", "-a",
                                         "/sdcard/" + directory + "/.", str(dest)],
                                        stdout=log, stderr=subprocess.STDOUT,
                                        timeout=timeout, check=False)
                status = "completed" if result.returncode == 0 else "failed"
            except subprocess.TimeoutExpired:
                status = "timeout"
            except OSError:
                status = "failed"
        results.append({"folder": directory, "status": status})
        roots.append(("adb", dest, "existing_shared_file"))
    return finish(run, {"mode": "adb_shared", "serial": serial,
                        "engines": results, "status": "complete" if all(
                            r["status"] == "completed" for r in results) else "partial_or_failed",
                        "source_note": "Live logical collection; source hashes not verified on device."}, roots)


REMUX_FORMATS = {".mp4": "mov", ".mov": "mov", ".m4v": "mov",
                 ".mkv": "matroska", ".avi": "avi", ".webm": "matroska"}


def salvage_media(ctx: CaseContext, source: Path, *, timeout: int = 300) -> dict[str, Any]:
    """Try lossless remux into a new MKV container; never overwrite evidence."""
    source = regular_source(source)
    fmt = REMUX_FORMATS.get(source.suffix.lower())
    if not fmt or timeout <= 0:
        raise ValueError("Select a supported local video file and positive timeout")
    run = new_run(ctx)
    logs = run / "logs"
    logs.mkdir()
    out = run / "salvage"
    out.mkdir()
    before = sha256_file(source)
    working = run / ("source" + source.suffix.lower())
    shutil.copyfile(source, working)
    working.chmod(0o400)
    if sha256_file(working) != before:
        return finish(run, {"mode": "media_salvage", "status": "partial_or_failed",
                            "error": "Working copy hash mismatch"}, [])
    destination = out / "salvaged.mkv"
    result = execute("ffmpeg", ["-nostdin", "-n", "-v", "error", "-protocol_whitelist", "file,pipe",
                                "-f", fmt, "-i", str(working), "-map", "0:v?", "-map", "0:a?",
                                "-c", "copy", "-f", "matroska", str(destination)], logs, timeout)
    unchanged = sha256_file(source) == before and sha256_file(working) == before
    complete = (result["status"] == "completed" and destination.is_file()
                and destination.stat().st_size > 0 and unchanged)
    return finish(run, {"mode": "media_salvage", "source": str(source),
                        "source_sha256_before": before, "source_unchanged": unchanged,
                        "engines": [result], "status": "complete" if complete else "partial_or_failed",
                        "note": "Remux is a derivative, not proof of repair or complete decoding."},
                  [("ffmpeg", out, "derived_media_remux")])
