"""Authorized, offline file recovery and logical export import.

Never operates on a live block device or bypasses Android access controls.
"""
from __future__ import annotations

import os
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
    if not ctx.file("00_case", "case_manifest.json").is_file():
        raise ValueError("Initialize the case first")
    root = ctx.subdir(RECOVERY_DIR)
    if root.is_symlink():
        raise ValueError("Recovery directory must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run = root / uuid.uuid4().hex
    run.mkdir(mode=0o700)
    return run.resolve()


def files_under(root: Path):
    for directory, dirs, files in os.walk(root, followlinks=False):
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
    if ext in {".zip", ".docx", ".xlsx", ".pptx", ".apk", ".odt"}:
        return "basic_pass" if zipfile.is_zipfile(path) else "suspect"
    return "not_validated"


def inventory(run: Path, roots: list[tuple[str, Path, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for engine, root, origin in roots:
        for path in files_under(root):
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
        "finished_utc": utc_now_iso(), "run": str(run),
        "files": len(rows), "unique_files": sum(not r["duplicate_of"] for r in rows),
        "suspect_or_empty": sum(r["validation"] in {"suspect", "empty"} for r in rows),
        "validation_note": "Basic checks and hashes do not prove completeness or deleted status.",
    })
    write_csv(run / "files.csv", rows, FIELDS)
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
    shutil.copyfile(source, working)
    if sha256_file(working) != before:
        raise ValueError("Working copy hash mismatch; source may have changed")
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
        roots.append(("photorec", out, "whole_image_carved_candidate"))
    after = sha256_file(source)
    copy_after = sha256_file(working)
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
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            before = sha256_file(path)
            shutil.copyfile(path, destination)
            if sha256_file(destination) != before or sha256_file(path) != before:
                errors.append({"path": str(rel), "error": "hash mismatch or changed source"})
        except OSError as error:
            errors.append({"path": str(rel), "error": str(error)})
    return finish(run, {"mode": "logical_export", "source": str(source),
                        "status": "partial_or_failed" if errors else "complete",
                        "errors": errors}, [("import", out, "existing_export_file")])
