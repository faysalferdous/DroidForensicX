"""Case folder creation and path helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re
import os
from pathlib import Path

from . import __version__
from .constants import CASE_DIRS, DEFAULT_CASES_ROOT, LIMITATIONS
from .utils import utc_now_iso, write_json


@dataclass(frozen=True)
class CaseContext:
    case_id: str
    root: Path

    def subdir(self, name: str) -> Path:
        return self.root / name

    def file(self, subdir: str, filename: str) -> Path:
        return self.subdir(subdir) / filename


def get_case(case_id: str, cases_root: Path = DEFAULT_CASES_ROOT) -> CaseContext:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", case_id):
        raise ValueError("Case ID must contain only letters, digits, dots, underscores or hyphens")
    if cases_root.is_symlink():
        raise ValueError("Cases directory cannot be a symlink")
    root = cases_root / case_id
    if root.is_symlink() or any((root / directory).is_symlink() for directory in CASE_DIRS):
        raise ValueError("Case directories cannot be symlinks")
    return CaseContext(case_id=case_id, root=root)


def create_case(case_id: str, examiner: str, cases_root: Path = DEFAULT_CASES_ROOT) -> CaseContext:
    ctx = get_case(case_id, cases_root)
    if ctx.root.exists():
        raise FileExistsError("Case already exists; use a new case ID to preserve evidence")
    cases_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    ctx.root.mkdir(mode=0o700)
    for directory in CASE_DIRS:
        (ctx.root / directory).mkdir(mode=0o700)
    if os.name == "posix":
        ctx.root.chmod(0o700)

    manifest = {
        "case_id": case_id,
        "examiner": examiner,
        "created_utc": utc_now_iso(),
        "tool": "DroidForensicX",
        "tool_version": __version__,
        "purpose": "Authorized Android logical forensic triage and reporting",
        "privacy_default": "Secrets redacted by default",
        "limitations": LIMITATIONS,
    }
    write_json(ctx.file("00_case", "case_manifest.json"), manifest)
    ctx.file("00_case", "case_notes.md").write_text(f"# Case Notes\n\nCase: {case_id}\nExaminer: {examiner}\n", encoding="utf-8")
    ctx.file("00_case", "chain_of_custody.md").write_text(
        "# Chain of Custody\n\nRecord transfers, handlers, timestamps, and evidence references here.\n",
        encoding="utf-8",
    )
    ctx.file("00_case", "tool_versions.txt").write_text(f"DroidForensicX {__version__}\n", encoding="utf-8")
    return ctx

