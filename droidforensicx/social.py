"""Lawful social/browser artifact import helpers."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from .case import CaseContext
from .utils import sha256_file, write_csv, write_json


def import_social(ctx: CaseContext, input_path: Path) -> dict[str, Any]:
    out = ctx.subdir("10_social_imports")
    out.mkdir(parents=True, exist_ok=True)
    imported = out / input_path.name
    if input_path.is_file():
        if input_path.resolve() != imported.resolve():
            shutil.copy2(input_path, imported)
        files = [imported]
    else:
        files = []
        target_dir = out / input_path.name
        shutil.copytree(input_path, target_dir, dirs_exist_ok=True)
        files = [p for p in target_dir.rglob("*") if p.is_file()]
    index = [{"path": str(path), "name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)} for path in files]
    chat_rows: list[dict[str, str]] = []
    mentions: dict[str, int] = {}
    for path in files:
        if path.suffix.lower() != ".txt":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            match = re.match(r"(?P<ts>\d{1,4}[./-]\d{1,2}[./-]\d{1,4},?\s+\d{1,2}:\d{2}.*?)\s+-\s+(?P<sender>[^:]+):\s+(?P<msg>.*)", line)
            if match:
                sender = match.group("sender").strip()
                mentions[sender] = mentions.get(sender, 0) + 1
                chat_rows.append({"timestamp": match.group("ts"), "sender": sender, "event_type": "chat_message", "message_redacted": _redact_message(match.group("msg"))})
    write_csv(out / "social_import_index.csv", index, ["path", "name", "size", "sha256"])
    write_csv(out / "chat_timeline.csv", chat_rows, ["timestamp", "sender", "event_type", "message_redacted"])
    write_csv(out / "contacts_mentions.csv", [{"contact": k, "count": v} for k, v in sorted(mentions.items())], ["contact", "count"])
    summary = {"files_imported": len(files), "chat_messages": len(chat_rows), "private_db_bypass": False}
    write_json(out / "social_report.json", summary)
    return summary


def _redact_message(value: str) -> str:
    value = re.sub(r"(?i)\b(password|token|otp|code)\b(?:\s+is)?\s*[:=]?\s*\S+", r"\1=********", value)
    value = re.sub(r"\b\d{4,8}\b", "********", value)
    return value[:240]
