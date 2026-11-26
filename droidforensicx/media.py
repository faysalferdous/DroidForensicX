"""Media indexing and metadata helpers."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .case import CaseContext
from .utils import run_command, sha256_file, tool_path, write_csv, write_json


def scan_media(ctx: CaseContext, input_path: Path | None = None) -> dict[str, Any]:
    out = ctx.subdir("07_media")
    out.mkdir(parents=True, exist_ok=True)
    roots = [input_path] if input_path else []
    rows: list[dict[str, Any]] = []
    exif_rows: list[dict[str, Any]] = []
    for root in roots:
        if not root or not root.exists():
            continue
        for path in ([root] if root.is_file() else root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            digest = sha256_file(path)
            stat = path.stat()
            row = {"path": str(path), "name": path.name, "size": stat.st_size, "mtime_epoch": int(stat.st_mtime), "sha256": digest}
            rows.append(row)
            if tool_path("exiftool"):
                result = run_command(["exiftool", "-json", str(path)], timeout=30)
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)[0]
                        exif_rows.append({"path": str(path), "CreateDate": data.get("CreateDate", ""), "MIMEType": data.get("MIMEType", ""), "Make": data.get("Make", ""), "Model": data.get("Model", "")})
                    except (json.JSONDecodeError, IndexError):
                        pass
    dupes = [{"sha256": digest, "count": len(items), "paths": " | ".join(items)} for digest, items in _group_duplicates(rows).items() if len(items) > 1]
    timeline = [{"timestamp": row["mtime_epoch"], "event_type": "file_mtime", "path": row["path"], "source": "media"} for row in rows]
    write_csv(out / "media_index.csv", rows, ["path", "name", "size", "mtime_epoch", "sha256"])
    write_csv(out / "media_exif.csv", exif_rows, ["path", "CreateDate", "MIMEType", "Make", "Model"])
    write_csv(out / "media_timeline.csv", timeline, ["timestamp", "event_type", "path", "source"])
    write_csv(out / "media_duplicates.csv", dupes, ["sha256", "count", "paths"])
    summary = {"media_files": len(rows), "duplicates": len(dupes), "exiftool_available": bool(tool_path("exiftool"))}
    write_json(out / "media_summary.json", summary)
    return summary


def _group_duplicates(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        grouped[str(row["sha256"])].append(str(row["path"]))
    return grouped

