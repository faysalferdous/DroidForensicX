"""Regression checks for evidence preservation and report safety."""
import csv
import os
import subprocess
from pathlib import Path

import pytest

from droidforensicx.analysis import build_timeline, import_credentials, timeline_sort_key
from droidforensicx.case import create_case, get_case
from droidforensicx.media import scan_media
from droidforensicx.parsers import parse_pm_packages
from droidforensicx.recovery import import_export, verify_run, recover_image
from droidforensicx.reporting import generate_report
from droidforensicx.utils import run_command, write_csv


def test_case_safety(tmp_path):
    with pytest.raises(ValueError):
        get_case("../outside", tmp_path)
    with pytest.raises(ValueError):
        get_case(str(tmp_path / "outside"), tmp_path)
    ctx = create_case("CASE-1", "Examiner", tmp_path)
    notes = ctx.file("00_case", "case_notes.md")
    notes.write_text("retain this evidence")
    with pytest.raises(FileExistsError):
        create_case("CASE-1", "Other", tmp_path)
    assert notes.read_text() == "retain this evidence"
    if os.name == "posix":
        assert ctx.root.stat().st_mode & 0o077 == 0


def test_case_symlink_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "LINK").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        get_case("LINK", tmp_path)


def test_html_escape_and_timeline(tmp_path):
    ctx = create_case("TEST", "Examiner", tmp_path)
    raw = "<script>synthetic</script>"
    write_csv(ctx.file("07_media", "media_timeline.csv"),
              [{"timestamp": "2026-01-01T00:00:00Z", "event_type": "media", "path": raw}])
    build_timeline(ctx)
    timeline = ctx.file("12_timeline", "timeline.html").read_text()
    assert raw not in timeline
    assert "&lt;script&gt;" in timeline
    report = Path(generate_report(ctx)["report_html"]).read_text()
    assert raw not in report
    assert "&lt;script&gt;" in report
    assert timeline_sort_key("2026-01-01T01:00:00+02:00") < timeline_sort_key("2026-01-01T00:00:00Z")
    assert timeline_sort_key("1767225600") == timeline_sort_key("2026-01-01T00:00:00Z")
    assert timeline_sort_key("07-12 10:22:00")[0] == 1


def test_credentials_preserved(tmp_path):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "test.csv"
    source.write_text("url,username,password\nhttps://example.test,test,synthetic\n")
    import_credentials(ctx, source)
    stored = ctx.file("08_credentials_sensitive", "test.csv")
    old = stored.read_bytes()
    source.write_text("url,username,password\nhttps://example.test,test,different\n")
    with pytest.raises(FileExistsError):
        import_credentials(ctx, source)
    assert stored.read_bytes() == old
    if os.name == "posix":
        assert stored.stat().st_mode & 0o077 == 0


def test_manifest_tampering_and_report(tmp_path):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "file.txt"
    source.write_text("sample")
    result = import_export(ctx, source)
    run = Path(result["run"])
    assert verify_run(ctx, run.name)["status"] == "verified"
    report = Path(generate_report(ctx)["report_html"]).read_text()
    assert run.name in report
    (run / "export" / "extra.txt").write_text("unlisted")
    assert verify_run(ctx, run.name)["status"] == "failed"
    (run / "export" / "extra.txt").unlink()
    manifest = run / "files.csv"
    manifest.write_text(manifest.read_text().splitlines()[0] + "\n")
    assert verify_run(ctx, run.name)["status"] == "failed"


def test_low_disk_space(tmp_path, monkeypatch):
    from collections import namedtuple
    from droidforensicx import recovery
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "image.img"
    source.write_bytes(b"synthetic")
    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(recovery.shutil, "disk_usage", lambda path: Usage(100, 100, 0))
    result = recover_image(ctx, source)
    assert result["status"] == "partial_or_failed"
    assert "Insufficient" in result["error"]


def test_timeout_and_error_parser(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1, output=b"partial")
    monkeypatch.setattr(subprocess, "run", timeout)
    result = run_command(["fake"])
    assert result.returncode == 124
    assert result.stdout == "partial"
    assert parse_pm_packages("error: device offline\npackage:com.example") == [
        {"package": "com.example", "source_path": ""}
    ]


def test_single_file_media(tmp_path):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "sample.txt"
    source.write_text("synthetic")
    assert scan_media(ctx, source)["media_files"] == 1


def test_png_structural_validation(tmp_path):
    import struct
    import zlib
    from droidforensicx.recovery import validation

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    png = tmp_path / "sample.png"
    signature = b"\x89PNG\r\n\x1a\n"
    content = signature + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    content += chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b"")
    png.write_bytes(content)
    assert validation(png) == "structural_pass"
    broken = bytearray(content)
    broken[-1] ^= 1
    png.write_bytes(broken)
    assert validation(png) == "suspect"


def test_zip_structural_validation(tmp_path):
    import zipfile
    from droidforensicx.recovery import validation
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
        handle.writestr("sample.txt", "synthetic contents")
    assert validation(archive) == "structural_pass"
    archive.write_bytes(archive.read_bytes().replace(b"synthetic contents", b"corrupted contents"))
    assert validation(archive) == "suspect"
