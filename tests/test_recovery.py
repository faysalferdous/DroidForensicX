from pathlib import Path

import pytest

from droidforensicx.case import create_case
from droidforensicx import recovery
from droidforensicx.utils import sha256_file


def test_import_hashes_and_duplicates(tmp_path):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "export"
    source.mkdir()
    (source / "a.txt").write_text("synthetic")
    (source / "b.txt").write_text("synthetic")
    (source / "bad.jpg").write_bytes(b"bad")
    (source / "link").symlink_to(source / "a.txt")
    report = recovery.import_export(ctx, source)
    assert report["files"] == 3
    assert report["unique_files"] == 2
    assert report["suspect_or_empty"] == 1
    assert "existing_export_file" in (Path(report["run"]) / "files.csv").read_text()


def test_image_engine_and_original_integrity(tmp_path, monkeypatch):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    source = tmp_path / "test.img"
    source.write_bytes(b"synthetic image")
    digest = sha256_file(source)

    def fake(name, args, logs, timeout, interactive=False):
        if name == "tsk_recover":
            (Path(args[-1]) / "a.txt").write_text("synthetic file")
        else:
            destination = Path(args[args.index("/d") + 1] + ".1")
            destination.mkdir()
            (destination / "b.txt").write_text("synthetic file")
        return {"engine": name, "status": "completed"}

    monkeypatch.setattr(recovery, "execute", fake)
    report = recovery.recover_image(ctx, source)
    assert report["status"] == "complete"
    assert report["files"] == 2
    assert report["unique_files"] == 1
    assert sha256_file(source) == digest
    assert report["working_copy_unchanged"]
    assert "whole_image_carved_candidate" in (Path(report["run"]) / "files.csv").read_text()


def test_missing_tool_and_invalid_source(tmp_path, monkeypatch):
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    image = tmp_path / "image"
    image.write_bytes(b"test")
    monkeypatch.setattr(recovery, "tool_path", lambda name: None)
    report = recovery.recover_image(ctx, image, carve=False)
    assert report["status"] == "partial_or_failed"
    assert report["engines"][0]["status"] == "missing"
    with pytest.raises(ValueError):
        recovery.recover_image(ctx, tmp_path)
    with pytest.raises(ValueError):
        recovery.import_export(ctx, ctx.root)
