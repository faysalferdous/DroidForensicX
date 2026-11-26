"""Real offline engine smoke test; requires explicit opt-in and installed tools."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from droidforensicx.case import create_case
from droidforensicx.recovery import recover_image
from droidforensicx.utils import sha256_file


@pytest.mark.skipif(os.environ.get("DFX_ENGINE_TEST") != "1", reason="opt-in real-engine test")
def test_deleted_fat_file(tmp_path):
    for name in ("mkfs.vfat", "mcopy", "mdel", "tsk_recover"):
        assert shutil.which(name), f"Missing required integration tool: {name}"
    source = tmp_path / "sample.txt"
    source.write_bytes(b"DroidForensicX synthetic fixture\n" * 100)
    image = tmp_path / "card.img"
    with image.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    subprocess.run(["mkfs.vfat", "-F", "16", str(image)], check=True)
    subprocess.run(["mcopy", "-i", str(image), str(source), "::SAMPLE.TXT"], check=True)
    subprocess.run(["mdel", "-i", str(image), "::SAMPLE.TXT"], check=True)
    before = sha256_file(image)
    ctx = create_case("TEST", "Examiner", tmp_path / "cases")
    report = recover_image(ctx, image, carve=False)
    assert report["status"] == "complete"
    assert sha256_file(image) == before
    assert any(sha256_file(path) == sha256_file(source)
               for path in (Path(report["run"]) / "sleuthkit").rglob("*") if path.is_file())
