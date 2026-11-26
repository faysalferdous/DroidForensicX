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


@pytest.mark.skipif(os.environ.get("DFX_ENGINE_TEST") != "1", reason="opt-in real-engine test")
def test_real_ffmpeg_remux(tmp_path):
    from droidforensicx.recovery import salvage_media, verify_run
    assert shutil.which("ffmpeg") and shutil.which("ffprobe")
    source = tmp_path / "sample.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
                    "color=c=blue:s=64x64:r=10", "-t", "1", "-c:v", "mpeg4",
                    str(source)], check=True, timeout=30)
    before = sha256_file(source)
    ctx = create_case("VIDEO", "Examiner", tmp_path / "cases")
    report = salvage_media(ctx, source, timeout=30)
    assert report["status"] == "complete"
    run = Path(report["run"])
    result = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0",
                             "-show_entries", "stream=codec_name", "-of", "csv=p=0",
                             str(run / "salvage" / "salvaged.mkv")],
                            capture_output=True, text=True, check=True, timeout=30)
    assert "mpeg4" in result.stdout
    assert sha256_file(source) == before
    assert verify_run(ctx, run.name)["status"] == "verified"
