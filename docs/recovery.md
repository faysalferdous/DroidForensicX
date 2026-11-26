
# Universal File Recovery

Use only with your own storage or explicitly authorized evidence. This module
does not bypass locks, root Android, decrypt internal storage, or acquire raw
live devices. Modern Android encryption, TRIM and overwrites can make deleted
data unrecoverable.

## Install (Debian, Ubuntu, Kali)

    sudo apt update
    sudo apt install testdisk sleuthkit gddrescue adb ffmpeg dosfstools mtools
    python -m pip install -e '.[dev]'

## Recovery commands

    droidforensicx init --case RECOVERY-001 --examiner Examiner
    droidforensicx recover-image --case RECOVERY-001 --image /path/to/card.img --authorized
    droidforensicx recover-import --case RECOVERY-001 --input /path/to/export --authorized

The image command runs TSK unallocated-file extraction and PhotoRec
whole-image carving with its default enabled formats. Use a raw partition image
for best carving results. Use --filesystem ext for ext filesystems, --offset
for a TSK partition offset in sectors, and --no-carve for TSK only. For a full
partitioned disk, inspect its layout with mmls and obtain a suitable partition
image before carving. PhotoRec may need an interactive terminal. Missing tools,
errors and timeouts yield a nonzero command exit and a partial report.

Logical import accepts files or folders exported via the phone's built-in
Trash, backup, USB file transfer or an explicitly authorized ADB media export.
These are existing files, not proof of deletion. It does not automatically
access app-private trash or cloud accounts.

## SD card and TestDisk

Use a write blocker where available; unmount the card and use a trusted imaging
workflow to make a raw image on a different drive. GNU ddrescue can image damaged
media; verify device identity before using it. Do not run recovery or repair on
the original card. TestDisk can inspect partition structure and perform
interactive undelete on a disposable working copy. Do not choose write or
repair operations on original evidence. This release does not automate physical
acquisition or TestDisk repair.

## Outputs and interpretation

Each run is isolated under cases/CASE/15_recovery/RUN_ID/. The input image is
hashed before and after, and a read-only working copy is retained. Ensure
enough disk space for the copy plus recovered files. The original image should
also be stored read-only. Logs, files.csv and recovery_report.json record
engine status, provenance, SHA-256, duplicate relationships and basic file
validation. Duplicate files are preserved, not removed. Whole-image carved
files may include existing files. Basic JPEG, PNG, PDF and ZIP container checks
are not full decoding, and other types are marked not validated. No repair or
recovery percentage is promised. Never upload case output to GitHub.

## Synthetic smoke test

From a disposable directory with an existing synthetic sample.jpg:

    truncate -s 128M test.img
    mkfs.vfat test.img
    mcopy -i test.img sample.jpg ::sample.jpg
    mdel -i test.img ::sample.jpg
    droidforensicx recover-image --case RECOVERY-001 --image test.img --authorized
    python -m pytest tests/test_recovery.py -q

Compare recovered file hashes against the original sample. Repeat with sample
video, PDF and ZIP files. Unit tests mock external engines; a real engine smoke
test is still required. No real personal data belongs in test fixtures.

References:
- https://www.cgsecurity.org/testdisk_doc/scripted_run.html
- https://wiki.sleuthkit.org/tsk_recover/
