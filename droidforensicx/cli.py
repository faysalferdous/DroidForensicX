"""Typer CLI for DroidForensicX."""

from __future__ import annotations

from pathlib import Path
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .adb import collect_basic, run_bugreport
from .analysis import app_inventory, app_lifecycle, build_timeline, hash_case, import_credentials, indicators
from .case import create_case, get_case
from .demo import create_demo
from .external import detect_tools, run_androidqf, run_mvt
from .media import scan_media
from .parsers import parse_adb_devices, parse_getprop
from .reporting import generate_report
from .recovery import import_export, recover_all, recover_image, verify_run
from .social import import_social
from .utils import read_text, run_command, tool_path, write_json

BANNER_TITLE = "DroidForensicX"
BANNER_SUBTITLE = "Free Android Defence Forensic Triage & Reporting Framework"
BANNER_CREATOR = "Created by Faysal Ferdous"

app = typer.Typer(
    help=(
        f"{BANNER_TITLE}\n"
        f"{BANNER_SUBTITLE}\n"
        f"{BANNER_CREATOR}\n\n"
        "Authorized Android logical forensic triage, evidence hashing, timeline, risk scoring, and reporting."
    )
)
console = Console()


def banner() -> None:
    console.print(
        Panel.fit(
            f"[bold]{BANNER_TITLE}[/bold] v{__version__}\n"
            f"{BANNER_SUBTITLE}\n"
            f"{BANNER_CREATOR}",
            border_style="cyan",
        )
    )


def ctx(case: str):
    return get_case(case)


@app.command()
def init(case: str = typer.Option(..., "--case"), examiner: str = typer.Option(..., "--examiner")) -> None:
    banner()
    case_ctx = create_case(case, examiner)
    console.print(f"[green]+[/green] Case created: {case_ctx.root}")


@app.command("check-device")
def check_device(case: str | None = typer.Option(None, "--case")) -> None:
    banner()
    table = Table("Tool", "Available", "Path")
    for name, info in detect_tools().items():
        table.add_row(name, "yes" if info["available"] else "no", str(info["path"]))
    console.print(table)
    if not tool_path("adb"):
        console.print("[yellow]adb not found; install Android platform-tools for device checks.[/yellow]")
        return
    result = run_command(["adb", "devices", "-l"], timeout=30)
    devices = parse_adb_devices(result.stdout)
    device_table = Table("Serial", "State", "Details")
    for device in devices:
        device_table.add_row(device.serial, device.state, str(device.details))
    console.print(device_table)
    if case:
        case_ctx = ctx(case)
        case_ctx.subdir("01_raw_adb").mkdir(parents=True, exist_ok=True)
        (case_ctx.file("01_raw_adb", "adb_devices_l.txt")).write_text(result.stdout + result.stderr, encoding="utf-8")


@app.command("acquire-basic")
def acquire_basic(case: str = typer.Option(..., "--case")) -> None:
    banner()
    summary = collect_basic(ctx(case).subdir("01_raw_adb"))
    props = parse_getprop(read_text(ctx(case).file("01_raw_adb", "getprop.txt")))
    identity = {k: props.get(k, "") for k in ["ro.product.manufacturer", "ro.product.model", "ro.build.version.release", "ro.build.fingerprint"]}
    write_json(ctx(case).file("01_raw_adb", "device_identity.json"), identity)
    console.print(f"[green]+[/green] Basic acquisition complete: {summary}")


@app.command()
def bugreport(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(run_bugreport(ctx(case).subdir("02_bugreport")))


@app.command()
def androidqf(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(run_androidqf(ctx(case).subdir("03_androidqf")))


@app.command()
def mvt(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(run_mvt(ctx(case).root, ctx(case).subdir("04_mvt")))


@app.command("app-inventory")
def app_inventory_cmd(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(app_inventory(ctx(case)))


@app.command("app-lifecycle")
def app_lifecycle_cmd(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(app_lifecycle(ctx(case)))


@app.command("media-scan")
def media_scan(case: str = typer.Option(..., "--case"), input_path: Path | None = typer.Option(None, "--input")) -> None:
    banner()
    console.print(scan_media(ctx(case), input_path))


@app.command("credential-import")
def credential_import(case: str = typer.Option(..., "--case"), csv_file: Path = typer.Option(..., "--csv"), show_sensitive: bool = typer.Option(False, "--show-sensitive")) -> None:
    banner()
    if show_sensitive:
        console.print("[yellow]--show-sensitive is a warning placeholder. Raw passwords are never printed in normal reports.[/yellow]")
    console.print(import_credentials(ctx(case), csv_file))


@app.command("social-import")
def social_import(case: str = typer.Option(..., "--case"), input_path: Path = typer.Option(..., "--input")) -> None:
    banner()
    console.print(import_social(ctx(case), input_path))


@app.command("indicators")
def indicators_cmd(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(indicators(ctx(case)))


@app.command()
def timeline(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(build_timeline(ctx(case)))


@app.command("hash")
def hash_cmd(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(hash_case(ctx(case)))


@app.command()
def report(case: str = typer.Option(..., "--case")) -> None:
    banner()
    console.print(generate_report(ctx(case)))


@app.command("defence-full")
def defence_full(case: str = typer.Option(..., "--case"), examiner: str = typer.Option("Unknown", "--examiner")) -> None:
    banner()
    if not ctx(case).root.exists():
        create_case(case, examiner)
    check_device(case)
    acquire_basic(case)
    bugreport(case)
    androidqf(case)
    app_inventory_cmd(case)
    app_lifecycle_cmd(case)
    indicators_cmd(case)
    timeline(case)
    hash_cmd(case)
    reports = generate_report(ctx(case))
    console.print(f"[green]+[/green] Report: {reports['report_html']}")


@app.command()
def demo(case: str = typer.Option("DEMO-ANDROID-FORENSIC", "--case")) -> None:
    banner()
    reports = create_demo(case)
    case_ctx = ctx(case)
    risk = case_ctx.file("11_indicators", "risk_summary.json")
    console.print(f"[green]+[/green] Case: {case}")
    console.print(f"[green]+[/green] Report: {reports['report_html']}")
    console.print(f"[green]+[/green] Risk summary: {risk}")


@app.command("recover-image")
def recovery_image_cmd(
    case: str = typer.Option(..., "--case"),
    image: Path = typer.Option(..., "--image"),
    authorized: bool = typer.Option(False, "--authorized"),
    filesystem: str = typer.Option("other", "--filesystem"),
    offset: int | None = typer.Option(None, "--offset", min=0),
    timeout: int = typer.Option(3600, "--timeout", min=1),
    no_carve: bool = typer.Option(False, "--no-carve"),
) -> None:
    """Recover candidates from an authorized offline storage image."""
    if not authorized:
        raise typer.BadParameter("Confirm authorization with --authorized")
    try:
        result = recover_image(ctx(case), image, timeout=timeout, filesystem=filesystem,
                               offset=offset, carve=not no_carve)
    except (ValueError, OSError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print("Recovery status:", result["status"], "Files:", result["files"], "Run:", result["run"], markup=False)
    if result["status"] != "complete":
        raise typer.Exit(1)


@app.command("recover-import")
def recovery_import_cmd(
    case: str = typer.Option(..., "--case"),
    source: Path = typer.Option(..., "--input"),
    authorized: bool = typer.Option(False, "--authorized"),
) -> None:
    """Import an authorized local backup, trash export, or shared file export."""
    if not authorized:
        raise typer.BadParameter("Confirm authorization with --authorized")
    try:
        result = import_export(ctx(case), source)
    except (ValueError, OSError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print("Import status:", result["status"], "Files:", result["files"], "Run:", result["run"], markup=False)
    if result["status"] != "complete":
        raise typer.Exit(1)


@app.command("recover-all")
def recovery_all_cmd(
    case: str = typer.Option(..., "--case"),
    images: list[Path] = typer.Option(None, "--image"),
    exports: list[Path] = typer.Option(None, "--input"),
    authorized: bool = typer.Option(False, "--authorized"),
    filesystem: str = typer.Option("other", "--filesystem"),
    timeout: int = typer.Option(3600, "--timeout", min=1),
    no_carve: bool = typer.Option(False, "--no-carve"),
) -> None:
    """Run applicable recovery methods against selected images and exports."""
    if not authorized:
        raise typer.BadParameter("Confirm authorization with --authorized")
    try:
        result = recover_all(ctx(case), images or [], exports or [], timeout=timeout,
                             filesystem=filesystem, carve=not no_carve)
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print("Recovery status:", result["status"], "Files:", result["files"],
                  "Unique:", result["unique_files"], "Run:", result["run"], markup=False)
    if result["status"] != "complete":
        raise typer.Exit(1)


@app.command("recover-verify")
def recovery_verify_cmd(
    case: str = typer.Option(..., "--case"),
    run_id: str = typer.Option(..., "--run"),
) -> None:
    """Verify recovered files against a saved run manifest."""
    try:
        result = verify_run(ctx(case), run_id)
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print(result, markup=False)
    if result["status"] != "verified":
        raise typer.Exit(1)


def main() -> None:
    if any(arg in {"--help", "-h"} for arg in sys.argv[1:]):
        banner()
    app()


if __name__ == "__main__":
    main()
