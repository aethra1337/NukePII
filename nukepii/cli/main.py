"""NukePII command-line interface.

Commands
--------
``nukepii scan --file <path>`` — stream-scan a file, print the risk report.
``nukepii clean --file <path> --mode mask`` — stream-sanitize to a new file.

Both commands run through :class:`nukepii.core.streamer.DataStreamer`, so
multi-GB inputs stay memory-bounded. Run via::

    python -m nukepii.cli.main scan --file data.csv
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nukepii import __version__
from nukepii.core.detectors import REGIONS
from nukepii.core.streamer import BACKENDS, CLEAN_MODES, PREVIEW_MODES, DataStreamer, capabilities

app = typer.Typer(name="nukepii", help="Zero-Trust PII detection & sanitization engine.",
                  no_args_is_help=True)
console = Console()

_RISK_STYLE = {"LOW": "green", "MODERATE": "yellow", "HIGH": "dark_orange", "CRITICAL": "red"}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"nukepii {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version_callback,
                                 is_eager=True, help="Show version and exit."),
) -> None:
    """NukePII — local-first PII detection, analysis & sanitization."""


@app.command()
def scan(
    file: Path = typer.Option(..., "--file", "-f", exists=True, dir_okay=False,
                              readable=True, help="File to scan (csv/json/log/sql/txt)."),
    mode: str = typer.Option("mask", "--mode", "-m",
                             help="Preview sanitization mode."),
    salt: str | None = typer.Option(None, "--salt",
                                       help="HMAC salt (else auto-generated)."),
    backend: str = typer.Option("auto", "--backend",
                                help=f"CSV batch backend: {', '.join(BACKENDS)}."),
    region: str = typer.Option("ALL", "--region", "-r",
                               help=f"Detector region filter: {', '.join(REGIONS)}."),
    output: Path | None = typer.Option(None, "--output", "-o",
                                          help="Write full JSON report to this file."),
    preview: str = typer.Option("masked", "--preview",
                                help=f"Preview exposure: {', '.join(PREVIEW_MODES)} (raw needs NUKEPII_ALLOW_RAW=1)."),
    workers: int = typer.Option(1, "--workers", "-w",
                               help="Parallel workers (Faz-3 pool hazır olana kadar 1; >1 uyarı verir)."),
    format: str = typer.Option("pretty", "--format",
                              help="Output format: pretty|json|sarif."),
) -> None:
    """Scan FILE in streaming batches and print the risk report."""
    if mode not in CLEAN_MODES:
        raise typer.BadParameter(f"mode must be one of {sorted(CLEAN_MODES)}.")
    if backend not in BACKENDS:
        raise typer.BadParameter(f"backend must be one of {BACKENDS}.")
    if region.upper() not in REGIONS:
        raise typer.BadParameter(f"region must be one of {list(REGIONS)}.")
    if preview.lower() not in PREVIEW_MODES:
        raise typer.BadParameter(f"preview must be one of {list(PREVIEW_MODES)}.")
    streamer = DataStreamer(backend=backend, workers=max(1, workers),
                            preview_mode=preview.lower())
    try:
        with console.status(f"[cyan]Scanning {file.name}…[/cyan]"):
            report = streamer.scan_file(str(file), mode=mode, salt=salt,
                                        region=region.upper(), preview=preview.lower())
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None

    fmt = format.lower()
    if fmt not in ("pretty", "json", "sarif"):
        raise typer.BadParameter("format must be one of pretty|json|sarif.")
    if fmt == "json":
        console.print_json(json.dumps(report))
        if output is not None:
            output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return
    if fmt == "sarif":
        from nukepii.core.sarif import report_to_sarif

        sarif = report_to_sarif(report)
        console.print_json(json.dumps(sarif))
        if output is not None:
            output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return

    style = _RISK_STYLE.get(report["risk_label"], "white")
    console.print(Panel(
        f"[bold]{report['filename']}[/bold] · {report['units']} {report['unit_kind']} · "
        f"{report['total_detections']} detections · region={report.get('region', 'ALL')} · "
        f"engine={report['engine']}/{report.get('backend', '?')}"
        + (" · [yellow]TRUNCATED[/yellow]" if report["truncated"] else ""),
        title=f"RISK [{style}]{report['risk_score']}/100 {report['risk_label']}[/{style}]",
        border_style=style,
    ))

    table = Table(title="PII breakdown", show_header=True, header_style="bold cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Count", justify="right")
    table.add_column("Compliance", style="green")
    for row in report["breakdown"]:
        table.add_row(row["type"], str(row["count"]),
                      ",".join(row.get("compliance", [])))
    console.print(table if report["breakdown"] else "[green]No PII detected. File is clean.[/green]")

    summary = report.get("compliance_summary", {})
    if any(summary.values()):
        order = ("GDPR", "KVKK", "CCPA", "LGPD", "HIPAA")
        shown = [fw for fw in order if fw in summary] or sorted(summary)
        console.print(
            "[dim]Compliance exposure — "
            + " · ".join(f"{fw}: {summary.get(fw, 0)}" for fw in shown)
            + "[/dim]"
        )

    heat = report["heatmap"]
    htable = Table(title=f"Sensitivity heatmap ({heat['kind']})",
                   show_header=True, header_style="bold cyan")
    htable.add_column("Field")
    htable.add_column("Hits", justify="right")
    htable.add_column("Heat", justify="right")
    for item in heat["items"][:10]:
        bar = "#" * max(1, round(item["risk"] / 10)) if item["count"] else "-"
        htable.add_row(str(item["label"]).replace("\u2013", "-"), str(item["count"]), f"[red]{bar}[/red]")
    if heat["items"]:
        console.print(htable)

    pmode = report.get("preview_mode", "masked")
    for row in report["preview"][:3]:
        if pmode == "raw":
            console.print(Panel(f"[red]{row['raw']}[/red]\n[green]{row['clean']}[/green]",
                                title=f"line {row['line']} · raw → {mode} (raw exposed)",
                                border_style="dim"))
        else:
            console.print(Panel(f"[green]{row['clean']}[/green]",
                                title=f"line {row['line']} · masked preview ({mode})",
                                border_style="dim"))

    if output is not None:
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[dim]Full report written to {output}[/dim]")


@app.command()
def clean(
    file: Path = typer.Option(..., "--file", "-f", exists=True, dir_okay=False,
                              readable=True, help="File to decontaminate."),
    mode: str = typer.Option("mask", "--mode", "-m",
                             help=f"Sanitization mode: {', '.join(sorted(CLEAN_MODES))}."),
    salt: str | None = typer.Option(None, "--salt",
                                       help="HMAC salt (reuse for stable hashes)."),
    out: Path | None = typer.Option(None, "--out", "-o",
                                       help="Output path (default: <stem>.nukepii.<ext>)."),
    region: str = typer.Option("ALL", "--region", "-r",
                               help=f"Detector region filter: {', '.join(REGIONS)}."),
) -> None:
    """Sanitize FILE in a bounded-memory stream; write the cleaned copy."""
    if mode not in CLEAN_MODES:
        raise typer.BadParameter(f"mode must be one of {sorted(CLEAN_MODES)}.")
    if region.upper() not in REGIONS:
        raise typer.BadParameter(f"region must be one of {list(REGIONS)}.")
    dest = out or file.with_name(f"{file.stem}.nukepii{file.suffix}")
    streamer = DataStreamer()
    total_lines = _count_lines(file)
    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/cyan]"),
                      BarColumn(), TextColumn("{task.completed}/{task.total} lines"),
                      console=console) as progress:
            task = progress.add_task("Sanitizing", total=total_lines or 1)
            # sanitize_file runs single-pass internally; the spinner shows
            # activity while streaming, then the bar completes from its stats.
            stats = streamer.sanitize_file(str(file), str(dest), mode=mode, salt=salt,
                                             region=region.upper())
            progress.update(task, completed=stats["units"])
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None

    stable = Table(title="Decontamination complete", show_header=False)
    for key in ("units", "detections", "bytes_in", "bytes_out"):
        stable.add_row(key, str(stats[key]))
    stable.add_row("output", str(dest))
    console.print(stable)


@app.command()
def engines() -> None:
    """Show streaming-backend availability (polars / pandas / stdlib)."""
    caps = capabilities()
    table = Table(title="Streamer backends", show_header=True, header_style="bold cyan")
    table.add_column("Backend")
    table.add_column("Available", justify="center")
    for name in ("polars", "pandas", "stdlib", "native", "keccak",
                 "yaml_rules", "onnx_ner", "ocr", "parquet"):
        mark = "[green]yes[/green]" if caps.get(name) else "[red]no[/red]"
        table.add_row(name, mark)
    console.print(table)


@app.command(name="rules")
def rules_validate(
    path: Path = typer.Option(..., "--file", "-f", exists=True, dir_okay=False,
                              readable=True, help="YAML/JSON rules file to validate."),
) -> None:
    """Validate a custom rules file (Faz-1 regex-only MVP)."""
    from nukepii.core.rules import load_rules

    try:
        rules, errors = load_rules(path)
    except ImportError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    table = Table(title=f"Rules: {path.name}", show_header=True, header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Pattern")
    table.add_column("Conf", justify="right")
    for r in rules:
        table.add_row(r.id, r.pattern[:40], f"{r.confidence:.2f}")
    console.print(table if rules else "[yellow]No valid rules.[/yellow]")
    if errors:
        for e in errors:
            console.print(f"[red]ERR:[/red] {e}")
        raise typer.Exit(code=1)
    console.print(f"[green]{len(rules)} rules OK[/green]")


@app.command(name="scan-dir")
def scan_dir(
    dir: Path = typer.Option(..., "--dir", "-d", exists=True, file_okay=False,
                             readable=True, help="Directory to scan."),
    pattern: str = typer.Option("*.csv", "--pattern",
                                help="Glob pattern for files (e.g. *.csv)."),
    fail_on: str = typer.Option("NEVER", "--fail-on",
                                help="Risk label that fails the run (NEVER|LOW|MODERATE|HIGH|CRITICAL)."),
    mode: str = typer.Option("mask", "--mode", "-m", help="Preview sanitization mode."),
    region: str = typer.Option("ALL", "--region", "-r",
                               help=f"Detector region filter: {', '.join(REGIONS)}."),
) -> None:
    """Scan every file in DIR matching PATTERN; print per-file risk."""
    import fnmatch

    if mode not in CLEAN_MODES:
        raise typer.BadParameter(f"mode must be one of {sorted(CLEAN_MODES)}.")
    if region.upper() not in REGIONS:
        raise typer.BadParameter(f"region must be one of {list(REGIONS)}.")
    order = ("NEVER", "LOW", "MODERATE", "HIGH", "CRITICAL")
    fail_on = fail_on.upper()
    if fail_on not in order:
        raise typer.BadParameter(f"fail-on must be one of {list(order)}.")
    threshold = order.index(fail_on)
    streamer = DataStreamer()
    worst = 0
    found = 0
    for path in sorted(dir.rglob("*")):
        if not path.is_file() or not fnmatch.fnmatch(path.name, pattern):
            continue
        found += 1
        try:
            report = streamer.scan_file(str(path), mode=mode, region=region.upper())
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]Error:[/red] {path.name}: {exc}")
            continue
        console.print(f"{path.name}: {report['risk_score']}/100 "
                      f"{report['risk_label']} ({report['total_detections']} detections)")
        worst = max(worst, order.index(report["risk_label"]))
    if not found:
        console.print("[yellow]No files matched.[/yellow]")
    if threshold > 0 and worst >= threshold:
        raise typer.Exit(code=1)


@app.command(name="openapi")
def openapi_export(
    out: Path = typer.Option(..., "--out", "-o", help="Write OpenAPI JSON here."),
) -> None:
    """Export the HTTP API contract (same document as GET /api/openapi.json)."""
    from nukepii.web.openapi import build_openapi

    out.write_text(json.dumps(build_openapi(), indent=2), encoding="utf-8")
    console.print(f"[dim]OpenAPI written to {out}[/dim]")


def _count_lines(path: Path) -> int:
    """Fast binary line count for the progress bar (one cheap extra pass)."""
    count = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            count += chunk.count(b"\n")
    return count


if __name__ == "__main__":
    app()
