"""Typer CLI for GhostForensics."""

from __future__ import annotations

import datetime
import json
import time
from pathlib import Path

import typer
from rich.console import Console

from ghostforensics.analyzer.handles import HandleAnalyzer
from ghostforensics.analyzer.injection import InjectionAnalyzer
from ghostforensics.analyzer.network import NetworkAnalyzer
from ghostforensics.analyzer.process import ProcessAnalyzer
from ghostforensics.analyzer.yara_scanner import YaraScanner
from ghostforensics.config import Settings
from ghostforensics.ioc.extractor import IOCExtractor
from ghostforensics.ioc.reputation import ReputationChecker
from ghostforensics.models import ForensicsReport
from ghostforensics.report.console import ConsoleReporter
from ghostforensics.report.html import HTMLReporter
from ghostforensics.report.json_report import JSONReporter

app = typer.Typer(
    name="ghostforensics",
    help="GhostForensics — Memory forensics automation for incident response.",
    add_completion=False,
)
console = Console()


def _load_dump(dump_path: str) -> dict:
    """Load a memory dump file (JSON format or raw)."""
    p = Path(dump_path)
    if not p.exists():
        console.print(f"[red]Error: file not found: {dump_path}[/red]")
        raise typer.Exit(1)

    if p.suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        data.setdefault("dump_path", str(p))
        return data

    # For raw dump files, pass path for Volatility3 backend.
    return {"dump_path": str(p)}


def _run_full_analysis(data: dict, settings: Settings) -> ForensicsReport:
    """Run all analyzers and produce a complete report."""
    start = time.time()

    proc_analyzer = ProcessAnalyzer()
    net_analyzer = NetworkAnalyzer()
    inj_analyzer = InjectionAnalyzer()
    handle_analyzer = HandleAnalyzer()
    yara_scanner = YaraScanner(settings)
    ioc_extractor = IOCExtractor()

    processes = proc_analyzer.extract_processes(data)
    connections = net_analyzer.extract_connections(data)

    proc_findings = proc_analyzer.analyze(data)
    net_findings = net_analyzer.analyze(data)
    inj_findings = inj_analyzer.extract_injection_findings(data)
    handle_findings = handle_analyzer.extract_handle_findings(data)
    yara_matches = yara_scanner.scan(data)

    # Generic findings (process + network).
    findings = proc_findings + net_findings

    report = ForensicsReport(
        dump_path=data.get("dump_path", "unknown"),
        analysis_time=datetime.datetime.now(datetime.UTC).isoformat(),
        os_profile=data.get("os_profile", ""),
        processes=processes,
        connections=connections,
        findings=findings,
        injection_findings=inj_findings,
        handle_findings=handle_findings,
        yara_matches=yara_matches,
    )

    # Extract IOCs from the report.
    report.iocs = ioc_extractor.extract_from_report(report)

    # Reputation checks.
    rep_checker = ReputationChecker(settings.reputation)
    if rep_checker.online_enabled:
        rep_results = rep_checker.check_batch(report.iocs)
        for ioc in report.iocs:
            if ioc.value in rep_results:
                ReputationChecker.update_ioc_severity(ioc, rep_results[ioc.value])

    report.duration_seconds = time.time() - start
    return report


@app.command()
def analyze(
    dump_path: str = typer.Argument(
        help="Path to memory dump file (.raw, .dmp, .vmem, or .json)",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output report file path (.html or .json)",
    ),
    config: str | None = typer.Option(
        None, "--config", "-c", help="Path to config YAML file",
    ),
    format: str = typer.Option(
        "console", "--format", "-f", help="Output format: console, html, json",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress console output"),
) -> None:
    """Analyze a memory dump and generate a forensics report."""
    settings = Settings.from_file(config) if config else Settings.default()
    data = _load_dump(dump_path)

    if not quiet:
        console.print(f"[bold blue]Analyzing:[/bold blue] {dump_path}")

    report = _run_full_analysis(data, settings)

    # Console output.
    if not quiet:
        ConsoleReporter(console).render(report)

    # File output.
    if output:
        out_path = Path(output)
        if out_path.suffix == ".json" or format == "json":
            JSONReporter().write(report, out_path)
        else:
            HTMLReporter().write(report, out_path)
        if not quiet:
            console.print(f"[green]Report written to:[/green] {out_path}")


@app.command()
def processes(
    dump_path: str = typer.Argument(help="Path to memory dump file"),
) -> None:
    """List processes and detect anomalies."""
    data = _load_dump(dump_path)
    analyzer = ProcessAnalyzer()
    procs = analyzer.extract_processes(data)
    findings = analyzer.analyze(data)

    console.print(f"[bold]Processes: {len(procs)}[/bold]")
    for proc in procs:
        style = "red" if proc.is_suspicious else ""
        flags = (
            f" [red]<< {', '.join(proc.suspicious_flags)}[/red]"
            if proc.suspicious_flags
            else ""
        )
        console.print(
            f"  [{style}]PID {proc.pid:>6} | PPID {proc.ppid:>6}"
            f" | {proc.name}{flags}[/{style}]"
        )

    if findings:
        console.print(f"\n[bold red]Findings: {len(findings)}[/bold red]")
        for f in findings:
            console.print(f"  [{f.severity.value}] {f.title}")


@app.command()
def network(
    dump_path: str = typer.Argument(help="Path to memory dump file"),
) -> None:
    """List network connections and detect anomalies."""
    data = _load_dump(dump_path)
    analyzer = NetworkAnalyzer()
    conns = analyzer.extract_connections(data)
    findings = analyzer.analyze(data)

    console.print(f"[bold]Connections: {len(conns)}[/bold]")
    for conn in conns:
        style = "red" if conn.suspicious else ""
        console.print(
            f"  [{style}]PID {conn.pid:>6} | {conn.process_name:<20} | "
            f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port} "
            f"| {conn.state}[/{style}]"
        )

    if findings:
        console.print(f"\n[bold red]Findings: {len(findings)}[/bold red]")
        for f in findings:
            console.print(f"  [{f.severity.value}] {f.title}")


@app.command(name="yara")
def yara_scan(
    dump_path: str = typer.Argument(help="Path to memory dump file"),
    rules_dir: str | None = typer.Option(None, "--rules", "-r", help="Custom YARA rules directory"),
) -> None:
    """Scan memory dump with YARA rules."""
    settings = Settings.default()
    if rules_dir:
        settings.yara.custom_rules_dirs.append(rules_dir)

    data = _load_dump(dump_path)
    scanner = YaraScanner(settings)
    matches = scanner.scan(data)

    console.print(f"[bold]YARA Matches: {len(matches)}[/bold]")
    for m in matches:
        console.print(
            f"  [{m.severity.value}] {m.rule_name} — PID {m.pid} ({m.process_name})"
        )
        if m.matched_strings:
            console.print(f"    Strings: {', '.join(m.matched_strings[:5])}")


@app.command()
def ioc(
    dump_path: str = typer.Argument(help="Path to memory dump file"),
    stix: bool = typer.Option(False, "--stix", help="Output in STIX 2.1 bundle format"),
) -> None:
    """Extract IOCs from a memory dump analysis."""
    data = _load_dump(dump_path)
    settings = Settings.default()
    report = _run_full_analysis(data, settings)

    if stix:
        bundle = IOCExtractor.to_stix_bundle(report.iocs)
        console.print_json(json.dumps(bundle, indent=2, default=str))
    else:
        console.print(f"[bold]IOCs Extracted: {len(report.iocs)}[/bold]")
        for i in report.iocs:
            console.print(f"  [{i.severity.value}] {i.type.value}: {i.value} — {i.context}")


@app.command()
def report(
    dump_path: str = typer.Argument(help="Path to memory dump file"),
    output: str = typer.Option("report.html", "--output", "-o", help="Output file path"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, json"),
) -> None:
    """Generate a full forensics report."""
    settings = Settings.default()
    data = _load_dump(dump_path)

    console.print("[bold blue]Generating report...[/bold blue]")
    forensics_report = _run_full_analysis(data, settings)

    out_path = Path(output)
    if format == "json" or out_path.suffix == ".json":
        JSONReporter().write(forensics_report, out_path)
    else:
        HTMLReporter().write(forensics_report, out_path)

    console.print(f"[green]Report written to:[/green] {out_path}")
    console.print(
        f"  Findings: {len(forensics_report.all_findings)} | "
        f"IOCs: {len(forensics_report.iocs)} | "
        f"YARA: {len(forensics_report.yara_matches)}"
    )
