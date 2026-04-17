"""Rich console output for forensics reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ghostforensics.models import ForensicsReport, Severity


_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
    Severity.INFO: "[i]",
}


class ConsoleReporter:
    """Renders a ForensicsReport to the terminal using Rich."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def render(self, report: ForensicsReport) -> None:
        """Render the full report to the console."""
        self._render_header(report)
        self._render_severity_summary(report)
        self._render_findings(report)
        self._render_process_tree(report)
        self._render_connections(report)
        self._render_yara_matches(report)
        self._render_iocs(report)
        self._render_footer(report)

    def _render_header(self, report: ForensicsReport) -> None:
        header = Text()
        header.append("GhostForensics Analysis Report\n", style="bold white")
        header.append(f"Dump: {report.dump_path}\n", style="dim")
        header.append(f"Time: {report.analysis_time}\n", style="dim")
        header.append(f"Duration: {report.duration_seconds:.2f}s\n", style="dim")
        if report.os_profile:
            header.append(f"Profile: {report.os_profile}\n", style="dim")
        self.console.print(Panel(header, title="[bold]Analysis Summary[/bold]", border_style="blue"))

    def _render_severity_summary(self, report: ForensicsReport) -> None:
        summary = report.severity_summary
        if not summary:
            return
        table = Table(title="Finding Severity Distribution", show_lines=False)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in Severity:
            count = summary.get(sev.value, 0)
            if count > 0:
                table.add_row(
                    Text(sev.value.upper(), style=_SEVERITY_COLORS[sev]),
                    str(count),
                )
        self.console.print(table)
        self.console.print()

    def _render_findings(self, report: ForensicsReport) -> None:
        findings = report.all_findings
        if not findings:
            self.console.print("[green]No suspicious findings detected.[/green]")
            return

        # Sort by severity.
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        self.console.print(Panel("[bold]Findings[/bold]", border_style="red"))
        for finding in findings:
            color = _SEVERITY_COLORS.get(finding.severity, "white")
            icon = _SEVERITY_ICONS.get(finding.severity, "[?]")
            self.console.print(
                f"  [{color}]{icon} {finding.title}[/{color}]"
            )
            self.console.print(f"      {finding.description}", style="dim")
            if finding.remediation:
                self.console.print(f"      Remediation: {finding.remediation}", style="green")
            if finding.mitre_attack:
                self.console.print(
                    f"      MITRE ATT&CK: {', '.join(finding.mitre_attack)}", style="dim cyan"
                )
            self.console.print()

    def _render_process_tree(self, report: ForensicsReport) -> None:
        if not report.processes:
            return

        self.console.print(Panel("[bold]Process Tree[/bold]", border_style="blue"))

        pid_map = {p.pid: p for p in report.processes}
        children_map: dict[int, list[int]] = {}
        roots: list[int] = []

        for proc in report.processes:
            if proc.ppid in pid_map:
                children_map.setdefault(proc.ppid, []).append(proc.pid)
            else:
                roots.append(proc.pid)

        tree = Tree("[bold]Processes[/bold]")
        for root_pid in roots:
            self._add_tree_node(tree, root_pid, pid_map, children_map)
        self.console.print(tree)
        self.console.print()

    def _add_tree_node(
        self,
        parent: Tree,
        pid: int,
        pid_map: dict[int, object],
        children_map: dict[int, list[int]],
    ) -> None:
        proc = pid_map.get(pid)
        if proc is None:
            return
        style = "bold red" if proc.is_suspicious else ""  # type: ignore[union-attr]
        label = f"[{style}]{proc.name} (PID {proc.pid})[/{style}]"  # type: ignore[union-attr]
        if proc.is_suspicious:  # type: ignore[union-attr]
            label += f" [red]<< {', '.join(proc.suspicious_flags)}[/red]"  # type: ignore[union-attr]
        node = parent.add(label)
        for child_pid in children_map.get(pid, []):
            self._add_tree_node(node, child_pid, pid_map, children_map)

    def _render_connections(self, report: ForensicsReport) -> None:
        if not report.connections:
            return

        self.console.print(Panel("[bold]Network Connections[/bold]", border_style="blue"))
        table = Table(show_lines=False)
        table.add_column("PID", justify="right")
        table.add_column("Process")
        table.add_column("Local")
        table.add_column("Remote")
        table.add_column("State")
        table.add_column("Flags")

        for conn in report.connections:
            style = "red" if conn.suspicious else ""
            flags = ", ".join(conn.suspicious_reasons) if conn.suspicious_reasons else ""
            table.add_row(
                str(conn.pid),
                conn.process_name,
                f"{conn.local_addr}:{conn.local_port}",
                f"{conn.remote_addr}:{conn.remote_port}",
                conn.state,
                flags,
                style=style,
            )
        self.console.print(table)
        self.console.print()

    def _render_yara_matches(self, report: ForensicsReport) -> None:
        if not report.yara_matches:
            return
        self.console.print(Panel("[bold]YARA Matches[/bold]", border_style="yellow"))
        for ym in report.yara_matches:
            color = _SEVERITY_COLORS.get(ym.severity, "white")
            self.console.print(
                f"  [{color}]Rule: {ym.rule_name}[/{color}] "
                f"(PID {ym.pid}, {ym.process_name})"
            )
            if ym.description:
                self.console.print(f"      {ym.description}", style="dim")
            if ym.matched_strings:
                self.console.print(
                    f"      Matched: {', '.join(ym.matched_strings[:5])}", style="dim"
                )
        self.console.print()

    def _render_iocs(self, report: ForensicsReport) -> None:
        if not report.iocs:
            return
        self.console.print(Panel("[bold]Extracted IOCs[/bold]", border_style="magenta"))
        table = Table(show_lines=False)
        table.add_column("Type")
        table.add_column("Value")
        table.add_column("Severity")
        table.add_column("Context")

        for ioc in report.iocs[:100]:  # Limit display.
            color = _SEVERITY_COLORS.get(ioc.severity, "white")
            table.add_row(
                ioc.type.value,
                ioc.value,
                Text(ioc.severity.value, style=color),
                ioc.context[:60],
            )
        self.console.print(table)
        if len(report.iocs) > 100:
            self.console.print(
                f"  ... and {len(report.iocs) - 100} more IOCs", style="dim"
            )
        self.console.print()

    def _render_footer(self, report: ForensicsReport) -> None:
        total = len(report.all_findings)
        self.console.print(
            Panel(
                f"Total findings: {total} | "
                f"Critical: {report.critical_count} | "
                f"High: {report.high_count} | "
                f"IOCs: {len(report.iocs)} | "
                f"YARA matches: {len(report.yara_matches)}",
                title="[bold]Summary[/bold]",
                border_style="green" if total == 0 else "red",
            )
        )
