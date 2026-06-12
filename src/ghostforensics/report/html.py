"""HTML report generation with Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ghostforensics.config import TEMPLATES_DIR
from ghostforensics.models import ForensicsReport, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH: "#ff8800",
    Severity.MEDIUM: "#ffcc00",
    Severity.LOW: "#44bbff",
    Severity.INFO: "#888888",
}


class HTMLReporter:
    """Generate an HTML forensics report."""

    def __init__(self, template_dir: str | Path | None = None):
        tdir = Path(template_dir) if template_dir else TEMPLATES_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(tdir)),
            autoescape=True,
        )
        self._env.filters["severity_color"] = lambda s: _SEVERITY_COLORS.get(s, "#ffffff")

    def render(self, report: ForensicsReport) -> str:
        """Render the report as an HTML string."""
        template = self._env.get_template("report.html")
        return template.render(
            report=report,
            severity_colors=_SEVERITY_COLORS,
            Severity=Severity,
        )

    def write(self, report: ForensicsReport, output_path: str | Path) -> None:
        """Write the HTML report to a file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report))
