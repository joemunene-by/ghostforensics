"""JSON report export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostforensics.ioc.extractor import IOCExtractor
from ghostforensics.models import ForensicsReport


class JSONReporter:
    """Export a ForensicsReport as JSON."""

    def render(self, report: ForensicsReport) -> str:
        """Render the report as a JSON string."""
        return json.dumps(self._to_dict(report), indent=2, default=str)

    def write(self, report: ForensicsReport, output_path: str | Path) -> None:
        """Write the report to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report))

    def _to_dict(self, report: ForensicsReport) -> dict[str, Any]:
        """Convert report to a serialisable dictionary."""
        stix_bundle = IOCExtractor.to_stix_bundle(report.iocs)

        return {
            "meta": {
                "tool": "GhostForensics",
                "version": "0.1.0",
                "dump_path": report.dump_path,
                "analysis_time": report.analysis_time,
                "duration_seconds": report.duration_seconds,
                "os_profile": report.os_profile,
            },
            "summary": {
                "total_findings": len(report.all_findings),
                "severity": report.severity_summary,
                "process_count": len(report.processes),
                "suspicious_processes": len(report.suspicious_processes),
                "connection_count": len(report.connections),
                "suspicious_connections": len(report.suspicious_connections),
                "yara_matches": len(report.yara_matches),
                "ioc_count": len(report.iocs),
            },
            "findings": [f.model_dump() for f in report.all_findings],
            "processes": [p.model_dump() for p in report.processes],
            "connections": [c.model_dump() for c in report.connections],
            "injection_findings": [f.model_dump() for f in report.injection_findings],
            "handle_findings": [f.model_dump() for f in report.handle_findings],
            "yara_matches": [y.model_dump() for y in report.yara_matches],
            "iocs": [i.model_dump() for i in report.iocs],
            "stix_bundle": stix_bundle,
        }
