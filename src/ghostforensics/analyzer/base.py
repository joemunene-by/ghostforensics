"""Base analyzer abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ghostforensics.models import Finding


class BaseAnalyzer(ABC):
    """Abstract base class for all forensics analyzers."""

    name: str = "base"

    @abstractmethod
    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Run the analysis and return findings.

        Args:
            data: Parsed memory dump data (JSON format or Volatility3 output).

        Returns:
            List of Finding objects describing suspicious activity.
        """

    def _make_finding(
        self,
        title: str,
        description: str,
        severity: str,
        evidence: dict[str, Any] | None = None,
        remediation: str = "",
        mitre_attack: list[str] | None = None,
    ) -> Finding:
        """Helper to create a Finding with this analyzer's name."""
        from ghostforensics.models import Severity

        return Finding(
            title=title,
            description=description,
            severity=Severity(severity),
            analyzer=self.name,
            evidence=evidence or {},
            remediation=remediation,
            mitre_attack=mitre_attack or [],
        )
