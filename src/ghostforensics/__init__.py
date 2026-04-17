"""GhostForensics — Memory forensics automation for incident response."""

__version__ = "0.1.0"

from ghostforensics.analyzer import (
    HandleAnalyzer,
    InjectionAnalyzer,
    NetworkAnalyzer,
    ProcessAnalyzer,
    YaraScanner,
)
from ghostforensics.ioc import IOCExtractor, ReputationChecker
from ghostforensics.models import ForensicsReport
from ghostforensics.report import ConsoleReporter, HTMLReporter, JSONReporter

# Convenience aliases matching the spec.
Analyzer = ProcessAnalyzer
Report = ForensicsReport

__all__ = [
    "Analyzer",
    "Report",
    "ConsoleReporter",
    "ForensicsReport",
    "HTMLReporter",
    "HandleAnalyzer",
    "IOCExtractor",
    "InjectionAnalyzer",
    "JSONReporter",
    "NetworkAnalyzer",
    "ProcessAnalyzer",
    "ReputationChecker",
    "YaraScanner",
]
