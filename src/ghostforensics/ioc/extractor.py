"""IOC (Indicator of Compromise) extraction from forensics analysis results."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ghostforensics.models import (
    IOC,
    Connection,
    Finding,
    ForensicsReport,
    IOCType,
    Process,
    Severity,
    YaraMatch,
)

# Regex patterns for IOC extraction.
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b"
)
_URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]}{,]+')
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_REGISTRY_PATTERN = re.compile(r'(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"\']+', re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Common false-positive domains and IPs to exclude.
_FP_DOMAINS = {
    "www.w3.org",
    "schemas.microsoft.com",
    "www.microsoft.com",
    "go.microsoft.com",
    "localhost",
    "example.com",
    "test.com",
    "schema.org",
    "purl.org",
    "ns.adobe.com",
}
_FP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _is_private_ip(addr: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_reserved or ip.is_loopback
    except ValueError:
        return False


class IOCExtractor:
    """Extracts and deduplicates IOCs from forensics analysis results.

    Scans process data, network connections, findings, and YARA matches
    for indicators such as IP addresses, domains, URLs, file hashes,
    registry keys, and email addresses.
    """

    def __init__(self, include_private_ips: bool = False):
        self._include_private = include_private_ips
        self._seen: set[tuple[str, str]] = set()  # (type, value) dedup

    def extract_from_report(self, report: ForensicsReport) -> list[IOC]:
        """Extract all IOCs from a complete forensics report."""
        self._seen.clear()
        iocs: list[IOC] = []

        iocs.extend(self._extract_from_processes(report.processes))
        iocs.extend(self._extract_from_connections(report.connections))
        iocs.extend(self._extract_from_findings(report.all_findings))
        iocs.extend(self._extract_from_yara(report.yara_matches))

        return iocs

    def extract_from_data(self, data: dict[str, Any]) -> list[IOC]:
        """Extract IOCs from raw analysis data dictionary."""
        self._seen.clear()
        iocs: list[IOC] = []

        # Extract from all string content in the data.
        text_blob = self._flatten_to_text(data)
        iocs.extend(self._extract_from_text(text_blob, source="raw_data"))

        # Extract structured IOCs.
        for proc in data.get("processes", []):
            cmdline = proc.get("cmdline", "")
            path = proc.get("path", "")
            iocs.extend(
                self._extract_from_text(
                    f"{cmdline} {path}", source=f"process:{proc.get('name', '')}"
                )
            )

        for conn in data.get("connections", []):
            remote = conn.get("remote_addr", "")
            if remote:
                iocs.extend(self._add_ip(remote, f"connection from PID {conn.get('pid', 0)}"))

        return iocs

    # -- Extraction from report components ---------------------------------

    def _extract_from_processes(self, processes: list[Process]) -> list[IOC]:
        """Extract IOCs from process command lines and paths."""
        iocs: list[IOC] = []
        for proc in processes:
            text = f"{proc.cmdline} {proc.path}"
            iocs.extend(self._extract_from_text(text, source=f"process:{proc.name}"))
        return iocs

    def _extract_from_connections(self, connections: list[Connection]) -> list[IOC]:
        """Extract IOCs from network connections."""
        iocs: list[IOC] = []
        for conn in connections:
            if conn.remote_addr:
                severity = Severity.HIGH if conn.suspicious else Severity.MEDIUM
                iocs.extend(
                    self._add_ip(
                        conn.remote_addr,
                        context=f"connection from {conn.process_name} (PID {conn.pid})",
                        severity=severity,
                    )
                )
        return iocs

    def _extract_from_findings(self, findings: list[Finding]) -> list[IOC]:
        """Extract IOCs from finding evidence and descriptions."""
        iocs: list[IOC] = []
        for finding in findings:
            text = f"{finding.description} {finding.title}"
            # Include evidence values.
            for v in finding.evidence.values():
                if isinstance(v, str):
                    text += f" {v}"
            iocs.extend(self._extract_from_text(text, source=f"finding:{finding.analyzer}"))
        return iocs

    def _extract_from_yara(self, yara_matches: list[YaraMatch]) -> list[IOC]:
        """Extract IOCs from YARA match data."""
        iocs: list[IOC] = []
        for ym in yara_matches:
            text = " ".join(ym.matched_strings)
            iocs.extend(self._extract_from_text(text, source=f"yara:{ym.rule_name}"))
        return iocs

    # -- Low-level extraction ----------------------------------------------

    def _extract_from_text(
        self, text: str, source: str = "", severity: Severity = Severity.MEDIUM
    ) -> list[IOC]:
        """Extract all IOC types from a text string."""
        iocs: list[IOC] = []

        # IPs
        for match in _IP_PATTERN.finditer(text):
            ip = match.group()
            iocs.extend(self._add_ip(ip, source, severity))

        # URLs (extract before domains to avoid double-counting).
        for match in _URL_PATTERN.finditer(text):
            url = match.group().rstrip(".,;:)")
            iocs.extend(self._add_ioc(IOCType.URL, url, source, severity))

        # Domains
        for match in _DOMAIN_PATTERN.finditer(text):
            domain = match.group().lower()
            if domain in _FP_DOMAINS:
                continue
            # Skip if it looks like a file extension or version number.
            if re.match(r"^\d+\.\d+\.\d+", domain):
                continue
            iocs.extend(self._add_ioc(IOCType.DOMAIN, domain, source, Severity.LOW))

        # SHA-256 (check before SHA-1 and MD5 to avoid substring matches).
        for match in _SHA256_PATTERN.finditer(text):
            iocs.extend(
                self._add_ioc(IOCType.FILE_HASH_SHA256, match.group().lower(), source, severity)
            )

        # SHA-1 (only if not part of a SHA-256).
        sha256_positions = {m.start() for m in _SHA256_PATTERN.finditer(text)}
        for match in _SHA1_PATTERN.finditer(text):
            if match.start() not in sha256_positions:
                iocs.extend(
                    self._add_ioc(IOCType.FILE_HASH_SHA1, match.group().lower(), source, severity)
                )

        # MD5
        sha1_positions = {m.start() for m in _SHA1_PATTERN.finditer(text)}
        for match in _MD5_PATTERN.finditer(text):
            if match.start() not in sha256_positions and match.start() not in sha1_positions:
                iocs.extend(
                    self._add_ioc(IOCType.FILE_HASH_MD5, match.group().lower(), source, severity)
                )

        # Registry keys
        for match in _REGISTRY_PATTERN.finditer(text):
            iocs.extend(self._add_ioc(IOCType.REGISTRY_KEY, match.group(), source, Severity.MEDIUM))

        # Emails
        for match in _EMAIL_PATTERN.finditer(text):
            iocs.extend(self._add_ioc(IOCType.EMAIL, match.group().lower(), source, Severity.LOW))

        return iocs

    def _add_ip(
        self,
        ip: str,
        context: str = "",
        severity: Severity = Severity.MEDIUM,
    ) -> list[IOC]:
        """Add an IP IOC with private-address filtering."""
        if ip in _FP_IPS:
            return []
        if not self._include_private and _is_private_ip(ip):
            return []
        return self._add_ioc(IOCType.IP_ADDRESS, ip, context, severity)

    def _add_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        context: str = "",
        severity: Severity = Severity.MEDIUM,
    ) -> list[IOC]:
        """Add an IOC with deduplication."""
        key = (ioc_type.value, value)
        if key in self._seen:
            return []
        self._seen.add(key)
        return [
            IOC(
                type=ioc_type,
                value=value,
                context=context,
                severity=severity,
                source_analyzer="ioc_extractor",
            )
        ]

    def _flatten_to_text(self, data: dict[str, Any], depth: int = 0) -> str:
        """Recursively flatten a dict to text for scanning."""
        if depth > 5:
            return ""
        parts: list[str] = []
        for v in data.values():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                parts.append(self._flatten_to_text(v, depth + 1))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.append(self._flatten_to_text(item, depth + 1))
        return " ".join(parts)

    @staticmethod
    def to_stix_bundle(iocs: list[IOC]) -> dict[str, Any]:
        """Export IOCs as a STIX 2.1 bundle."""
        return {
            "type": "bundle",
            "id": "bundle--ghostforensics-iocs",
            "objects": [ioc.to_stix_indicator() for ioc in iocs],
        }
