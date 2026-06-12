"""Data models for GhostForensics findings and reports."""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOCType(str, Enum):
    """Indicator of Compromise types."""

    IP_ADDRESS = "ip-address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file-hash-md5"
    FILE_HASH_SHA1 = "file-hash-sha1"
    FILE_HASH_SHA256 = "file-hash-sha256"
    REGISTRY_KEY = "registry-key"
    EMAIL = "email"
    MUTEX = "mutex"
    FILE_PATH = "file-path"


class Process(BaseModel):
    """Represents a process extracted from a memory dump."""

    pid: int
    ppid: int
    name: str
    path: str = ""
    cmdline: str = ""
    create_time: str = ""
    exit_time: str = ""
    threads: int = 0
    handles: int = 0
    suspicious_flags: list[str] = Field(default_factory=list)
    children: list[int] = Field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return len(self.suspicious_flags) > 0


class Connection(BaseModel):
    """Represents a network connection extracted from memory."""

    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str = "UNKNOWN"
    protocol: str = "TCP"
    pid: int = 0
    process_name: str = ""
    suspicious: bool = False
    suspicious_reasons: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Base finding from any analyzer."""

    title: str
    description: str
    severity: Severity
    analyzer: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    mitre_attack: list[str] = Field(default_factory=list)


class InjectionFinding(Finding):
    """Finding related to code injection detection."""

    injection_type: str = ""  # hollowing, dll_injection, rwx_memory
    target_pid: int = 0
    target_process: str = ""
    injected_region_addr: str = ""
    injected_region_size: int = 0


class HandleFinding(Finding):
    """Finding related to suspicious handle patterns."""

    handle_type: str = ""  # mutex, file, registry, process
    handle_name: str = ""
    owner_pid: int = 0
    owner_process: str = ""


class YaraMatch(BaseModel):
    """A YARA rule match in memory."""

    rule_name: str
    rule_file: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    pid: int = 0
    process_name: str = ""
    offset: int = 0
    matched_strings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IOC(BaseModel):
    """Indicator of Compromise extracted from analysis."""

    type: IOCType
    value: str
    context: str = ""
    severity: Severity = Severity.MEDIUM
    source_analyzer: str = ""
    first_seen: str = ""
    tags: list[str] = Field(default_factory=list)

    def to_stix_indicator(self) -> dict[str, Any]:
        """Export as a STIX-like indicator object."""
        pattern_type_map = {
            IOCType.IP_ADDRESS: f"[ipv4-addr:value = '{self.value}']",
            IOCType.DOMAIN: f"[domain-name:value = '{self.value}']",
            IOCType.URL: f"[url:value = '{self.value}']",
            IOCType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{self.value}']",
            IOCType.FILE_HASH_SHA1: f"[file:hashes.'SHA-1' = '{self.value}']",
            IOCType.FILE_HASH_SHA256: f"[file:hashes.'SHA-256' = '{self.value}']",
            IOCType.EMAIL: f"[email-addr:value = '{self.value}']",
            IOCType.REGISTRY_KEY: f"[windows-registry-key:key = '{self.value}']",
            IOCType.MUTEX: f"[mutex:name = '{self.value}']",
            IOCType.FILE_PATH: f"[file:name = '{self.value}']",
        }
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "pattern_type": "stix",
            "pattern": pattern_type_map.get(self.type, f"[artifact:payload_bin = '{self.value}']"),
            "name": f"{self.type.value}: {self.value}",
            "description": self.context,
            "indicator_types": ["malicious-activity"],
            "valid_from": self.first_seen
            or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "labels": self.tags,
            "custom_properties": {
                "x_severity": self.severity.value,
                "x_source_analyzer": self.source_analyzer,
            },
        }


class ForensicsReport(BaseModel):
    """Aggregated forensics analysis report."""

    dump_path: str
    analysis_time: str = ""
    duration_seconds: float = 0.0
    os_profile: str = ""

    processes: list[Process] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    injection_findings: list[InjectionFinding] = Field(default_factory=list)
    handle_findings: list[HandleFinding] = Field(default_factory=list)
    yara_matches: list[YaraMatch] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

    @property
    def suspicious_processes(self) -> list[Process]:
        return [p for p in self.processes if p.is_suspicious]

    @property
    def suspicious_connections(self) -> list[Connection]:
        return [c for c in self.connections if c.suspicious]

    @property
    def all_findings(self) -> list[Finding]:
        combined: list[Finding] = list(self.findings)
        combined.extend(self.injection_findings)
        combined.extend(self.handle_findings)
        for ym in self.yara_matches:
            combined.append(
                Finding(
                    title=f"YARA Match: {ym.rule_name}",
                    description=ym.description,
                    severity=ym.severity,
                    analyzer="yara_scanner",
                    evidence={"matched_strings": ym.matched_strings, "pid": ym.pid},
                )
            )
        return combined

    @property
    def severity_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
