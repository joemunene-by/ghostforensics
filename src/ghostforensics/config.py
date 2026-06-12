"""Configuration management for GhostForensics."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AnalyzerConfig:
    """Configuration for analyzer modules."""

    enable_process_analysis: bool = True
    enable_network_analysis: bool = True
    enable_injection_analysis: bool = True
    enable_handle_analysis: bool = True
    enable_yara_scan: bool = True
    enable_ioc_extraction: bool = True


@dataclass
class YaraConfig:
    """Configuration for YARA scanning."""

    builtin_rules: bool = True
    custom_rules_dirs: list[str] = field(default_factory=list)
    timeout: int = 60
    max_strings_per_rule: int = 20000


@dataclass
class ReputationConfig:
    """Configuration for IOC reputation checking."""

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    enable_online_checks: bool = False
    cache_ttl_hours: int = 24


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    output_format: str = "html"  # html, json, console
    include_evidence: bool = True
    include_remediation: bool = True
    include_mitre: bool = True
    max_iocs_displayed: int = 500


# Well-known system processes on Windows and their expected parent relationships.
KNOWN_SYSTEM_PROCESSES: dict[str, dict[str, Any]] = {
    "system": {"expected_pid": 4, "expected_ppid": 0},
    "smss.exe": {"expected_ppid_name": "system"},
    "csrss.exe": {"expected_ppid_name": "smss.exe"},
    "wininit.exe": {"expected_ppid_name": "smss.exe"},
    "winlogon.exe": {"expected_ppid_name": "smss.exe"},
    "services.exe": {"expected_ppid_name": "wininit.exe"},
    "lsass.exe": {"expected_ppid_name": "wininit.exe", "expected_count": 1},
    "svchost.exe": {"expected_ppid_name": "services.exe"},
    "explorer.exe": {"expected_ppid_name": "userinit.exe"},
}

# Suspicious process names that often indicate malware.
SUSPICIOUS_PROCESS_NAMES: list[str] = [
    "mimikatz",
    "procdump",
    "psexec",
    "cobalt",
    "beacon",
    "meterpreter",
    "nc.exe",
    "ncat.exe",
    "powershell_ise",
    "certutil",
    "bitsadmin",
    "mshta",
    "wscript",
    "cscript",
    "regsvr32",
    "rundll32",
    "msiexec",
]

# Ports commonly used by malware.
SUSPICIOUS_PORTS: set[int] = {
    4444,  # Metasploit default
    5555,  # Android debug / backdoors
    1337,  # Common backdoor
    31337,  # Back Orifice
    8080,  # Common C2
    8443,  # Common C2
    6666,  # IRC backdoor
    6667,  # IRC
    6697,  # IRC SSL
    9001,  # Tor
    9050,  # Tor SOCKS
    9150,  # Tor Browser
    3389,  # RDP (suspicious if outbound)
    5900,  # VNC
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    1080,  # SOCKS proxy
    12345,  # NetBus
    54321,  # Backdoors
}

# Known-bad mutex names associated with malware families.
SUSPICIOUS_MUTEX_PATTERNS: list[str] = [
    "Global\\MSCTFMonitor",
    "IESQMMUTEX",
    "c:!documents",
    "WininetStartupMutex",
    "shell.{",
    "MUTEX_RUNNING",
    "ZoNeAlArM",
    "Jp2Global",
    "PERSIST",
    "_SHuassist",
]

# Sensitive file paths that might indicate credential harvesting.
SENSITIVE_FILE_PATHS: list[str] = [
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\system",
    "\\windows\\system32\\config\\security",
    "\\windows\\ntds\\ntds.dit",
    "\\windows\\repair\\sam",
    ".ssh\\id_rsa",
    ".ssh\\known_hosts",
    "\\appdata\\roaming\\mozilla\\firefox\\profiles",
    "\\appdata\\local\\google\\chrome\\user data\\default\\login data",
    "\\appdata\\local\\microsoft\\credentials",
]

PACKAGE_ROOT = Path(__file__).resolve().parent
RULES_DIR = PACKAGE_ROOT / "rules"
TEMPLATES_DIR = PACKAGE_ROOT / "templates"


@dataclass
class Settings:
    """Top-level settings container."""

    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> Settings:
        """Load settings from a YAML config file."""
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        settings = cls()
        if "analyzer" in data:
            settings.analyzer = AnalyzerConfig(**data["analyzer"])
        if "yara" in data:
            settings.yara = YaraConfig(**data["yara"])
        if "reputation" in data:
            rep_data = data["reputation"]
            # Allow environment variable overrides for API keys.
            rep_data.setdefault("virustotal_api_key", os.environ.get("VT_API_KEY", ""))
            rep_data.setdefault("abuseipdb_api_key", os.environ.get("ABUSEIPDB_API_KEY", ""))
            settings.reputation = ReputationConfig(**rep_data)
        if "report" in data:
            settings.report = ReportConfig(**data["report"])
        return settings

    @classmethod
    def default(cls) -> Settings:
        return cls()
