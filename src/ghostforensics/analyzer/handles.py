"""Handle analysis module — detects suspicious handle patterns."""

from __future__ import annotations

import logging
from typing import Any

from ghostforensics.analyzer.base import BaseAnalyzer
from ghostforensics.config import SENSITIVE_FILE_PATHS, SUSPICIOUS_MUTEX_PATTERNS
from ghostforensics.models import Finding, HandleFinding, Severity

logger = logging.getLogger(__name__)


class HandleAnalyzer(BaseAnalyzer):
    """Analyzes process handles for suspicious patterns.

    Checks:
    - Known-bad mutex names (malware families)
    - File handles to sensitive system files (SAM, NTDS.dit, etc.)
    - Suspicious registry key access
    - Cross-process handle access patterns
    """

    name = "handle_analyzer"

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Analyze handle data and return findings."""
        findings: list[Finding] = []

        findings.extend(self._detect_suspicious_mutexes(data))
        findings.extend(self._detect_sensitive_file_access(data))
        findings.extend(self._detect_suspicious_registry_access(data))
        findings.extend(self._detect_cross_process_handles(data))

        return findings

    def extract_handle_findings(self, data: dict[str, Any]) -> list[HandleFinding]:
        """Return typed HandleFinding objects."""
        raw_findings = self.analyze(data)
        handle_findings: list[HandleFinding] = []
        for f in raw_findings:
            handle_findings.append(
                HandleFinding(
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    analyzer=f.analyzer,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    mitre_attack=f.mitre_attack,
                    handle_type=f.evidence.get("handle_type", ""),
                    handle_name=f.evidence.get("handle_name", ""),
                    owner_pid=f.evidence.get("pid", 0),
                    owner_process=f.evidence.get("process_name", ""),
                )
            )
        return handle_findings

    # -- Detection methods -------------------------------------------------

    def _detect_suspicious_mutexes(self, data: dict[str, Any]) -> list[Finding]:
        """Detect mutexes matching known malware families."""
        findings: list[Finding] = []
        for handle in data.get("handles", []):
            if handle.get("type", "").lower() != "mutant":
                continue
            mutex_name = handle.get("name", "")
            if not mutex_name:
                continue
            mutex_lower = mutex_name.lower()
            for pattern in SUSPICIOUS_MUTEX_PATTERNS:
                if pattern.lower() in mutex_lower:
                    findings.append(
                        self._make_finding(
                            title=(
                                f"Suspicious mutex: '{mutex_name}' in "
                                f"{handle.get('process_name', 'unknown')} "
                                f"(PID {handle.get('pid', 0)})"
                            ),
                            description=(
                                f"Mutex '{mutex_name}' matches known malware pattern "
                                f"'{pattern}'. This mutex is associated with malware "
                                "families and may indicate an active infection."
                            ),
                            severity=Severity.HIGH.value,
                            evidence={
                                "handle_type": "mutex",
                                "handle_name": mutex_name,
                                "pid": handle.get("pid", 0),
                                "process_name": handle.get("process_name", ""),
                                "matched_pattern": pattern,
                            },
                            remediation=(
                                "Investigate the owning process. Scan with AV/EDR. "
                                "Search threat intel for the mutex name."
                            ),
                            mitre_attack=["T1106"],  # Native API
                        )
                    )
                    break
        return findings

    def _detect_sensitive_file_access(self, data: dict[str, Any]) -> list[Finding]:
        """Detect handles to sensitive system files."""
        findings: list[Finding] = []
        for handle in data.get("handles", []):
            if handle.get("type", "").lower() != "file":
                continue
            file_name = handle.get("name", "")
            if not file_name:
                continue
            file_lower = file_name.lower()
            for sensitive_path in SENSITIVE_FILE_PATHS:
                if sensitive_path.lower() in file_lower:
                    # Legitimate access by SYSTEM process is expected.
                    proc_name = handle.get("process_name", "").lower()
                    if proc_name in ("system", "lsass.exe", "svchost.exe"):
                        continue
                    findings.append(
                        self._make_finding(
                            title=(
                                f"Sensitive file access: {handle.get('process_name', 'unknown')} "
                                f"accessing {sensitive_path}"
                            ),
                            description=(
                                f"Process '{handle.get('process_name', 'unknown')}' "
                                f"(PID {handle.get('pid', 0)}) has an open handle to "
                                f"'{file_name}'. This file contains sensitive security data."
                            ),
                            severity=Severity.CRITICAL.value,
                            evidence={
                                "handle_type": "file",
                                "handle_name": file_name,
                                "pid": handle.get("pid", 0),
                                "process_name": handle.get("process_name", ""),
                                "sensitive_path": sensitive_path,
                            },
                            remediation=(
                                "Immediately investigate credential harvesting. Check for "
                                "tools like mimikatz, secretsdump, or ntdsutil."
                            ),
                            mitre_attack=["T1003"],  # OS Credential Dumping
                        )
                    )
                    break
        return findings

    def _detect_suspicious_registry_access(self, data: dict[str, Any]) -> list[Finding]:
        """Detect handles to suspicious registry keys."""
        findings: list[Finding] = []
        suspicious_keys = [
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\winlogon",
            "\\services\\",
            "\\currentcontrolset\\services",
            "\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
            "\\sam\\sam\\domains\\account",
        ]
        for handle in data.get("handles", []):
            if handle.get("type", "").lower() not in ("key", "registry"):
                continue
            key_name = handle.get("name", "")
            if not key_name:
                continue
            key_lower = key_name.lower()
            for suspicious_key in suspicious_keys:
                if suspicious_key in key_lower:
                    proc_name = handle.get("process_name", "").lower()
                    if proc_name in ("services.exe", "svchost.exe", "explorer.exe", "regedit.exe"):
                        continue
                    findings.append(
                        self._make_finding(
                            title=(
                                f"Suspicious registry access: "
                                f"{handle.get('process_name', 'unknown')} "
                                f"accessing {suspicious_key}"
                            ),
                            description=(
                                f"Process '{handle.get('process_name', 'unknown')}' "
                                f"(PID {handle.get('pid', 0)}) has a handle to registry key "
                                f"'{key_name}'. This key is often targeted for persistence."
                            ),
                            severity=Severity.MEDIUM.value,
                            evidence={
                                "handle_type": "registry",
                                "handle_name": key_name,
                                "pid": handle.get("pid", 0),
                                "process_name": handle.get("process_name", ""),
                                "suspicious_key": suspicious_key,
                            },
                            remediation=(
                                "Check if the registry modification is legitimate. "
                                "Review autorun entries for persistence."
                            ),
                            mitre_attack=["T1547.001"],  # Registry Run Keys
                        )
                    )
                    break
        return findings

    def _detect_cross_process_handles(self, data: dict[str, Any]) -> list[Finding]:
        """Detect suspicious cross-process handle access."""
        findings: list[Finding] = []
        for entry in data.get("cross_process_handles", []):
            source_pid = entry.get("source_pid", 0)
            source_name = entry.get("source_name", "unknown")
            target_pid = entry.get("target_pid", 0)
            target_name = entry.get("target_name", "unknown")
            access_rights = entry.get("access_rights", "")

            # High-privilege access to sensitive processes is suspicious.
            sensitive_targets = {"lsass.exe", "csrss.exe", "winlogon.exe"}
            if target_name.lower() in sensitive_targets:
                findings.append(
                    self._make_finding(
                        title=(f"Cross-process access: {source_name} -> {target_name}"),
                        description=(
                            f"Process '{source_name}' (PID {source_pid}) has a handle to "
                            f"'{target_name}' (PID {target_pid}) with access rights: "
                            f"{access_rights}. This may indicate credential dumping or "
                            "process manipulation."
                        ),
                        severity=Severity.CRITICAL.value,
                        evidence={
                            "handle_type": "process",
                            "handle_name": target_name,
                            "pid": source_pid,
                            "process_name": source_name,
                            "target_pid": target_pid,
                            "target_name": target_name,
                            "access_rights": access_rights,
                        },
                        remediation=(
                            "Investigate the source process immediately. This pattern "
                            "is consistent with credential theft tools like Mimikatz."
                        ),
                        mitre_attack=["T1003.001"],  # LSASS Memory
                    )
                )
        return findings
