"""Process analysis module — extracts process tree and detects anomalies."""

from __future__ import annotations

import logging
from typing import Any

from ghostforensics.analyzer.base import BaseAnalyzer
from ghostforensics.config import KNOWN_SYSTEM_PROCESSES, SUSPICIOUS_PROCESS_NAMES
from ghostforensics.models import Finding, Process, Severity

logger = logging.getLogger(__name__)

# Try importing Volatility3; fall back gracefully.
try:
    import volatility3  # noqa: F401
    from volatility3.framework import automagic, contexts
    from volatility3.plugins.windows import pslist

    HAS_VOL3 = True
except ImportError:
    HAS_VOL3 = False


class ProcessAnalyzer(BaseAnalyzer):
    """Analyzes process listings from memory dumps.

    Supports two backends:
      1. Volatility3 API (if installed) for raw .raw/.dmp/.vmem files.
      2. Standalone JSON parser for pre-processed dump data.
    """

    name = "process_analyzer"

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Analyze processes from dump data and return findings."""
        processes = self._extract_processes(data)
        findings: list[Finding] = []

        findings.extend(self._detect_hidden_processes(processes, data))
        findings.extend(self._detect_orphan_processes(processes))
        findings.extend(self._detect_name_masquerading(processes))
        findings.extend(self._detect_suspicious_names(processes))
        findings.extend(self._detect_parent_mismatch(processes))
        findings.extend(self._detect_duplicate_system_processes(processes))

        return findings

    def extract_processes(self, data: dict[str, Any]) -> list[Process]:
        """Public interface to extract process list."""
        return self._extract_processes(data)

    # -- Backend dispatch --------------------------------------------------

    def _extract_processes(self, data: dict[str, Any]) -> list[Process]:
        """Extract processes from either vol3 results or JSON data."""
        if "processes" in data:
            return self._parse_json_processes(data["processes"])
        if HAS_VOL3 and "dump_path" in data:
            return self._extract_via_vol3(data["dump_path"])
        return []

    def _parse_json_processes(self, raw_procs: list[dict[str, Any]]) -> list[Process]:
        """Parse processes from JSON representation."""
        processes: list[Process] = []
        for entry in raw_procs:
            proc = Process(
                pid=entry.get("pid", 0),
                ppid=entry.get("ppid", 0),
                name=entry.get("name", ""),
                path=entry.get("path", ""),
                cmdline=entry.get("cmdline", ""),
                create_time=entry.get("create_time", ""),
                exit_time=entry.get("exit_time", ""),
                threads=entry.get("threads", 0),
                handles=entry.get("handles", 0),
                suspicious_flags=entry.get("suspicious_flags", []),
                children=entry.get("children", []),
            )
            processes.append(proc)
        return processes

    def _extract_via_vol3(self, dump_path: str) -> list[Process]:
        """Extract processes using the Volatility3 API."""
        if not HAS_VOL3:
            return []
        try:
            ctx = contexts.Context()
            automagic.available(ctx)
            plugin = pslist.PsList(ctx, config_path="plugins.PsList", progress_callback=None)
            treegrid = plugin.run()

            processes: list[Process] = []

            def visitor(node, _accumulator):
                values = node.values
                proc = Process(
                    pid=int(values[0]),
                    ppid=int(values[1]),
                    name=str(values[2]),
                    path=str(values.get(3, "")),
                    create_time=str(values.get(4, "")),
                    threads=int(values.get(5, 0)),
                    handles=int(values.get(6, 0)),
                )
                processes.append(proc)

            treegrid.populate(visitor)
            return processes
        except Exception:
            logger.exception("Volatility3 process extraction failed")
            return []

    # -- Detection methods -------------------------------------------------

    def _detect_hidden_processes(
        self, processes: list[Process], data: dict[str, Any]
    ) -> list[Finding]:
        """Detect processes present in one listing but absent from another.

        In JSON mode this relies on an optional 'hidden_pids' key.
        """
        findings: list[Finding] = []
        hidden_pids: list[int] = data.get("hidden_pids", [])
        pid_set = {p.pid for p in processes}

        for hpid in hidden_pids:
            if hpid not in pid_set:
                findings.append(
                    self._make_finding(
                        title=f"Hidden process detected (PID {hpid})",
                        description=(
                            f"PID {hpid} was found in a cross-view comparison but is not "
                            "visible in the standard process list. This is a strong indicator "
                            "of rootkit activity."
                        ),
                        severity=Severity.CRITICAL.value,
                        evidence={"hidden_pid": hpid},
                        remediation=(
                            "Isolate the host immediately. Capture a full disk image. "
                            "Investigate rootkit presence with specialized tools."
                        ),
                        mitre_attack=["T1014"],  # Rootkit
                    )
                )
        return findings

    def _detect_orphan_processes(self, processes: list[Process]) -> list[Finding]:
        """Detect processes whose parent PID does not exist (orphans)."""
        findings: list[Finding] = []
        pid_set = {p.pid for p in processes}

        for proc in processes:
            if proc.ppid != 0 and proc.ppid not in pid_set:
                # Ignore system-level processes with expected orphan parents.
                if proc.name.lower() in ("system", "smss.exe", "registry"):
                    continue
                findings.append(
                    self._make_finding(
                        title=f"Orphan process: {proc.name} (PID {proc.pid})",
                        description=(
                            f"Process '{proc.name}' (PID {proc.pid}) has parent PID "
                            f"{proc.ppid} which does not exist in the process list. "
                            "This may indicate the parent was terminated to hide tracks."
                        ),
                        severity=Severity.MEDIUM.value,
                        evidence={
                            "pid": proc.pid,
                            "ppid": proc.ppid,
                            "name": proc.name,
                        },
                        remediation=(
                            "Investigate the process lineage. Check if the parent was "
                            "legitimately terminated or if this indicates evasion."
                        ),
                        mitre_attack=["T1036"],  # Masquerading
                    )
                )
        return findings

    def _detect_name_masquerading(self, processes: list[Process]) -> list[Finding]:
        """Detect processes using names similar to system processes but from wrong paths."""
        findings: list[Finding] = []
        system_names = set(KNOWN_SYSTEM_PROCESSES.keys())

        for proc in processes:
            lower_name = proc.name.lower()
            if lower_name in system_names and proc.path:
                # svchost.exe should run from system32.
                expected_paths = [
                    "\\windows\\system32\\",
                    "\\systemroot\\system32\\",
                    "c:\\windows\\system32\\",
                ]
                path_lower = proc.path.lower()
                if lower_name in (
                    "svchost.exe",
                    "csrss.exe",
                    "lsass.exe",
                    "services.exe",
                ) and not any(ep in path_lower for ep in expected_paths):
                    findings.append(
                        self._make_finding(
                            title=f"Process name masquerading: {proc.name} (PID {proc.pid})",
                            description=(
                                f"Process '{proc.name}' is running from '{proc.path}' "
                                "instead of the expected system directory. This is a "
                                "common technique used by malware to blend in."
                            ),
                            severity=Severity.HIGH.value,
                            evidence={
                                "pid": proc.pid,
                                "name": proc.name,
                                "actual_path": proc.path,
                                "expected_path": "\\Windows\\System32\\",
                            },
                            remediation=(
                                "Quarantine the process and its binary. Submit the "
                                "binary for malware analysis."
                            ),
                            mitre_attack=["T1036.005"],  # Match Legitimate Name or Location
                        )
                    )
        return findings

    def _detect_suspicious_names(self, processes: list[Process]) -> list[Finding]:
        """Detect processes with names matching known offensive tools."""
        findings: list[Finding] = []
        for proc in processes:
            lower_name = proc.name.lower().replace(".exe", "")
            for sus_name in SUSPICIOUS_PROCESS_NAMES:
                if sus_name in lower_name:
                    findings.append(
                        self._make_finding(
                            title=f"Suspicious tool detected: {proc.name} (PID {proc.pid})",
                            description=(
                                f"Process '{proc.name}' matches known offensive tool "
                                f"pattern '{sus_name}'. Command line: {proc.cmdline or 'N/A'}"
                            ),
                            severity=Severity.HIGH.value,
                            evidence={
                                "pid": proc.pid,
                                "name": proc.name,
                                "cmdline": proc.cmdline,
                                "matched_pattern": sus_name,
                            },
                            remediation=(
                                "Terminate the process. Investigate the user account and "
                                "how the tool was introduced. Check for lateral movement."
                            ),
                            mitre_attack=["T1003", "T1059"],
                        )
                    )
                    break
        return findings

    def _detect_parent_mismatch(self, processes: list[Process]) -> list[Finding]:
        """Detect system processes with unexpected parent processes."""
        findings: list[Finding] = []
        pid_to_proc = {p.pid: p for p in processes}

        for proc in processes:
            lower_name = proc.name.lower()
            if lower_name not in KNOWN_SYSTEM_PROCESSES:
                continue
            expected = KNOWN_SYSTEM_PROCESSES[lower_name]
            expected_ppid_name = expected.get("expected_ppid_name", "")

            if expected_ppid_name and proc.ppid in pid_to_proc:
                parent = pid_to_proc[proc.ppid]
                if parent.name.lower() != expected_ppid_name:
                    findings.append(
                        self._make_finding(
                            title=f"Parent process mismatch: {proc.name} (PID {proc.pid})",
                            description=(
                                f"'{proc.name}' has parent '{parent.name}' (PID {proc.ppid}) "
                                f"but expected parent is '{expected_ppid_name}'. "
                                "This may indicate process spoofing."
                            ),
                            severity=Severity.HIGH.value,
                            evidence={
                                "pid": proc.pid,
                                "name": proc.name,
                                "actual_parent": parent.name,
                                "expected_parent": expected_ppid_name,
                            },
                            remediation=(
                                "Investigate the spawning chain. This process may have "
                                "been spawned by malware using parent PID spoofing."
                            ),
                            mitre_attack=["T1134.004"],  # Parent PID Spoofing
                        )
                    )
        return findings

    def _detect_duplicate_system_processes(self, processes: list[Process]) -> list[Finding]:
        """Detect multiple instances of processes that should be singletons."""
        findings: list[Finding] = []
        name_counts: dict[str, list[Process]] = {}

        for proc in processes:
            lower = proc.name.lower()
            name_counts.setdefault(lower, []).append(proc)

        for name, expected in KNOWN_SYSTEM_PROCESSES.items():
            expected_count = expected.get("expected_count")
            if expected_count is not None and name in name_counts:
                actual = name_counts[name]
                if len(actual) > expected_count:
                    findings.append(
                        self._make_finding(
                            title=f"Duplicate system process: {name} ({len(actual)} instances)",
                            description=(
                                f"Found {len(actual)} instances of '{name}' but expected "
                                f"at most {expected_count}. Additional instances may be malware "
                                "masquerading as a system process."
                            ),
                            severity=Severity.HIGH.value,
                            evidence={
                                "process_name": name,
                                "expected_count": expected_count,
                                "actual_count": len(actual),
                                "pids": [p.pid for p in actual],
                            },
                            remediation=(
                                "Identify the legitimate instance and investigate the "
                                "additional instances. Compare binary hashes."
                            ),
                            mitre_attack=["T1036"],
                        )
                    )
        return findings
