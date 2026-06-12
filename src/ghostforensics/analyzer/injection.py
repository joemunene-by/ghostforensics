"""Code injection detection module."""

from __future__ import annotations

import logging
from typing import Any

from ghostforensics.analyzer.base import BaseAnalyzer
from ghostforensics.models import Finding, InjectionFinding, Severity

logger = logging.getLogger(__name__)


class InjectionAnalyzer(BaseAnalyzer):
    """Detects code injection indicators in memory dumps.

    Looks for:
    - Process hollowing (unmapped executable sections)
    - DLL injection signatures (unexpected DLLs loaded)
    - RWX memory regions (read-write-execute, common in shellcode)
    - Reflective DLL loading indicators
    """

    name = "injection_analyzer"

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Analyze memory data for injection indicators."""
        findings: list[Finding] = []

        findings.extend(self._detect_hollowing(data))
        findings.extend(self._detect_dll_injection(data))
        findings.extend(self._detect_rwx_regions(data))
        findings.extend(self._detect_reflective_loading(data))

        return findings

    def extract_injection_findings(self, data: dict[str, Any]) -> list[InjectionFinding]:
        """Return typed InjectionFinding objects."""
        raw_findings = self.analyze(data)
        injection_findings: list[InjectionFinding] = []
        for f in raw_findings:
            injection_findings.append(
                InjectionFinding(
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    analyzer=f.analyzer,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    mitre_attack=f.mitre_attack,
                    injection_type=f.evidence.get("injection_type", ""),
                    target_pid=f.evidence.get("pid", 0),
                    target_process=f.evidence.get("process_name", ""),
                    injected_region_addr=f.evidence.get("region_addr", ""),
                    injected_region_size=f.evidence.get("region_size", 0),
                )
            )
        return injection_findings

    # -- Detection methods -------------------------------------------------

    def _detect_hollowing(self, data: dict[str, Any]) -> list[Finding]:
        """Detect process hollowing indicators.

        Process hollowing: legitimate process started in suspended state, original
        code unmapped, malicious code mapped in its place.

        Indicators in JSON data:
        - 'hollowed_processes' key with list of PIDs / process info
        - Processes with mismatched image base vs. PEB image base
        """
        findings: list[Finding] = []
        for entry in data.get("hollowed_processes", []):
            pid = entry.get("pid", 0)
            name = entry.get("name", "unknown")
            reason = entry.get("reason", "Image base mismatch detected")
            findings.append(
                self._make_finding(
                    title=f"Process hollowing detected: {name} (PID {pid})",
                    description=(
                        f"Process '{name}' (PID {pid}) shows signs of process hollowing. "
                        f"Indicator: {reason}. The legitimate process image may have been "
                        "replaced with malicious code."
                    ),
                    severity=Severity.CRITICAL.value,
                    evidence={
                        "injection_type": "hollowing",
                        "pid": pid,
                        "process_name": name,
                        "reason": reason,
                    },
                    remediation=(
                        "Dump the process memory for analysis. Compare the in-memory "
                        "image with the on-disk binary. Isolate the host."
                    ),
                    mitre_attack=["T1055.012"],  # Process Hollowing
                )
            )
        return findings

    def _detect_dll_injection(self, data: dict[str, Any]) -> list[Finding]:
        """Detect DLL injection indicators.

        Indicators:
        - 'injected_dlls' key listing unexpected DLLs loaded into processes
        - DLLs loaded from temp directories or unusual paths
        """
        findings: list[Finding] = []
        suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]

        for entry in data.get("injected_dlls", []):
            pid = entry.get("pid", 0)
            process_name = entry.get("process_name", "unknown")
            dll_path = entry.get("dll_path", "")
            dll_name = entry.get("dll_name", "")

            path_lower = dll_path.lower()
            is_suspicious = any(sp in path_lower for sp in suspicious_paths)
            is_suspicious = is_suspicious or entry.get("suspicious", False)

            if is_suspicious:
                findings.append(
                    self._make_finding(
                        title=(
                            f"Suspicious DLL injection: {dll_name} in {process_name} (PID {pid})"
                        ),
                        description=(
                            f"DLL '{dll_name}' loaded into '{process_name}' (PID {pid}) "
                            f"from suspicious path: {dll_path}"
                        ),
                        severity=Severity.HIGH.value,
                        evidence={
                            "injection_type": "dll_injection",
                            "pid": pid,
                            "process_name": process_name,
                            "dll_name": dll_name,
                            "dll_path": dll_path,
                        },
                        remediation=(
                            "Analyze the injected DLL. Check its digital signature. "
                            "Compare with known-good DLL lists."
                        ),
                        mitre_attack=["T1055.001"],  # DLL Injection
                    )
                )
        return findings

    def _detect_rwx_regions(self, data: dict[str, Any]) -> list[Finding]:
        """Detect RWX (read-write-execute) memory regions.

        Legitimate processes rarely need RWX memory. Shellcode and packers
        commonly allocate RWX regions.
        """
        findings: list[Finding] = []
        for entry in data.get("memory_regions", []):
            protection = entry.get("protection", "").upper()
            if "RWX" in protection or protection == "PAGE_EXECUTE_READWRITE":
                pid = entry.get("pid", 0)
                process_name = entry.get("process_name", "unknown")
                region_addr = entry.get("address", "0x0")
                region_size = entry.get("size", 0)

                # Skip known-good RWX regions (JIT compilers, etc.).
                if process_name.lower() in ("java.exe", "javaw.exe", "node.exe", "chrome.exe"):
                    continue

                findings.append(
                    self._make_finding(
                        title=(f"RWX memory region in {process_name} (PID {pid}) at {region_addr}"),
                        description=(
                            f"Process '{process_name}' (PID {pid}) has a memory region at "
                            f"{region_addr} (size: {region_size} bytes) with read-write-execute "
                            "permissions. This is commonly used by shellcode and packers."
                        ),
                        severity=Severity.HIGH.value,
                        evidence={
                            "injection_type": "rwx_memory",
                            "pid": pid,
                            "process_name": process_name,
                            "region_addr": region_addr,
                            "region_size": region_size,
                            "protection": protection,
                        },
                        remediation=(
                            "Dump the RWX memory region for analysis. Scan with YARA "
                            "rules. Check for known shellcode patterns."
                        ),
                        mitre_attack=["T1055"],  # Process Injection
                    )
                )
        return findings

    def _detect_reflective_loading(self, data: dict[str, Any]) -> list[Finding]:
        """Detect reflective DLL loading indicators.

        Reflective loading: DLL loaded directly from memory without touching disk.
        Indicators:
        - PE headers in non-image memory regions
        - 'ReflectiveLoader' export
        """
        findings: list[Finding] = []
        for entry in data.get("reflective_indicators", []):
            pid = entry.get("pid", 0)
            process_name = entry.get("process_name", "unknown")
            indicator = entry.get("indicator", "PE header in non-image memory")
            address = entry.get("address", "0x0")

            findings.append(
                self._make_finding(
                    title=(f"Reflective DLL loading in {process_name} (PID {pid})"),
                    description=(
                        f"Reflective loading indicator found in '{process_name}' "
                        f"(PID {pid}) at {address}: {indicator}. This technique loads "
                        "code directly into memory without writing to disk."
                    ),
                    severity=Severity.CRITICAL.value,
                    evidence={
                        "injection_type": "reflective_loading",
                        "pid": pid,
                        "process_name": process_name,
                        "indicator": indicator,
                        "region_addr": address,
                    },
                    remediation=(
                        "Dump the reflectively loaded module. This is a strong indicator "
                        "of sophisticated malware. Full incident response recommended."
                    ),
                    mitre_attack=["T1620"],  # Reflective Code Loading
                )
            )
        return findings
