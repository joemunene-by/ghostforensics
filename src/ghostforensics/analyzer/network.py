"""Network connection analysis module."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from ghostforensics.analyzer.base import BaseAnalyzer
from ghostforensics.config import SUSPICIOUS_PORTS
from ghostforensics.models import Connection, Finding, Severity

logger = logging.getLogger(__name__)


# RFC 5735 / RFC 6890 private and reserved ranges.
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_external(addr: str) -> bool:
    """Return True if the address is a routable external IP."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_multicast)


class NetworkAnalyzer(BaseAnalyzer):
    """Analyzes network connections from memory dumps."""

    name = "network_analyzer"

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Analyze network connections and return findings."""
        connections = self._extract_connections(data)
        findings: list[Finding] = []

        findings.extend(self._detect_suspicious_ports(connections))
        findings.extend(self._detect_external_connections(connections))
        findings.extend(self._detect_known_bad_ports(connections))
        findings.extend(self._detect_listening_unusual(connections))
        findings.extend(self._detect_high_connection_count(connections, data))

        return findings

    def extract_connections(self, data: dict[str, Any]) -> list[Connection]:
        """Public interface to extract connections."""
        return self._extract_connections(data)

    def _extract_connections(self, data: dict[str, Any]) -> list[Connection]:
        """Parse connections from JSON dump data."""
        raw_conns = data.get("connections", [])
        connections: list[Connection] = []
        for entry in raw_conns:
            conn = Connection(
                local_addr=entry.get("local_addr", ""),
                local_port=entry.get("local_port", 0),
                remote_addr=entry.get("remote_addr", ""),
                remote_port=entry.get("remote_port", 0),
                state=entry.get("state", "UNKNOWN"),
                protocol=entry.get("protocol", "TCP"),
                pid=entry.get("pid", 0),
                process_name=entry.get("process_name", ""),
                suspicious=entry.get("suspicious", False),
                suspicious_reasons=entry.get("suspicious_reasons", []),
            )
            connections.append(conn)
        return connections

    def _detect_suspicious_ports(self, connections: list[Connection]) -> list[Finding]:
        """Flag connections using known-bad or unusual ports."""
        findings: list[Finding] = []
        for conn in connections:
            flagged_port = None
            if conn.remote_port in SUSPICIOUS_PORTS:
                flagged_port = conn.remote_port
            elif conn.local_port in SUSPICIOUS_PORTS:
                flagged_port = conn.local_port

            if flagged_port:
                conn.suspicious = True
                conn.suspicious_reasons.append(f"suspicious port {flagged_port}")
                findings.append(
                    self._make_finding(
                        title=(
                            f"Suspicious port: {conn.process_name or 'unknown'} "
                            f"(PID {conn.pid}) using port {flagged_port}"
                        ),
                        description=(
                            f"Connection from {conn.local_addr}:{conn.local_port} to "
                            f"{conn.remote_addr}:{conn.remote_port} uses port {flagged_port} "
                            f"which is commonly associated with malicious activity."
                        ),
                        severity=Severity.HIGH.value,
                        evidence={
                            "pid": conn.pid,
                            "process_name": conn.process_name,
                            "local": f"{conn.local_addr}:{conn.local_port}",
                            "remote": f"{conn.remote_addr}:{conn.remote_port}",
                            "port": flagged_port,
                        },
                        remediation=(
                            "Investigate the process making this connection. Check if "
                            "this is a legitimate service or a C2 channel."
                        ),
                        mitre_attack=["T1571"],  # Non-Standard Port
                    )
                )
        return findings

    def _detect_external_connections(self, connections: list[Connection]) -> list[Finding]:
        """Flag connections to external (routable) IP addresses from suspicious processes."""
        findings: list[Finding] = []
        # Processes that normally do not make external connections.
        internal_only = {
            "lsass.exe",
            "csrss.exe",
            "smss.exe",
            "wininit.exe",
            "services.exe",
            "winlogon.exe",
        }
        for conn in connections:
            if _is_external(conn.remote_addr):
                proc_lower = conn.process_name.lower()
                if proc_lower in internal_only:
                    conn.suspicious = True
                    conn.suspicious_reasons.append("system process with external connection")
                    findings.append(
                        self._make_finding(
                            title=(
                                f"System process external connection: {conn.process_name} "
                                f"(PID {conn.pid})"
                            ),
                            description=(
                                f"System process '{conn.process_name}' has an external "
                                f"connection to {conn.remote_addr}:{conn.remote_port}. "
                                "System processes should not communicate externally."
                            ),
                            severity=Severity.CRITICAL.value,
                            evidence={
                                "pid": conn.pid,
                                "process_name": conn.process_name,
                                "remote_addr": conn.remote_addr,
                                "remote_port": conn.remote_port,
                            },
                            remediation=(
                                "This is a strong indicator of compromise. Isolate the "
                                "host and begin incident response procedures."
                            ),
                            mitre_attack=["T1071"],  # Application Layer Protocol
                        )
                    )
        return findings

    def _detect_known_bad_ports(self, connections: list[Connection]) -> list[Finding]:
        """Detect connections on ports commonly used for lateral movement."""
        findings: list[Finding] = []
        lateral_ports = {445, 135, 139, 3389, 5985, 5986, 22}
        for conn in connections:
            if conn.remote_port in lateral_ports and _is_external(conn.remote_addr):
                conn.suspicious = True
                conn.suspicious_reasons.append("lateral movement port to external IP")
                findings.append(
                    self._make_finding(
                        title=(
                            f"Potential lateral movement: port {conn.remote_port} "
                            f"to {conn.remote_addr}"
                        ),
                        description=(
                            f"Process '{conn.process_name}' (PID {conn.pid}) is connecting "
                            f"to {conn.remote_addr}:{conn.remote_port}. This port is commonly "
                            "used for lateral movement."
                        ),
                        severity=Severity.MEDIUM.value,
                        evidence={
                            "pid": conn.pid,
                            "process_name": conn.process_name,
                            "remote_addr": conn.remote_addr,
                            "remote_port": conn.remote_port,
                        },
                        remediation="Verify if this connection is expected in the environment.",
                        mitre_attack=["T1021"],  # Remote Services
                    )
                )
        return findings

    def _detect_listening_unusual(self, connections: list[Connection]) -> list[Finding]:
        """Flag unexpected listening ports."""
        findings: list[Finding] = []
        for conn in connections:
            if conn.state.upper() == "LISTENING" and conn.local_port > 49151:
                conn.suspicious = True
                conn.suspicious_reasons.append("listening on ephemeral port")
                findings.append(
                    self._make_finding(
                        title=(
                            f"Unusual listening port: {conn.process_name or 'unknown'} "
                            f"on port {conn.local_port}"
                        ),
                        description=(
                            f"Process '{conn.process_name}' (PID {conn.pid}) is listening "
                            f"on ephemeral port {conn.local_port}. Legitimate services "
                            "typically use well-known or registered ports."
                        ),
                        severity=Severity.LOW.value,
                        evidence={
                            "pid": conn.pid,
                            "process_name": conn.process_name,
                            "local_port": conn.local_port,
                        },
                        remediation="Verify the service is legitimate.",
                        mitre_attack=["T1571"],
                    )
                )
        return findings

    def _detect_high_connection_count(
        self, connections: list[Connection], data: dict[str, Any]
    ) -> list[Finding]:
        """Detect processes with an unusually high number of connections (potential beaconing)."""
        findings: list[Finding] = []
        threshold = data.get("connection_count_threshold", 20)
        pid_counts: dict[int, int] = {}
        pid_names: dict[int, str] = {}

        for conn in connections:
            pid_counts[conn.pid] = pid_counts.get(conn.pid, 0) + 1
            pid_names[conn.pid] = conn.process_name

        for pid, count in pid_counts.items():
            if count >= threshold:
                findings.append(
                    self._make_finding(
                        title=(
                            f"High connection count: {pid_names.get(pid, 'unknown')} "
                            f"(PID {pid}) — {count} connections"
                        ),
                        description=(
                            f"Process '{pid_names.get(pid, 'unknown')}' (PID {pid}) has "
                            f"{count} network connections. This may indicate beaconing, "
                            "scanning, or data exfiltration."
                        ),
                        severity=Severity.MEDIUM.value,
                        evidence={"pid": pid, "connection_count": count},
                        remediation="Analyze the connection destinations and timing patterns.",
                        mitre_attack=["T1071", "T1041"],
                    )
                )
        return findings
