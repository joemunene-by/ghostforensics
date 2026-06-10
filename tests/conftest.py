"""Shared test fixtures for GhostForensics."""

from __future__ import annotations

import pytest


@pytest.fixture()
def sample_processes() -> list[dict]:
    """A realistic process list with both legitimate and suspicious entries."""
    s32 = "C:\\Windows\\System32"
    return [
        {"pid": 4, "ppid": 0, "name": "System", "path": "", "cmdline": ""},
        {"pid": 348, "ppid": 4, "name": "smss.exe", "path": f"{s32}\\smss.exe", "cmdline": ""},
        {"pid": 452, "ppid": 348, "name": "csrss.exe", "path": f"{s32}\\csrss.exe", "cmdline": ""},
        {
            "pid": 528, "ppid": 348, "name": "wininit.exe",
            "path": f"{s32}\\wininit.exe", "cmdline": "",
        },
        {
            "pid": 596, "ppid": 528, "name": "services.exe",
            "path": f"{s32}\\services.exe", "cmdline": "",
        },
        {
            "pid": 604, "ppid": 528, "name": "lsass.exe",
            "path": f"{s32}\\lsass.exe", "cmdline": "",
        },
        {
            "pid": 780, "ppid": 596, "name": "svchost.exe",
            "path": f"{s32}\\svchost.exe", "cmdline": "",
        },
        {
            "pid": 2100, "ppid": 780, "name": "explorer.exe",
            "path": "C:\\Windows\\explorer.exe", "cmdline": "",
        },
    ]


@pytest.fixture()
def suspicious_processes() -> list[dict]:
    """Processes with suspicious characteristics."""
    return [
        # Masquerading: svchost from temp.
        {
            "pid": 4444, "ppid": 2100,
            "name": "svchost.exe",
            "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost.exe",
            "cmdline": "svchost.exe -connect 10.0.0.1:4444",
        },
        # Known offensive tool.
        {
            "pid": 4550, "ppid": 4444,
            "name": "mimikatz.exe",
            "path": "C:\\Users\\analyst\\Desktop\\mimikatz.exe",
            "cmdline": "mimikatz.exe sekurlsa::logonpasswords exit",
        },
        # Duplicate lsass.
        {
            "pid": 5000, "ppid": 1,
            "name": "lsass.exe",
            "path": "C:\\Users\\Public\\lsass.exe",
            "cmdline": "",
        },
    ]


@pytest.fixture()
def sample_data(sample_processes, suspicious_processes) -> dict:
    """Complete sample dump data."""
    return {
        "dump_path": "test_dump.json",
        "processes": sample_processes + suspicious_processes,
        "hidden_pids": [6666],
        "connections": [
            {
                "local_addr": "192.168.1.100", "local_port": 49152,
                "remote_addr": "142.250.80.46", "remote_port": 443,
                "state": "ESTABLISHED", "pid": 3340, "process_name": "chrome.exe",
            },
            {
                "local_addr": "192.168.1.100", "local_port": 49200,
                "remote_addr": "45.33.32.156", "remote_port": 4444,
                "state": "ESTABLISHED", "pid": 4444, "process_name": "svchost.exe",
            },
            {
                "local_addr": "0.0.0.0", "local_port": 54321,
                "remote_addr": "0.0.0.0", "remote_port": 0,
                "state": "LISTENING", "pid": 4444, "process_name": "svchost.exe",
            },
        ],
        "memory_regions": [
            {
                "pid": 4444, "process_name": "svchost.exe",
                "address": "0x7FFE0000", "size": 65536,
                "protection": "PAGE_EXECUTE_READWRITE",
            },
        ],
        "hollowed_processes": [
            {"pid": 4444, "name": "svchost.exe", "reason": "Image base mismatch"},
        ],
        "injected_dlls": [
            {
                "pid": 604, "process_name": "lsass.exe",
                "dll_name": "evil.dll",
                "dll_path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\evil.dll",
                "suspicious": True,
            },
        ],
        "handles": [
            {
                "type": "Mutant", "name": "Global\\MSCTFMonitor_test",
                "pid": 4444, "process_name": "svchost.exe",
            },
            {
                "type": "File", "name": "\\windows\\system32\\config\\SAM",
                "pid": 4550, "process_name": "mimikatz.exe",
            },
        ],
        "cross_process_handles": [
            {
                "source_pid": 4550, "source_name": "mimikatz.exe",
                "target_pid": 604, "target_name": "lsass.exe",
                "access_rights": "PROCESS_VM_READ",
            },
        ],
        "yara_matches": [
            {
                "rule_name": "CredentialHarvesting",
                "severity": "critical",
                "pid": 4550, "process_name": "mimikatz.exe",
                "matched_strings": ["mimikatz", "sekurlsa"],
                "description": "Credential harvesting tool detected",
            },
        ],
    }


@pytest.fixture()
def sample_connections() -> list[dict]:
    """Network connections for testing."""
    return [
        {
            "local_addr": "192.168.1.100", "local_port": 49152,
            "remote_addr": "142.250.80.46", "remote_port": 443,
            "state": "ESTABLISHED", "pid": 3340, "process_name": "chrome.exe",
        },
        {
            "local_addr": "192.168.1.100", "local_port": 49200,
            "remote_addr": "45.33.32.156", "remote_port": 4444,
            "state": "ESTABLISHED", "pid": 4444, "process_name": "svchost.exe",
        },
        {
            "local_addr": "192.168.1.100", "local_port": 49300,
            "remote_addr": "23.129.64.200", "remote_port": 9001,
            "state": "ESTABLISHED", "pid": 5000, "process_name": "lsass.exe",
        },
    ]


@pytest.fixture()
def sample_yara_matches() -> list[dict]:
    """Pre-computed YARA matches."""
    return [
        {
            "rule_name": "CredentialHarvesting",
            "severity": "critical",
            "pid": 4550,
            "process_name": "mimikatz.exe",
            "matched_strings": ["mimikatz", "sekurlsa"],
            "description": "Credential harvesting tool detected",
            "metadata": {"mitre_attack": "T1003"},
        },
        {
            "rule_name": "MalwareStrings",
            "severity": "high",
            "pid": 4444,
            "process_name": "svchost.exe",
            "matched_strings": ["VirtualAllocEx", "WriteProcessMemory"],
            "description": "Common malware API calls",
        },
    ]
