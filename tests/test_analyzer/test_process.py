"""Tests for the ProcessAnalyzer module."""

from __future__ import annotations

from ghostforensics.analyzer.process import ProcessAnalyzer
from ghostforensics.models import Severity


class TestProcessExtraction:
    """Test process extraction from JSON data."""

    def test_extract_processes_from_json(self, sample_processes):
        """Processes are correctly parsed from JSON data."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes}
        procs = analyzer.extract_processes(data)
        assert len(procs) == len(sample_processes)
        assert procs[0].pid == 4
        assert procs[0].name == "System"

    def test_extract_processes_empty(self):
        """Empty data returns empty process list."""
        analyzer = ProcessAnalyzer()
        procs = analyzer.extract_processes({})
        assert procs == []

    def test_extract_preserves_fields(self, sample_processes):
        """All process fields are correctly populated."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes}
        procs = analyzer.extract_processes(data)
        smss = next(p for p in procs if p.name == "smss.exe")
        assert smss.pid == 348
        assert smss.ppid == 4
        assert "System32" in smss.path


class TestHiddenProcessDetection:
    """Test detection of hidden processes."""

    def test_detect_hidden_pid(self, sample_processes):
        """Hidden PIDs not in process list trigger critical finding."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes, "hidden_pids": [9999]}
        findings = analyzer.analyze(data)
        hidden_findings = [f for f in findings if "Hidden process" in f.title]
        assert len(hidden_findings) == 1
        assert hidden_findings[0].severity == Severity.CRITICAL

    def test_no_hidden_pids(self, sample_processes):
        """No hidden_pids key produces no hidden-process findings."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes}
        findings = analyzer.analyze(data)
        hidden_findings = [f for f in findings if "Hidden process" in f.title]
        assert len(hidden_findings) == 0


class TestOrphanDetection:
    """Test orphan process detection."""

    def test_detect_orphan_process(self):
        """Process with non-existent parent PID is flagged as orphan."""
        analyzer = ProcessAnalyzer()
        data = {
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System"},
                {"pid": 100, "ppid": 999, "name": "suspicious.exe"},
            ]
        }
        findings = analyzer.analyze(data)
        orphan = [f for f in findings if "Orphan" in f.title]
        assert len(orphan) == 1
        assert orphan[0].severity == Severity.MEDIUM

    def test_system_processes_not_flagged_orphan(self):
        """System and smss.exe should not be flagged even if ppid is absent."""
        analyzer = ProcessAnalyzer()
        data = {
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System"},
                {"pid": 348, "ppid": 4, "name": "smss.exe"},
            ]
        }
        findings = analyzer.analyze(data)
        orphan = [f for f in findings if "Orphan" in f.title]
        assert len(orphan) == 0


class TestNameMasquerading:
    """Test process name masquerading detection."""

    def test_detect_svchost_wrong_path(self):
        """svchost.exe from non-system path triggers high-severity finding."""
        analyzer = ProcessAnalyzer()
        data = {
            "processes": [
                {
                    "pid": 4444,
                    "ppid": 100,
                    "name": "svchost.exe",
                    "path": "C:\\Users\\Temp\\svchost.exe",
                },
            ]
        }
        findings = analyzer.analyze(data)
        masq = [f for f in findings if "masquerading" in f.title.lower()]
        assert len(masq) >= 1
        assert masq[0].severity == Severity.HIGH

    def test_legitimate_svchost_not_flagged(self, sample_processes):
        """Legitimate svchost from System32 is not flagged."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes}
        findings = analyzer.analyze(data)
        masq = [f for f in findings if "masquerading" in f.title.lower()]
        assert len(masq) == 0


class TestSuspiciousNames:
    """Test detection of known offensive tool names."""

    def test_detect_mimikatz(self, suspicious_processes, sample_processes):
        """mimikatz.exe triggers a finding."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes + suspicious_processes}
        findings = analyzer.analyze(data)
        mimi = [f for f in findings if "mimikatz" in f.title.lower()]
        assert len(mimi) >= 1
        assert mimi[0].severity == Severity.HIGH

    def test_no_false_positive_on_normal_names(self, sample_processes):
        """Normal process names do not trigger suspicious name findings."""
        analyzer = ProcessAnalyzer()
        data = {"processes": sample_processes}
        findings = analyzer.analyze(data)
        sus = [f for f in findings if "Suspicious tool" in f.title]
        assert len(sus) == 0


class TestParentMismatch:
    """Test parent process relationship validation."""

    def test_detect_lsass_wrong_parent(self):
        """lsass.exe with unexpected parent triggers finding."""
        analyzer = ProcessAnalyzer()
        data = {
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System"},
                {"pid": 100, "ppid": 4, "name": "explorer.exe"},
                {
                    "pid": 604,
                    "ppid": 100,
                    "name": "lsass.exe",
                    "path": "C:\\Windows\\System32\\lsass.exe",
                },
            ]
        }
        findings = analyzer.analyze(data)
        mismatch = [f for f in findings if "Parent process mismatch" in f.title]
        assert len(mismatch) >= 1


class TestDuplicateSystemProcesses:
    """Test duplicate system process detection."""

    def test_detect_duplicate_lsass(self):
        """Two lsass.exe instances trigger a finding."""
        analyzer = ProcessAnalyzer()
        data = {
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System"},
                {"pid": 528, "ppid": 4, "name": "wininit.exe"},
                {
                    "pid": 604,
                    "ppid": 528,
                    "name": "lsass.exe",
                    "path": "C:\\Windows\\System32\\lsass.exe",
                },
                {
                    "pid": 5000,
                    "ppid": 1,
                    "name": "lsass.exe",
                    "path": "C:\\Users\\Public\\lsass.exe",
                },
            ]
        }
        findings = analyzer.analyze(data)
        dup = [f for f in findings if "Duplicate system process" in f.title]
        assert len(dup) >= 1
        assert dup[0].severity == Severity.HIGH
