"""Tests for the IOCExtractor module."""

from __future__ import annotations

from ghostforensics.ioc.extractor import IOCExtractor
from ghostforensics.models import (
    IOC,
    Connection,
    ForensicsReport,
    IOCType,
)


class TestIPExtraction:
    """Test IP address extraction."""

    def test_extract_public_ip(self):
        """Public IP addresses are extracted."""
        extractor = IOCExtractor()
        data = {
            "connections": [
                {"remote_addr": "45.33.32.156", "pid": 100, "process_name": "test"},
            ]
        }
        iocs = extractor.extract_from_data(data)
        ips = [i for i in iocs if i.type == IOCType.IP_ADDRESS]
        assert any(i.value == "45.33.32.156" for i in ips)

    def test_private_ips_excluded_by_default(self):
        """Private IPs are excluded by default."""
        extractor = IOCExtractor()
        data = {
            "connections": [
                {"remote_addr": "192.168.1.1", "pid": 100, "process_name": "test"},
            ]
        }
        iocs = extractor.extract_from_data(data)
        ips = [i for i in iocs if i.type == IOCType.IP_ADDRESS]
        assert not any(i.value == "192.168.1.1" for i in ips)

    def test_private_ips_included_when_requested(self):
        """Private IPs are included when include_private_ips is True."""
        extractor = IOCExtractor(include_private_ips=True)
        data = {
            "connections": [
                {"remote_addr": "192.168.1.1", "pid": 100, "process_name": "test"},
            ]
        }
        iocs = extractor.extract_from_data(data)
        ips = [i for i in iocs if i.type == IOCType.IP_ADDRESS]
        assert any(i.value == "192.168.1.1" for i in ips)


class TestDeduplication:
    """Test IOC deduplication."""

    def test_duplicate_ips_deduplicated(self):
        """Same IP appearing multiple times is only reported once."""
        extractor = IOCExtractor()
        data = {
            "connections": [
                {"remote_addr": "45.33.32.156", "pid": 100, "process_name": "a"},
                {"remote_addr": "45.33.32.156", "pid": 200, "process_name": "b"},
            ]
        }
        iocs = extractor.extract_from_data(data)
        ips = [i for i in iocs if i.type == IOCType.IP_ADDRESS and i.value == "45.33.32.156"]
        assert len(ips) == 1


class TestURLExtraction:
    """Test URL extraction."""

    def test_extract_urls(self):
        """URLs in extracted strings are found."""
        extractor = IOCExtractor()
        data = {
            "extracted_strings": [
                "http://evil.com/payload.ps1",
                "https://malware.example.org/stage2",
            ]
        }
        iocs = extractor.extract_from_data(data)
        urls = [i for i in iocs if i.type == IOCType.URL]
        assert len(urls) >= 2


class TestEmailExtraction:
    """Test email extraction."""

    def test_extract_emails(self):
        """Email addresses in data are extracted."""
        extractor = IOCExtractor()
        data = {
            "extracted_strings": [
                "contact admin@evil-corp.com for payload",
            ]
        }
        iocs = extractor.extract_from_data(data)
        emails = [i for i in iocs if i.type == IOCType.EMAIL]
        assert any(i.value == "admin@evil-corp.com" for i in emails)


class TestSTIXExport:
    """Test STIX bundle export."""

    def test_stix_bundle_structure(self):
        """STIX bundle has correct structure."""
        iocs = [
            IOC(type=IOCType.IP_ADDRESS, value="45.33.32.156", context="test"),
            IOC(type=IOCType.DOMAIN, value="evil.com", context="test"),
        ]
        bundle = IOCExtractor.to_stix_bundle(iocs)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2
        assert bundle["objects"][0]["type"] == "indicator"
        assert "pattern" in bundle["objects"][0]

    def test_stix_pattern_format(self):
        """STIX patterns use correct format for different IOC types."""
        ioc = IOC(type=IOCType.IP_ADDRESS, value="45.33.32.156")
        stix = ioc.to_stix_indicator()
        assert stix["pattern"] == "[ipv4-addr:value = '45.33.32.156']"

        ioc2 = IOC(type=IOCType.FILE_HASH_SHA256, value="a" * 64)
        stix2 = ioc2.to_stix_indicator()
        assert "SHA-256" in stix2["pattern"]


class TestReportExtraction:
    """Test IOC extraction from a full ForensicsReport."""

    def test_extract_from_report(self):
        """IOCs are extracted from a ForensicsReport with connections."""
        report = ForensicsReport(
            dump_path="test.raw",
            connections=[
                Connection(
                    local_addr="192.168.1.1",
                    local_port=49000,
                    remote_addr="45.33.32.156",
                    remote_port=443,
                    pid=100,
                    process_name="test.exe",
                ),
            ],
        )
        extractor = IOCExtractor()
        iocs = extractor.extract_from_report(report)
        ips = [i for i in iocs if i.type == IOCType.IP_ADDRESS]
        assert any(i.value == "45.33.32.156" for i in ips)
