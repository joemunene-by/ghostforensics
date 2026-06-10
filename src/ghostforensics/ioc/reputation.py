"""IOC reputation checking against public threat intelligence feeds."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from ghostforensics.config import ReputationConfig
from ghostforensics.models import IOC, IOCType, Severity

logger = logging.getLogger(__name__)


class ReputationResult:
    """Result from a reputation check."""

    def __init__(
        self,
        ioc: IOC,
        source: str,
        malicious: bool = False,
        score: int = 0,
        details: dict[str, Any] | None = None,
        error: str = "",
    ):
        self.ioc = ioc
        self.source = source
        self.malicious = malicious
        self.score = score
        self.details = details or {}
        self.error = error


class ReputationChecker:
    """Check IOCs against public threat intelligence APIs.

    Supports (with API keys):
    - VirusTotal: file hashes, IPs, domains, URLs
    - AbuseIPDB: IP addresses

    Works without API keys in offline mode (returns no results).
    """

    def __init__(self, config: ReputationConfig | None = None):
        self._config = config or ReputationConfig()

    @property
    def online_enabled(self) -> bool:
        return self._config.enable_online_checks

    def check(self, ioc: IOC) -> list[ReputationResult]:
        """Check a single IOC against configured sources."""
        if not self._config.enable_online_checks:
            return []

        results: list[ReputationResult] = []

        if self._config.virustotal_api_key:
            vt_result = self._check_virustotal(ioc)
            if vt_result:
                results.append(vt_result)

        if self._config.abuseipdb_api_key and ioc.type == IOCType.IP_ADDRESS:
            abuse_result = self._check_abuseipdb(ioc)
            if abuse_result:
                results.append(abuse_result)

        return results

    def check_batch(self, iocs: list[IOC]) -> dict[str, list[ReputationResult]]:
        """Check a batch of IOCs. Returns mapping of IOC value to results."""
        all_results: dict[str, list[ReputationResult]] = {}
        for ioc in iocs:
            results = self.check(ioc)
            if results:
                all_results[ioc.value] = results
        return all_results

    def _check_virustotal(self, ioc: IOC) -> ReputationResult | None:
        """Check an IOC against VirusTotal API v3."""
        api_key = self._config.virustotal_api_key
        if not api_key:
            return None

        endpoint_map = {
            IOCType.IP_ADDRESS: f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}",
            IOCType.DOMAIN: f"https://www.virustotal.com/api/v3/domains/{ioc.value}",
            IOCType.FILE_HASH_MD5: f"https://www.virustotal.com/api/v3/files/{ioc.value}",
            IOCType.FILE_HASH_SHA1: f"https://www.virustotal.com/api/v3/files/{ioc.value}",
            IOCType.FILE_HASH_SHA256: f"https://www.virustotal.com/api/v3/files/{ioc.value}",
        }

        url = endpoint_map.get(ioc.type)
        if not url:
            return None

        try:
            req = urllib.request.Request(url, headers={"x-apikey": api_key})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return ReputationResult(
                ioc=ioc,
                source="virustotal",
                malicious=malicious_count > 0,
                score=malicious_count,
                details={
                    "malicious": malicious_count,
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": total,
                },
            )
        except urllib.error.HTTPError as e:
            logger.warning("VirusTotal API error for %s: %s", ioc.value, e)
            return ReputationResult(ioc=ioc, source="virustotal", error=str(e))
        except Exception as e:
            logger.warning("VirusTotal check failed for %s: %s", ioc.value, e)
            return ReputationResult(ioc=ioc, source="virustotal", error=str(e))

    def _check_abuseipdb(self, ioc: IOC) -> ReputationResult | None:
        """Check an IP against AbuseIPDB API v2."""
        api_key = self._config.abuseipdb_api_key
        if not api_key or ioc.type != IOCType.IP_ADDRESS:
            return None

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc.value}&maxAgeInDays=90"

        try:
            req = urllib.request.Request(url, headers={
                "Key": api_key,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            result_data = data.get("data", {})
            abuse_score = result_data.get("abuseConfidenceScore", 0)
            total_reports = result_data.get("totalReports", 0)

            return ReputationResult(
                ioc=ioc,
                source="abuseipdb",
                malicious=abuse_score > 50,
                score=abuse_score,
                details={
                    "abuse_confidence_score": abuse_score,
                    "total_reports": total_reports,
                    "country_code": result_data.get("countryCode", ""),
                    "isp": result_data.get("isp", ""),
                    "is_tor": result_data.get("isTor", False),
                },
            )
        except urllib.error.HTTPError as e:
            logger.warning("AbuseIPDB API error for %s: %s", ioc.value, e)
            return ReputationResult(ioc=ioc, source="abuseipdb", error=str(e))
        except Exception as e:
            logger.warning("AbuseIPDB check failed for %s: %s", ioc.value, e)
            return ReputationResult(ioc=ioc, source="abuseipdb", error=str(e))

    @staticmethod
    def update_ioc_severity(ioc: IOC, results: list[ReputationResult]) -> IOC:
        """Update an IOC's severity based on reputation results."""
        for result in results:
            if result.malicious:
                if result.score >= 10:
                    ioc.severity = Severity.CRITICAL
                elif result.score >= 3:
                    ioc.severity = Severity.HIGH
                else:
                    ioc.severity = Severity.MEDIUM
                ioc.tags.append(f"reputation:{result.source}:malicious")
                break
        return ioc
