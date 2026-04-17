"""YARA scanning module — scans memory regions against YARA rules."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ghostforensics.analyzer.base import BaseAnalyzer
from ghostforensics.config import RULES_DIR, Settings
from ghostforensics.models import Finding, Severity, YaraMatch

logger = logging.getLogger(__name__)

# Try importing yara-python; fall back to simplified matcher.
try:
    import yara  # type: ignore[import-untyped]

    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class _SimplifiedRule:
    """A minimal YARA-like rule parsed from .yar files for fallback matching."""

    def __init__(
        self,
        name: str,
        strings: list[tuple[str, bytes | re.Pattern[bytes]]],
        metadata: dict[str, str],
        tags: list[str],
    ):
        self.name = name
        self.strings = strings
        self.metadata = metadata
        self.tags = tags

    def match_data(self, data: bytes) -> list[str]:
        """Return list of matched string identifiers."""
        matched: list[str] = []
        for identifier, pattern in self.strings:
            if isinstance(pattern, re.Pattern):
                if pattern.search(data):
                    matched.append(identifier)
            elif isinstance(pattern, bytes):
                if pattern in data:
                    matched.append(identifier)
        return matched


def _parse_yar_file(path: Path) -> list[_SimplifiedRule]:
    """Parse a .yar file into simplified rules (fallback when yara-python missing)."""
    rules: list[_SimplifiedRule] = []
    text = path.read_text(errors="replace")

    # Very simplified parser: extract rule blocks.
    rule_pattern = re.compile(
        r'rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{(.*?)\}(?=\s*(?:rule\s|\Z))',
        re.DOTALL,
    )
    for match in rule_pattern.finditer(text):
        rule_name = match.group(1)
        tag_str = match.group(2) or ""
        body = match.group(3)
        tags = tag_str.split()

        # Parse meta section.
        metadata: dict[str, str] = {}
        meta_match = re.search(r'meta\s*:(.*?)(?=strings\s*:|condition\s*:|$)', body, re.DOTALL)
        if meta_match:
            for m in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', meta_match.group(1)):
                metadata[m.group(1)] = m.group(2)

        # Parse strings section.
        strings: list[tuple[str, bytes | re.Pattern[bytes]]] = []
        strings_match = re.search(r'strings\s*:(.*?)(?=condition\s*:|$)', body, re.DOTALL)
        if strings_match:
            for s in re.finditer(
                r'(\$\w+)\s*=\s*(?:"([^"]*)"|\{([^}]*)\}|/([^/]*)/)(?:\s+(\w+))?',
                strings_match.group(1),
            ):
                identifier = s.group(1)
                if s.group(2) is not None:
                    # Text string.
                    text_str = s.group(2)
                    modifier = s.group(5) or ""
                    if modifier == "nocase":
                        strings.append(
                            (identifier, re.compile(re.escape(text_str.encode()), re.IGNORECASE))
                        )
                    else:
                        strings.append((identifier, text_str.encode()))
                elif s.group(3) is not None:
                    # Hex string — convert to bytes.
                    hex_str = re.sub(r'\s+', '', s.group(3))
                    # Handle wildcards by converting to regex.
                    if '?' in hex_str:
                        regex_str = hex_str.replace('??', '.').replace('?', '.')
                        try:
                            byte_pattern = re.compile(
                                bytes.fromhex(
                                    regex_str.replace('.', '00')
                                ).replace(b'\x00', b'.'),
                            )
                            strings.append((identifier, byte_pattern))
                        except (ValueError, re.error):
                            pass
                    else:
                        try:
                            strings.append((identifier, bytes.fromhex(hex_str)))
                        except ValueError:
                            pass
                elif s.group(4) is not None:
                    # Regex string.
                    try:
                        strings.append(
                            (identifier, re.compile(s.group(4).encode()))
                        )
                    except re.error:
                        pass

        rules.append(_SimplifiedRule(rule_name, strings, metadata, tags))
    return rules


class YaraScanner(BaseAnalyzer):
    """Scans memory regions against YARA rules.

    Uses yara-python when available, otherwise falls back to a simplified
    pattern matcher that can parse basic .yar rule files.
    """

    name = "yara_scanner"

    def __init__(self, settings: Settings | None = None):
        self._settings = settings or Settings.default()
        self._compiled_rules: Any = None
        self._simplified_rules: list[_SimplifiedRule] = []
        self._rules_loaded = False

    def _load_rules(self) -> None:
        """Load YARA rules from built-in and custom directories."""
        if self._rules_loaded:
            return

        rule_files: list[Path] = []
        if self._settings.yara.builtin_rules and RULES_DIR.exists():
            rule_files.extend(RULES_DIR.glob("*.yar"))

        for custom_dir in self._settings.yara.custom_rules_dirs:
            p = Path(custom_dir)
            if p.exists():
                rule_files.extend(p.glob("*.yar"))

        if not rule_files:
            logger.warning("No YARA rule files found")
            self._rules_loaded = True
            return

        if HAS_YARA:
            try:
                filepaths = {f"rule_{i}": str(rf) for i, rf in enumerate(rule_files)}
                self._compiled_rules = yara.compile(filepaths=filepaths)
                logger.info("Loaded %d YARA rule files with yara-python", len(rule_files))
            except Exception:
                logger.exception("Failed to compile YARA rules with yara-python, using fallback")
                self._load_simplified(rule_files)
        else:
            self._load_simplified(rule_files)

        self._rules_loaded = True

    def _load_simplified(self, rule_files: list[Path]) -> None:
        """Load rules using the simplified parser."""
        for rf in rule_files:
            try:
                self._simplified_rules.extend(_parse_yar_file(rf))
            except Exception:
                logger.exception("Failed to parse rule file: %s", rf)
        logger.info(
            "Loaded %d simplified YARA rules (yara-python not available)",
            len(self._simplified_rules),
        )

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Scan data for YARA matches and return findings."""
        self._load_rules()
        matches = self.scan(data)
        findings: list[Finding] = []
        for m in matches:
            findings.append(
                self._make_finding(
                    title=f"YARA match: {m.rule_name}",
                    description=m.description or f"Rule '{m.rule_name}' matched in memory",
                    severity=m.severity.value,
                    evidence={
                        "rule_name": m.rule_name,
                        "matched_strings": m.matched_strings,
                        "pid": m.pid,
                        "process_name": m.process_name,
                        "tags": m.tags,
                    },
                    remediation="Analyze the matched content. Cross-reference with threat intel.",
                    mitre_attack=m.metadata.get("mitre_attack", "").split(",") if m.metadata.get("mitre_attack") else [],
                )
            )
        return findings

    def scan(self, data: dict[str, Any]) -> list[YaraMatch]:
        """Scan memory data and return YaraMatch objects."""
        self._load_rules()
        matches: list[YaraMatch] = []

        # Scan string content from processes and memory regions.
        scan_targets = self._build_scan_targets(data)

        for target in scan_targets:
            content = target.get("content", b"")
            if isinstance(content, str):
                content = content.encode(errors="replace")

            if not content:
                continue

            pid = target.get("pid", 0)
            process_name = target.get("process_name", "")

            if HAS_YARA and self._compiled_rules:
                matches.extend(
                    self._scan_with_yara(content, pid, process_name)
                )
            elif self._simplified_rules:
                matches.extend(
                    self._scan_simplified(content, pid, process_name)
                )

        # Also handle pre-computed YARA matches in JSON data.
        for entry in data.get("yara_matches", []):
            matches.append(
                YaraMatch(
                    rule_name=entry.get("rule_name", "unknown"),
                    rule_file=entry.get("rule_file", ""),
                    description=entry.get("description", ""),
                    tags=entry.get("tags", []),
                    severity=Severity(entry.get("severity", "medium")),
                    pid=entry.get("pid", 0),
                    process_name=entry.get("process_name", ""),
                    offset=entry.get("offset", 0),
                    matched_strings=entry.get("matched_strings", []),
                    metadata=entry.get("metadata", {}),
                )
            )

        return matches

    def _build_scan_targets(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Build list of content blobs to scan."""
        targets: list[dict[str, Any]] = []

        # Process command lines and paths as scan targets.
        for proc in data.get("processes", []):
            combined = f"{proc.get('name', '')} {proc.get('cmdline', '')} {proc.get('path', '')}"
            targets.append({
                "content": combined,
                "pid": proc.get("pid", 0),
                "process_name": proc.get("name", ""),
            })

        # Memory region contents.
        for region in data.get("memory_regions", []):
            if "content" in region:
                targets.append({
                    "content": region["content"],
                    "pid": region.get("pid", 0),
                    "process_name": region.get("process_name", ""),
                })

        # Raw strings extracted from dump.
        if "extracted_strings" in data:
            targets.append({
                "content": "\n".join(data["extracted_strings"]),
                "pid": 0,
                "process_name": "extracted_strings",
            })

        return targets

    def _scan_with_yara(
        self, content: bytes, pid: int, process_name: str
    ) -> list[YaraMatch]:
        """Scan content using yara-python."""
        matches: list[YaraMatch] = []
        try:
            yara_matches = self._compiled_rules.match(
                data=content,
                timeout=self._settings.yara.timeout,
            )
            for ym in yara_matches:
                matched_strings = []
                for offset, identifier, data_bytes in ym.strings:
                    matched_strings.append(f"{identifier} at 0x{offset:x}")

                meta = dict(ym.meta) if hasattr(ym, 'meta') else {}
                severity_str = meta.get("severity", "medium")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM

                matches.append(
                    YaraMatch(
                        rule_name=ym.rule,
                        description=meta.get("description", ""),
                        tags=list(ym.tags) if hasattr(ym, 'tags') else [],
                        severity=severity,
                        pid=pid,
                        process_name=process_name,
                        matched_strings=matched_strings,
                        metadata=meta,
                    )
                )
        except Exception:
            logger.exception("YARA scan failed for PID %d", pid)
        return matches

    def _scan_simplified(
        self, content: bytes, pid: int, process_name: str
    ) -> list[YaraMatch]:
        """Scan content using simplified rule matching."""
        matches: list[YaraMatch] = []
        for rule in self._simplified_rules:
            matched = rule.match_data(content)
            if matched:
                severity_str = rule.metadata.get("severity", "medium")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM

                matches.append(
                    YaraMatch(
                        rule_name=rule.name,
                        description=rule.metadata.get("description", ""),
                        tags=rule.tags,
                        severity=severity,
                        pid=pid,
                        process_name=process_name,
                        matched_strings=matched,
                        metadata=rule.metadata,
                    )
                )
        return matches
