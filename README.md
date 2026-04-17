# GhostForensics

Memory forensics automation tool for incident response. Wraps Volatility3 to automate RAM dump analysis, IOC extraction, and report generation for SOC teams.

## Features

- **Process Analysis** — Extracts process tree, detects hidden processes, orphans, name masquerading, and duplicate system processes
- **Network Analysis** — Extracts connections, flags suspicious ports, external IPs from system processes, and lateral movement indicators
- **Injection Detection** — Identifies process hollowing, DLL injection, RWX memory regions, and reflective loading
- **Handle Analysis** — Detects suspicious mutexes, sensitive file access (SAM, NTDS.dit), and cross-process handle abuse
- **YARA Scanning** — Scans memory with built-in and custom YARA rules (works with or without yara-python)
- **IOC Extraction** — Extracts IPs, domains, URLs, hashes, registry keys, and emails with deduplication and STIX 2.1 export
- **Reputation Checking** — Optional integration with VirusTotal and AbuseIPDB
- **Reports** — Console (Rich), HTML (dark-themed), and JSON output formats

## Installation

```bash
pip install -e .
```

With optional dependencies:

```bash
# Volatility3 support
pip install -e ".[volatility]"

# YARA support
pip install -e ".[yara]"

# Everything
pip install -e ".[all]"
```

## Quick Start

Analyze a memory dump (JSON format):

```bash
ghostforensics analyze examples/sample_dump.json
```

Generate an HTML report:

```bash
ghostforensics analyze examples/sample_dump.json --output report.html
```

Export as JSON:

```bash
ghostforensics analyze examples/sample_dump.json --output report.json --format json
```

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Full analysis with all modules |
| `processes` | List processes and detect anomalies |
| `network` | List network connections and flags |
| `yara` | Scan with YARA rules |
| `ioc` | Extract IOCs (supports `--stix` for STIX 2.1 export) |
| `report` | Generate a standalone report file |

## Input Formats

GhostForensics works **without Volatility3 installed** by accepting JSON files that represent pre-processed memory dump data. When Volatility3 is available, it can also analyze raw `.raw`, `.dmp`, and `.vmem` files directly.

### JSON Format

See `examples/sample_dump.json` for the complete schema. Key sections:

- `processes` — List of process objects (pid, ppid, name, path, cmdline)
- `connections` — Network connections (local/remote addr and port, state, pid)
- `memory_regions` — Memory regions with protection flags
- `handles` — Open handles (mutexes, files, registry keys)
- `yara_matches` — Pre-computed YARA matches
- `extracted_strings` — Raw strings from the dump

## IOC Extraction

GhostForensics extracts and classifies indicators across all analysis modules:

```
IOCs Extracted: 12
  [high] ip-address: 45.33.32.156 — connection from svchost.exe (PID 4444)
  [high] ip-address: 185.220.101.42 — connection from svchost.exe (PID 4444)
  [medium] url: http://evil.com/payload.ps1 — raw_data
  [critical] ip-address: 91.215.85.209 — connection from powershell.exe (PID 4600)
  [low] email: admin@evil-corp.com — raw_data
```

Export in STIX 2.1 format:

```bash
ghostforensics ioc examples/sample_dump.json --stix
```

## YARA Rules

Built-in rules cover:

- `malware_indicators.yar` — Malware API calls, packer signatures, suspicious user agents
- `webshells.yar` — PHP, ASPX, and JSP webshell patterns
- `credentials.yar` — Mimikatz, credential dumping tools, SSH keys
- `persistence.yar` — Registry run keys, scheduled tasks, WMI persistence

Add custom rules:

```bash
ghostforensics yara dump.json --rules /path/to/custom/rules/
```

## Configuration

Create a `config.yml`:

```yaml
analyzer:
  enable_process_analysis: true
  enable_network_analysis: true
  enable_injection_analysis: true
  enable_handle_analysis: true
  enable_yara_scan: true
  enable_ioc_extraction: true

yara:
  builtin_rules: true
  custom_rules_dirs:
    - /opt/yara-rules/
  timeout: 60

reputation:
  enable_online_checks: true
  virustotal_api_key: ${VT_API_KEY}
  abuseipdb_api_key: ${ABUSEIPDB_API_KEY}

report:
  output_format: html
  include_evidence: true
  include_remediation: true
  include_mitre: true
```

```bash
ghostforensics analyze dump.json --config config.yml --output report.html
```

## Development

```bash
pip install -e ".[dev]"
make test
make lint
```

## License

MIT License. Copyright (c) 2026 Joe Munene.
