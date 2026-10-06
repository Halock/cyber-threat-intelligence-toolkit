# Cyber Threat Intelligence Toolkit — Tools

This directory contains defensive Python utilities developed for Cyber Threat Intelligence (CTI) analysis, indicator identification and basic infrastructure assessment.

The tools are designed for cybersecurity education, authorized investigations and portfolio demonstration.

## Available Tools

### 1. CTI Analyzer

**File:** `cti_analyzer.py`

Identifies the likely type of a supplied indicator and provides basic analytical context.

Supported indicators include:

* IPv4 addresses
* Domains
* URLs
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes

**Usage:**

```bash
python tools/cti_analyzer.py 8.8.8.8
```

Example:

```text
Type      : IPv4 Address
Next Step : Use ip_reputation_checker.py
```

---

### 2. IOC Parser

**File:** `ioc_parser.py`

Extracts common Indicators of Compromise (IOCs) from a text file.

The parser can identify:

* IPv4 addresses
* URLs
* Email addresses
* Domains
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes

**Usage:**

```bash
python tools/ioc_parser.py iocs/sample_input.txt
```

The parser produces a structured summary of the indicators identified in the input.

---

### 3. IP Intelligence Checker

**File:** `ip_reputation_checker.py`

Performs basic classification of IP addresses using Python's `ipaddress` module.

It identifies classifications such as:

* Public
* Private
* Loopback
* Reserved
* Link-local
* Multicast
* Unspecified

The tool also generates a basic analyst assessment.

**Usage:**

```bash
python tools/ip_reputation_checker.py 8.8.8.8
```

**Note:** The tool provides classification and analytical context. It does not independently establish whether a public IP address is malicious.

---

### 4. Domain Recon

**File:** `domain_recon.py`

Performs basic domain infrastructure analysis by resolving a domain to its IPv4 addresses.

**Usage:**

```bash
python tools/domain_recon.py example.com
```

The tool reports the resolved IPv4 addresses and provides basic analyst context for further authorized investigation.

---

## CTI Workflow

The tools can be used together as part of a basic indicator-analysis workflow:

```text
Indicator
    |
    v
CTI Analyzer
    |
    +---- IPv4 ----> IP Intelligence Checker
    |
    +---- Domain --> Domain Recon
    |
    +---- URL -----> Further URL Analysis
    |
    +---- Hash ----> Hash / Malware Intelligence
    |
    v
IOC Parser
    |
    v
Structured Indicator Identification
```

## Technologies

* Python 3
* Python `ipaddress` module
* Python `re` module
* Command-line interface
* DNS resolution

## Defensive Use

These utilities are intended for defensive cybersecurity, threat-intelligence analysis, education and authorized security investigations.

They do not perform exploitation, unauthorized access or intrusive network activity.

## Project Status

The toolkit is under continuous development.

Future enhancements may include:

* External threat-intelligence API integration
* WHOIS and DNS enrichment
* ASN and geolocation enrichment
* Threat-feed integration
* Hash reputation analysis
* URL reputation analysis
* Automated CTI reporting
* MITRE ATT&CK mapping
* Structured JSON output
* Analyst case-report generation
