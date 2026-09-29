#!/usr/bin/env python3

"""
CTI Analyzer
------------

A defensive Cyber Threat Intelligence utility that identifies
the likely type of an indicator and provides basic analytical
context.

Supported indicators:
- IPv4 addresses
- Domains
- URLs
- File hashes

Designed for cybersecurity education and portfolio use.
"""

import ipaddress
import re
import sys


def is_ipv4(indicator):
    """Check whether the indicator is an IPv4 address."""
    try:
        address = ipaddress.ip_address(indicator)
        return address.version == 4
    except ValueError:
        return False


def is_url(indicator):
    """Check whether the indicator is a URL."""
    pattern = r"^https?://[^\s]+$"
    return bool(re.match(pattern, indicator, re.IGNORECASE))


def is_domain(indicator):
    """Check whether the indicator is a domain name."""
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, indicator))


def is_hash(indicator):
    """Check whether the indicator resembles a common file hash."""
    return bool(
        re.fullmatch(
            r"(?:[a-fA-F0-9]{32}|"
            r"[a-fA-F0-9]{40}|"
            r"[a-fA-F0-9]{64})",
            indicator
        )
    )


def analyze_indicator(indicator):
    """Identify the indicator type and provide basic context."""

    if is_ipv4(indicator):
        return {
            "type": "IPv4 Address",
            "action": "Use ip_reputation_checker.py",
            "context": (
                "The indicator is an IPv4 address. "
                "IP classification and reputation enrichment "
                "can be performed."
            )
        }

    if is_url(indicator):
        return {
            "type": "URL",
            "action": "Perform URL analysis",
            "context": (
                "The indicator is a URL. "
                "Further analysis may include domain, hosting, "
                "certificate and reputation information."
            )
        }

    if is_hash(indicator):
        return {
            "type": "File Hash",
            "action": "Perform malware/hash intelligence lookup",
            "context": (
                "The indicator resembles a file hash. "
                "Threat-intelligence databases can be used "
                "for malware identification and reputation analysis."
            )
        }

    if is_domain(indicator):
        return {
            "type": "Domain",
            "action": "Use domain_recon.py",
            "context": (
                "The indicator is a domain name. "
                "Domain intelligence and infrastructure analysis "
                "can be performed."
            )
        }

    return {
        "type": "Unknown",
        "action": "Manual validation required",
        "context": (
            "The supplied indicator could not be confidently "
            "classified by this tool."
        )
    }


def main():

    if len(sys.argv) != 2:
        print("Usage: python cti_analyzer.py <indicator>")
        sys.exit(1)

    indicator = sys.argv[1].strip()

    result = analyze_indicator(indicator)

    print("\n" + "=" * 60)
    print("CYBER THREAT INTELLIGENCE — ANALYZER")
    print("=" * 60)

    print(f"\nIndicator : {indicator}")
    print(f"Type      : {result['type']}")
    print(f"Next Step : {result['action']}")

    print("\nAnalytical Context")
    print("------------------")
    print(result["context"])

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
