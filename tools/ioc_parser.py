#!/usr/bin/env python3

"""
IOC Parser
----------

A defensive Cyber Threat Intelligence utility that identifies
common Indicators of Compromise (IOCs) from text files.

Supported indicators:
- IPv4 addresses
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- Email addresses

This tool is intended for cybersecurity education,
threat-intelligence analysis and portfolio demonstration.
"""

import re
import sys
from pathlib import Path


# Regular expressions for IOC detection

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)


def unique_matches(pattern, text):
    """Return unique matches while preserving order."""
    matches = pattern.findall(text)

    unique = []
    seen = set()

    for match in matches:
        if match not in seen:
            unique.append(match)
            seen.add(match)

    return unique


def parse_iocs(text):
    """Extract supported IOCs from supplied text."""

    return {
        "IPv4 Addresses": unique_matches(IP_PATTERN, text),
        "URLs": unique_matches(URL_PATTERN, text),
        "Email Addresses": unique_matches(EMAIL_PATTERN, text),
        "SHA256 Hashes": unique_matches(SHA256_PATTERN, text),
        "SHA1 Hashes": unique_matches(SHA1_PATTERN, text),
        "MD5 Hashes": unique_matches(MD5_PATTERN, text),
        "Domains": unique_matches(DOMAIN_PATTERN, text),
    }


def print_results(results):
    """Display extracted indicators."""

    print("\n" + "=" * 60)
    print("CYBER THREAT INTELLIGENCE — IOC PARSER")
    print("=" * 60)

    total = 0

    for category, indicators in results.items():
        print(f"\n{category}")
        print("-" * len(category))

        if indicators:
            for indicator in indicators:
                print(f"  {indicator}")
                total += 1
        else:
            print("  None detected")

    print("\n" + "=" * 60)
    print(f"Total indicators identified: {total}")
    print("=" * 60)


def main():
    """Main application entry point."""

    if len(sys.argv) != 2:
        print("Usage: python ioc_parser.py <input_file>")
        sys.exit(1)

    input_file = Path(sys.argv[1])

    if not input_file.exists():
        print(f"Error: File not found: {input_file}")
        sys.exit(1)

    if not input_file.is_file():
        print(f"Error: Path is not a file: {input_file}")
        sys.exit(1)

    try:
        text = input_file.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except OSError as error:
        print(f"Error reading file: {error}")
        sys.exit(1)

    results = parse_iocs(text)
    print_results(results)


if __name__ == "__main__":
    main()
