#!/usr/bin/env python3

"""
Domain Intelligence Tool
------------------------

A defensive utility for basic domain analysis.

The tool performs limited DNS resolution and does not conduct
port scanning, exploitation or intrusive reconnaissance.
"""

import socket
import sys


def normalize_domain(domain):
    """Normalize user-supplied domain input."""

    domain = domain.strip().lower()

    if domain.startswith("https://"):
        domain = domain[8:]

    elif domain.startswith("http://"):
        domain = domain[7:]

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    return domain


def resolve_domain(domain):
    """Resolve a domain to IPv4 addresses."""

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET
        )

        addresses = sorted(
            set(result[4][0] for result in results)
        )

        return addresses

    except socket.gaierror:
        return []


def generate_assessment(domain, addresses):
    """Generate a basic analytical note."""

    if addresses:
        return (
            f"The domain {domain} resolved to {len(addresses)} "
            "IPv4 address(es). The observed infrastructure can "
            "be subjected to additional authorized CTI enrichment."
        )

    return (
        f"No IPv4 resolution was returned for {domain} during "
        "the local DNS lookup."
    )


def main():
    """Main program entry point."""

    if len(sys.argv) != 2:
        print("Usage: python domain_recon.py <domain>")
        sys.exit(1)

    domain = normalize_domain(sys.argv[1])

    if not domain:
        print("Error: A domain name is required.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("CYBER THREAT INTELLIGENCE — DOMAIN ANALYSIS")
    print("=" * 60)

    print(f"\nDomain: {domain}")

    addresses = resolve_domain(domain)

    print("\nIPv4 Addresses")
    print("--------------")

    if addresses:
        for address in addresses:
            print(f"  {address}")
    else:
        print("  No IPv4 addresses returned.")

    print("\nAnalyst Assessment")
    print("------------------")
    print(generate_assessment(domain, addresses))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
