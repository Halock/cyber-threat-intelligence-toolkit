#!/usr/bin/env python3

"""
IP Intelligence Checker
-----------------------

A defensive Cyber Threat Intelligence utility for classifying
IPv4 addresses and generating basic analytical context.

The tool does not perform scanning, exploitation or intrusive
network activity.

Designed for cybersecurity education and portfolio use.
"""

import ipaddress
import sys


def classify_ip(ip):
    """
    Classify an IPv4 address using Python's ipaddress module.
    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "valid": False,
            "classification": "Invalid IP address",
            "details": "The supplied value is not a valid IP address."
        }

    if address.is_loopback:
        classification = "Loopback"
        details = "The address refers to the local host."

    elif address.is_private:
        classification = "Private"
        details = "The address belongs to a private address range."

    elif address.is_reserved:
        classification = "Reserved"
        details = "The address belongs to a reserved address range."

    elif address.is_link_local:
        classification = "Link-local"
        details = "The address is intended for local network communication."

    elif address.is_multicast:
        classification = "Multicast"
        details = "The address is used for multicast communication."

    elif address.is_unspecified:
        classification = "Unspecified"
        details = "The address represents an unspecified host."

    else:
        classification = "Public"
        details = "The address is not classified as private or reserved."

    return {
        "valid": True,
        "classification": classification,
        "details": details
    }


def generate_assessment(ip, result):
    """
    Generate a simple CTI analyst note.
    """

    if not result["valid"]:
        return (
            f"Assessment: {ip} requires validation because "
            "the supplied value is not a valid IPv4 address."
        )

    classification = result["classification"]

    if classification == "Public":
        return (
            f"Assessment: {ip} is classified as a public IPv4 address. "
            "Additional reputation and infrastructure enrichment may "
            "be required during an investigation."
        )

    return (
        f"Assessment: {ip} is classified as {classification.lower()}. "
        "Its classification should be considered when interpreting "
        "network activity associated with the indicator."
    )


def main():
    """
    Main program entry point.
    """

    if len(sys.argv) != 2:
        print("Usage: python ip_reputation_checker.py <IPv4>")
        sys.exit(1)

    ip = sys.argv[1]

    result = classify_ip(ip)

    print("\n" + "=" * 60)
    print("CYBER THREAT INTELLIGENCE — IP INTELLIGENCE CHECKER")
    print("=" * 60)

    print(f"\nIndicator: {ip}")
    print(f"Valid: {result['valid']}")
    print(f"Classification: {result['classification']}")
    print(f"Details: {result['details']}")

    print("\nAnalyst Assessment")
    print("------------------")
    print(generate_assessment(ip, result))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
