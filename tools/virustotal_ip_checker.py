#!/usr/bin/env python3

"""
VirusTotal IP Intelligence Checker
-----------------------------------

Defensive CTI utility for retrieving basic IP reputation
information from VirusTotal.

The API key is loaded securely from a local .env file.
"""

import json
import os
import subprocess
import sys

from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def check_ip(ip_address):
    """Query VirusTotal for information about an IP address."""

    if not API_KEY:
        print("Error: VIRUSTOTAL_API_KEY was not found.")
        print("Check that your .env file contains the API key.")
        sys.exit(1)

    url = BASE_URL + ip_address

    command = [
        "curl.exe",
        "--ssl-no-revoke",
        "-s",
        "-H",
        f"x-apikey: {API_KEY}",
        "-H",
        "Accept: application/json",
        "-H",
        "User-Agent: CTI-Toolkit/1.0",
        url,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        print("Connection error: VirusTotal request timed out.")
        sys.exit(1)
    except OSError as error:
        print(f"Connection error: Unable to execute curl.exe: {error}")
        sys.exit(1)

    if result.returncode != 0:
        print("Connection error: VirusTotal request failed.")
        print(result.stderr.strip())
        sys.exit(1)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error: VirusTotal returned an invalid response.")
        print(result.stdout)
        sys.exit(1)

    if "error" in data:
        error_code = data["error"].get("code", "UnknownError")
        error_message = data["error"].get("message", "Unknown error")

        if error_code == "WrongCredentialsError":
            print("Error: VirusTotal API key is invalid or unauthorized.")
        else:
            print(f"VirusTotal API error: {error_code}")
            print(error_message)

        sys.exit(1)

    return data


def main():

    if len(sys.argv) != 2:
        print("Usage: python virustotal_ip_checker.py <IPv4>")
        sys.exit(1)

    ip_address = sys.argv[1].strip()

    data = check_ip(ip_address)

    attributes = data["data"]["attributes"]

    reputation = attributes.get("reputation", 0)
    malicious = attributes.get("last_analysis_stats", {}).get("malicious", 0)
    suspicious = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
    harmless = attributes.get("last_analysis_stats", {}).get("harmless", 0)
    undetected = attributes.get("last_analysis_stats", {}).get("undetected", 0)

    print("\n" + "=" * 60)
    print("VIRUSTOTAL — IP INTELLIGENCE")
    print("=" * 60)

    print(f"\nIP Address : {ip_address}")
    print(f"Reputation : {reputation}")

    print("\nAnalysis Results")
    print("----------------")
    print(f"Malicious  : {malicious}")
    print(f"Suspicious : {suspicious}")
    print(f"Harmless   : {harmless}")
    print(f"Undetected : {undetected}")

    print("\nAnalyst Assessment")
    print("------------------")

    if malicious > 0:
        print(
            "The IP address has malicious detections. "
            "Further investigation is recommended."
        )
    elif suspicious > 0:
        print(
            "The IP address has suspicious detections. "
            "Additional contextual analysis is recommended."
        )
    else:
        print(
            "No malicious or suspicious detections were reported "
            "in the returned analysis."
        )

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()