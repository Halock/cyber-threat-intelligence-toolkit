#!/usr/bin/env python3

"""
VirusTotal URL Intelligence Checker
------------------------------------

Defensive CTI utility for retrieving URL reputation
and analysis information from VirusTotal.

The API key is loaded securely from a local .env file.
"""

import base64
import json
import os
import subprocess
import sys

from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/urls/"


def encode_url(url):
    """Encode a URL into the identifier required by VirusTotal."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url(url):
    """Query VirusTotal for information about a URL."""

    if not API_KEY:
        print("Error: VIRUSTOTAL_API_KEY was not found.")
        print("Check that your .env file contains the API key.")
        sys.exit(1)

    url_id = encode_url(url)
    endpoint = BASE_URL + url_id

    command = [
        "curl.exe",
        "--ssl-no-revoke",
        "-sS",
        "-H",
        f"x-apikey: {API_KEY}",
        "-H",
        "Accept: application/json",
        "-H",
        "User-Agent: CTI-Toolkit/1.0",
        endpoint,
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
        if result.stderr.strip():
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
        print("Usage: python virustotal_url_checker.py <URL>")
        sys.exit(1)

    url = sys.argv[1].strip()

    if not url.startswith(("http://", "https://")):
        print("Error: Please provide a valid HTTP or HTTPS URL.")
        sys.exit(1)

    data = check_url(url)

    attributes = data["data"]["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    reputation = attributes.get("reputation", 0)
    title = attributes.get("title", "N/A")
    final_url = attributes.get("last_final_url", url)
    http_code = attributes.get("last_http_response_code", "N/A")

    print("\n" + "=" * 60)
    print("VIRUSTOTAL — URL INTELLIGENCE")
    print("=" * 60)

    print(f"\nURL          : {url}")
    print(f"Final URL    : {final_url}")
    print(f"Page Title   : {title}")
    print(f"HTTP Status  : {http_code}")
    print(f"Reputation   : {reputation}")

    print("\nAnalysis Results")
    print("----------------")
    print(f"Malicious    : {malicious}")
    print(f"Suspicious   : {suspicious}")
    print(f"Harmless     : {harmless}")
    print(f"Undetected   : {undetected}")

    print("\nAnalyst Assessment")
    print("------------------")

    if malicious > 0:
        print(
            "The URL has malicious detections. "
            "Further investigation is recommended."
        )
    elif suspicious > 0:
        print(
            "The URL has suspicious detections. "
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