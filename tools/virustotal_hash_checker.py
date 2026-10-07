#!/usr/bin/env python3

"""
VirusTotal Hash Intelligence Checker
-------------------------------------

Defensive CTI utility for retrieving file hash
reputation and analysis information from VirusTotal.

Supported hashes:
- MD5
- SHA-1
- SHA-256

The API key is loaded securely from a local .env file.
"""

import json
import os
import re
import subprocess
import sys

from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/files/"


def validate_hash(file_hash):
    """Validate whether the supplied value is a supported file hash."""

    if re.fullmatch(r"[a-fA-F0-9]{32}", file_hash):
        return "MD5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", file_hash):
        return "SHA-1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", file_hash):
        return "SHA-256"

    return None


def check_hash(file_hash):
    """Query VirusTotal for information about a file hash."""

    if not API_KEY:
        print("Error: VIRUSTOTAL_API_KEY was not found.")
        print("Check that your .env file contains the API key.")
        sys.exit(1)

    endpoint = BASE_URL + file_hash

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
        elif error_code == "NotFoundError":
            print("No VirusTotal file record was found for this hash.")
        else:
            print(f"VirusTotal API error: {error_code}")
            print(error_message)

        sys.exit(1)

    return data


def main():

    if len(sys.argv) != 2:
        print("Usage: python virustotal_hash_checker.py <MD5|SHA1|SHA256>")
        sys.exit(1)

    file_hash = sys.argv[1].strip()

    hash_type = validate_hash(file_hash)

    if not hash_type:
        print("Error: Invalid file hash.")
        print("Supported formats: MD5, SHA-1, SHA-256.")
        sys.exit(1)

    data = check_hash(file_hash)

    attributes = data["data"]["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    reputation = attributes.get("reputation", 0)
    file_type = attributes.get("type_description", "N/A")
    file_size = attributes.get("size", "N/A")
    meaningful_name = attributes.get("meaningful_name", "N/A")

    print("\n" + "=" * 60)
    print("VIRUSTOTAL — FILE HASH INTELLIGENCE")
    print("=" * 60)

    print(f"\nHash         : {file_hash}")
    print(f"Hash Type    : {hash_type}")
    print(f"File Name    : {meaningful_name}")
    print(f"File Type    : {file_type}")
    print(f"File Size    : {file_size} bytes")
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
            "The file hash has malicious detections. "
            "Further investigation is recommended."
        )
    elif suspicious > 0:
        print(
            "The file hash has suspicious detections. "
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