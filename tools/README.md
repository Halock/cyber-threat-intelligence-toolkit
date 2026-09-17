# CTI Tools

This directory contains Python utilities developed for Cyber Threat Intelligence (CTI) analysis and cybersecurity automation.

## Available Tools

### IOC Parser

`ioc_parser.py` automatically extracts common Indicators of Compromise from text files.

Supported indicators include:

- IPv4 addresses
- Domains
- URLs
- Email addresses
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

## Usage

Run the parser from a terminal:

```bash
python tools/ioc_parser.py iocs/sample_input.txt
