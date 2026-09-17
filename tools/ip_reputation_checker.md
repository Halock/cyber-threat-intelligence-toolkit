# IP Intelligence Checker

## Purpose

The IP Intelligence Checker is a defensive Python utility for validating and classifying IPv4 addresses.

It provides basic contextual information that can assist an analyst during the initial assessment of a network indicator.

## Capabilities

The tool can identify whether an IPv4 address is:

- Public
- Private
- Loopback
- Reserved
- Link-local
- Multicast
- Unspecified
- Invalid

## Usage

Run:

```bash
python tools/ip_reputation_checker.py <IPv4>
