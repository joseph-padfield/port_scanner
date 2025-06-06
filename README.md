# Python Port Scanner — Work In Progress

## Overview

This is a simple Python-based port scanner designed to take either an IP address or a domain name as a target. The program can scan a default range of common ports or user-specified ports and port ranges.

## Features Implemented So Far
- Input Validation and Sanitisation
  - Strips URL prefixes such as http:// and https:// and trailing slashes from the target input.
  - Validates the target as a proper IPv4 address or domain name using regex and range checks.
- Parses user-defined port inputs which can be:
  - Single ports (e.g., 22)
  - Port ranges (e.g., 20-80)
  - Multiple ports and ranges separated by commas (e.g., 22,80-90,443)
- Ensures port numbers are within the valid range of 1 to 65535 and raises clear errors for invalid input.
- Hostname Resolution
  - Converts domain names to their corresponding IP addresses before scanning.
- Error Handling

## How to Use

Run the script directly and provide inputs when prompted:

`python3 scanner.py`

- Enter the target IP or domain name.
- Enter ports or port ranges to scan using formats like 22, 20-80, or 22,80-90.

## Next Steps
- Implement the port scanning logic (attempt TCP connections to the specified ports).
- Add service identification for open ports.
- Integrate command-line argument parsing using argparse for a flexible CLI interface.
