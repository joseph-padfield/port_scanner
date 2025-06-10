# Python Port Scanner

## Overview

A lightweight, Python-based TCP port scanner that accepts either an IP address or a domain name as a target. It scans specified ports or a default range of commonly used ports and provides real-time feedback on open ports including service names and banner information where available.

My goal in making this project was to better understand what is going on when we run an nmap scan. It was also a welcome opportunity to brush up my Python and learn some new tools. My goal having been achieved - rather than continue to polish and develop further, I decided to wrap things up at this point and move on to a new project.

I tested this tool on `scanme.nmap.org` - a URL that is designed to be scanned. I also used it on some target machines during HackTheBox challenges. Generally speaking, scanning a target without permission is illegal, so be careful!

## Features

- **Input Validation and Sanitisation**
  - Cleans input by stripping URL schemes (`http://`, `https://`) and trailing slashes.
  - Validates targets as IPv4/IPv6 addresses (using the `ipaddress` module) or domain names via regex.
  
- **Flexible Port Selection**
  - Supports single ports (e.g. `22`), ranges (e.g. `20-80`), or multiple ports and ranges separated by commas (e.g. `22,80-90,443`).
  - Validates port numbers are within the valid range (1–65535).

- **Hostname Resolution**
  - Converts domain names into their corresponding IP addresses prior to scanning.

- **Concurrent Scanning**
  - Utilises `ThreadPoolExecutor` to scan ports concurrently, greatly improving scan speed.

- **Banner Grabbing**
  - Attempts to retrieve service banners on open ports for rudimentary version and service information.

- **Colorised Output**
  - Uses `colorama` to provide colored terminal output for better user experience.

- **Command Line Interface**
  - Supports both interactive input prompts and command-line arguments via `argparse`.

## Usage

Run the scanner interactively:

```
bash
python3 scanner.py
```

You’ll be prompted for:
- Target IP address or domain name.
- Ports or port ranges to scan (press Enter to scan default ports 20-1024).

Or run with command-line arguments:

```
python3 scanner.py --target scanme.nmap.org --ports 22,80-90
```

## Requirements
- Python 3.7+
- `colorama` - `pip install colorama`
