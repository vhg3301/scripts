# Python Port Scanner

A smart and powerful scanner that helps you scan networks, ports, and gather important information such as firewall detection.

## Features

- TCP/UDP port scanning
- Automatic service identification (SSH, HTTP/S, FTP, etc.)
- Firewall detection for filtered ports
- Multithreading for fast scans
- Clean and professional outputs

## Usage

```bash
python3 scanner.py

# Output example
[+] Port TCP 22 (SSH) is open!
[+] Port TCP 80 (HTTP) is open!
[~] Port TCP 25 (SMTP) - firewall detected!

# Legal Notice

Only perform scans on networks and ports you are authorized to test. This tool is not intended for illegal purposes.

# How to obtain 

git clone https://github.com/vhg3301/scripts.git
cd scripts
python3 scanner.py

