#!/usr/bin/env python3
"""
ioc_to_splunk.py

SOC-friendly tool to generate Splunk queries from Indicators of Compromise (IOCs).
- Supports IPv4, IPv6, domains, URLs, and hashes (MD5, SHA1, SHA256)
- Accepts pasted input or text file
- Refangs IOCs (hxxp, hxxps, h__p, [.] etc.)
- Converts URLs to Splunk wildcard format
- Deduplicates automatically
- Prints warning count for invalid IOCs
"""

import re
import sys
from pathlib import Path
 

# -----------------------------
# Regex definitions
# -----------------------------
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$', re.IGNORECASE)
SHA1_REGEX   = re.compile(r'^[a-fA-F0-9]{40}$', re.IGNORECASE)
MD5_REGEX    = re.compile(r'^[a-fA-F0-9]{32}$', re.IGNORECASE)

IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

IPV6_REGEX = re.compile(
    r'^('
    r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,7}:|'
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)'
    r')$', re.IGNORECASE
)

URL_REGEX = re.compile(r'^https?:\/\/[a-zA-Z0-9\-\.]+', re.IGNORECASE)

DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9]'
    r'([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]'
    r'([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
)

# -----------------------------
# Refang logic
# -----------------------------
def refang_ioc(ioc: str) -> str:
    refanged = (
        ioc.replace('[.]', '.')
           .replace('[:]', ':')
           .replace('hxxp://', 'http://')
           .replace('hxxps://', 'https://')
           .replace('h__p://', 'http://')
           .replace('h__ps://', 'https://')
    )

    # URL → Splunk wildcard
    match = re.match(r'^https?:\/\/(.+)', refanged, re.IGNORECASE)
    if match:
        url_path = match.group(1)
        return '*' + url_path.replace('/', '*')

    return refanged

# -----------------------------
# IOC detection
# -----------------------------
def detect_ioc_type(ioc: str) -> str:
    if not ioc or not isinstance(ioc, str):
        return 'unknown'

    test_ioc = (
        ioc.strip()
           .replace('[.]', '.')
           .replace('[:]', ':')
           .replace('hxxp://', 'http://')
           .replace('hxxps://', 'https://')
           .replace('h__p://', 'http://')
           .replace('h__ps://', 'https://')
    )

    if SHA256_REGEX.match(test_ioc):
        return 'hash'
    if SHA1_REGEX.match(test_ioc):
        return 'hash'
    if MD5_REGEX.match(test_ioc):
        return 'hash'
    if IPV4_REGEX.match(test_ioc):
        return 'ip'
    if IPV6_REGEX.match(test_ioc):
        return 'ip'
    if URL_REGEX.match(test_ioc):
        return 'url'
    if DOMAIN_REGEX.match(test_ioc):
        return 'domain'
    return 'unknown'

def is_valid_ioc(value: str) -> bool:
    return detect_ioc_type(value) != 'unknown'

# -----------------------------
# Splunk query generation
# -----------------------------
def generate_splunk_query(iocs: list[str]) -> str:
    unique_iocs = sorted(set(iocs))  # Deduplicate
    quoted = [f'"{ioc}"' for ioc in unique_iocs]
    return f'index=* ({" OR ".join(quoted)})'

# -----------------------------
# CLI main function
# -----------------------------
def main():
    # Print custom welcome message
    print("\n=== Welcom to IOC Splunk query Generator ===")
    print("-- Devolped by Zourob\n")
    print("(CTRL+D to finish on Linux/macOS, CTRL+Z on Windows)")
    print(" --  Paste your IOCs Below --------  \n")

    # Read from stdin only
    lines = sys.stdin.readlines()

    # Process IOCs and print detailed stats
    refanged_iocs = []
    invalid_count = 0
    duplicate_count = 0

    # Track unique findings by type
    type_sets = {
        'domain': set(),
        'hash': set(),
        'ipv4': set(),
        'ipv6': set(),
    }
    all_ips = set()
    seen_iocs = set()

    for line in lines:
        # Remove comments and extra whitespace
        ioc = line.split('#')[0].strip()
        if not ioc:
            continue
        ioc_type = detect_ioc_type(ioc)
        if ioc_type != 'unknown':
            ref = refang_ioc(ioc)
            # Count duplicates (ignore whitespace/comments)
            if ref in seen_iocs:
                duplicate_count += 1
            else:
                seen_iocs.add(ref)
            refanged_iocs.append(ref)
            # Classify by type
            if ioc_type == 'domain':
                type_sets['domain'].add(ref)
            elif ioc_type == 'hash':
                type_sets['hash'].add(ref)
            elif ioc_type == 'ip':
                # Distinguish IPv4/IPv6
                if IPV4_REGEX.match(ref):
                    type_sets['ipv4'].add(ref)
                elif IPV6_REGEX.match(ref):
                    type_sets['ipv6'].add(ref)
                all_ips.add(ref)
        else:
            # Only count truly invalid (not empty/comment)
            invalid_count += 1

    if not refanged_iocs:
        print("[ERROR] No valid IOCs detected.")
        sys.exit(1)

    total_findings = len(seen_iocs)
    print()
    print(f"--- Total Findings: {total_findings} ---")
    print(f"- Domains: {len(type_sets['domain'])}")
    print(f"- Hashes: {len(type_sets['hash'])}")
    print(f"- All IPs: {len(type_sets['ipv4']) + len(type_sets['ipv6'])}")
    print(f" -IPv4: {len(type_sets['ipv4'])}")
    print(f" -IPv6: {len(type_sets['ipv6'])}")
    print()
    print(f"- doublicated IOCs: {duplicate_count}")
    print(f"- invalid IOCs and ignored: {invalid_count}")
    print()
    print("=== Splunk Query ===\n")
    query = generate_splunk_query(refanged_iocs)
    print(query)
    print("\n(; === Devolped by Zourob === ;)")

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    main()
    # Prevent window from closing immediately if run from double-click/Notepad
    try:
        input("\nPress Enter to end...")
    except EOFError:
        pass
