# IOC to Splunk Query Generator

A powerful, lightweight CLI tool built for SOC analysts and cybersecurity professionals to eliminate manual IOC cleanup and move faster during investigations.

---

## The Problem

In real-world SOC operations, threat intelligence rarely arrives clean.

Analysts often receive:
- Defanged URLs (`hxxp`, `[.]`)
- Mixed IOC types
- Duplicate entries
- Invalid or malformed strings
- Large bulk lists requiring normalization

Manually converting these into a structured Splunk query wastes time and introduces errors.

Time matters during investigations.

---

## The Solution

---

## 🌐 Web Version

For a more user-friendly experience, a web-based version of this tool is also available.

👉 https://claude.ai/public/artifacts/feb12dd4-1a4e-4864-9e7c-097e73599545

The web interface allows analysts to paste IOCs, review results, and generate Splunk queries without using the command line.

**IOC to Splunk Query Generator** automates the entire cleanup and transformation process.

Paste raw IOCs → Get a clean, ready-to-run Splunk query.

No formatting.  
No manual editing.  
No duplicate hunting.  

Just actionable results.

---

## Key Capabilities

- 🔎 Detects IPv4 and IPv6
- 🌐 Detects domains and URLs
- 🧬 Detects MD5, SHA1, SHA256 hashes
- 🔄 Automatically refangs:
  - `hxxp` / `hxxps`
  - `h__p` / `h__ps`
  - `[.]`
  - `[:]`
- 🧹 Removes duplicates automatically
- 🚫 Ignores invalid input safely
- 📊 Provides structured IOC summary
- 🎯 Generates SOC-ready Splunk OR queries
- ⚡ Pure Python — zero external dependencies

Built for operational efficiency.

---

## How It Works

Run the script:

```bash
python ioc_to_splunk.py


Paste your IOCs when prompted:jb

(CTRL+D to finish on Linux/macOS, CTRL+Z on Windows)
 --  Paste your IOCs Below --------

End input and receive:

Total valid findings
IOC type breakdown
Duplicate count
Invalid count
Fully formatted Splunk query

---

Raw Intelligence Input:

hxxp://malicious[.]site/login
192.168.1.10
5f4dcc3b5aa765d61d8327deb882cf99
invalid_string
192.168.1.10

Generated Output:

--- Total Findings: 3 ---
- Domains: 0
- Hashes: 1
- All IPs: 1
 -IPv4: 1
 -IPv6: 0

- doublicated IOCs: 1
- invalid IOCs and ignored: 1

=== Splunk Query ===

index=* ("*malicious.site*login" OR "192.168.1.10" OR "5f4dcc3b5aa765d61d8327deb882cf99")

---

Why This Project Matters:
This tool was built from real SOC workflow experience.


Requirements:
Python 3.x
No external libraries required


Author:
Mohamed Zourob
Cybersecurity Analyst | SOC Operations & Automation