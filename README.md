\# Phishing Analysis Lab



A structured phishing triage pipeline that mirrors real-world SOC analyst workflows.

Analyzes suspicious URLs, IPs, and file attachments using VirusTotal, AbuseIPDB, and

URLScan.io — automatically generating case reports with IOC enrichment and MITRE ATT\&CK

mappings.



\## What This Does



\- Submits suspicious URLs to VirusTotal and URLScan.io for reputation analysis

\- Checks IPs against AbuseIPDB for abuse history and geolocation

\- Hashes file attachments and checks them against VirusTotal's malware database

\- Generates structured markdown case reports with a BENIGN / SUSPICIOUS / MALICIOUS verdict

\- Maps findings to MITRE ATT\&CK techniques



\## Tools \& APIs



| Tool | Purpose |
|---|---|
| VirusTotal API | URL and file hash reputation |
| AbuseIPDB API | IP abuse scoring and geolocation |
| URLScan.io API | URL scanning and screenshot capture |
| Shodan API | Open port enumeration and infrastructure intel |
| Python (requests, dotenv) | Pipeline automation |
| Google Gemini API | AI-generated Splunk SPL detection rules and response recommendations |


\## MITRE ATT\&CK Coverage



| Technique | ID |

|---|---|

| Phishing | T1566 |

| Spearphishing Attachment | T1566.001 |

| Spearphishing Link | T1566.002 |



\## Cases Analyzed



| Case | Type | Key Finding |

|---|---|---|

| 001 | Malware delivery URL | IP 185.220.101.45 — AbuseIPDB 100/100, known Tor exit node (DE) |

| 002 | Credential harvesting (PayPal lure) | Domain no longer resolves — takedown likely |

| 003 | Compromised WordPress site | IP 185.220.101.182 — AbuseIPDB 100/100, Tor exit node (DE) |

| 004 | Admin panel exposure | IP 194.165.16.11 — AbuseIPDB 100/100, 201 reports (LT) |

| 005 | Malware staging via WordPress | Live URLScan report generated |



\## Project Structure

phishing-analysis-lab/



├── analyzer.py          # Core triage pipeline



├── cases/               # Generated case reports (Markdown)



├── samples/             # .eml phishing samples



├── iocs/



│   └── indicators.csv   # Aggregated IOCs across all cases



├── .env                 # API keys (not committed)



└── .gitignore



\> **Note:** AI detection rule generation requires a Google Gemini API key with available quota. Free tier users may need to run cases individually to stay within rate limits.

## Usage



```bash

\# Install dependencies

pip install requests python-dotenv



\# Add your API keys to .env

VIRUSTOTAL\_API\_KEY=your\_key

ABUSEIPDB\_API\_KEY=your\_key

URLSCAN\_API\_KEY=your\_key



\# Run analysis

py analyzer.py

```



\## Author



Nishanth Butta — \[github.com/nishthebish](https://github.com/nishthebish) — \[linkedin.com/in/nish-butta](https://linkedin.com/in/nish-butta)

