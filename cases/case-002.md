# Phishing Analysis Report - Case 002

**Date:** 2026-06-17 22:26:26

## IOCs Analyzed
```
{
  "urls": [
    "http://www.360pps.net/wp-includes/pomo/paypal/"
  ],
  "ips": [
    "91.108.4.1"
  ],
  "files": []
}
```

## Results
```
[
  {
    "url": "http://www.360pps.net/wp-includes/pomo/paypal/",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "http://www.360pps.net/wp-includes/pomo/paypal/",
    "error": 400
  },
  {
    "ip": "91.108.4.1",
    "abuse_score": 0,
    "country": "NL",
    "total_reports": 0
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
