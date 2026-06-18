# Phishing Analysis Report - Case 001

**Date:** 2026-06-17 21:45:19

## IOCs Analyzed
```
{
  "urls": [
    "http://malware.wicar.org/data/ms14_064_ole_not_xp.html"
  ],
  "ips": [
    "185.220.101.45"
  ],
  "files": []
}
```

## Results
```
[
  {
    "url": "http://malware.wicar.org/data/ms14_064_ole_not_xp.html",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "http://malware.wicar.org/data/ms14_064_ole_not_xp.html",
    "scan_id": "019ed867-76ff-7469-9b40-c97eb9571dc0",
    "report_url": "https://urlscan.io/result/019ed867-76ff-7469-9b40-c97eb9571dc0/"
  },
  {
    "ip": "185.220.101.45",
    "abuse_score": 100,
    "country": "DE",
    "total_reports": 124
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
