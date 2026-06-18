# Phishing Analysis Report - Case 004

**Date:** 2026-06-17 22:26:29

## IOCs Analyzed
```
{
  "urls": [
    "http://arraiolosmktplace.com/wp-admin/"
  ],
  "ips": [
    "194.165.16.11"
  ],
  "files": []
}
```

## Results
```
[
  {
    "url": "http://arraiolosmktplace.com/wp-admin/",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "http://arraiolosmktplace.com/wp-admin/",
    "error": 400
  },
  {
    "ip": "194.165.16.11",
    "abuse_score": 100,
    "country": "LT",
    "total_reports": 201
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
