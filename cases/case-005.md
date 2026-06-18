# Phishing Analysis Report - Case 005

**Date:** 2026-06-17 22:26:32

## IOCs Analyzed
```
{
  "urls": [
    "http://thaibangkokrestaurant.com/wp-includes/sodium_compat/"
  ],
  "ips": [
    "45.142.212.100"
  ],
  "files": []
}
```

## Results
```
[
  {
    "url": "http://thaibangkokrestaurant.com/wp-includes/sodium_compat/",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "http://thaibangkokrestaurant.com/wp-includes/sodium_compat/",
    "scan_id": "019ed88d-30e0-724b-9d1a-ef10204a83ab",
    "report_url": "https://urlscan.io/result/019ed88d-30e0-724b-9d1a-ef10204a83ab/"
  },
  {
    "ip": "45.142.212.100",
    "abuse_score": 1,
    "country": "MD",
    "total_reports": 1
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
