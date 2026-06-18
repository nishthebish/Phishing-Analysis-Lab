# Phishing Analysis Report - Case 003

**Date:** 2026-06-17 23:20:24

## IOCs Analyzed
```
{
  "urls": [
    "http://inexistente.lojaclothing.com.br/wp-admin/css/colors/midnight/"
  ],
  "ips": [
    "185.220.101.182"
  ],
  "files": []
}
```

## Results
```
[
  {
    "url": "http://inexistente.lojaclothing.com.br/wp-admin/css/colors/midnight/",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "http://inexistente.lojaclothing.com.br/wp-admin/css/colors/midnight/",
    "error": 400
  },
  {
    "ip": "185.220.101.182",
    "abuse_score": 100,
    "country": "DE",
    "total_reports": 97
  },
  {
    "ip": "185.220.101.182",
    "found": false
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
