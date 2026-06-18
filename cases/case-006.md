# Phishing Analysis Report - Case 006

**Date:** 2026-06-17 22:16:09

## IOCs Analyzed
```
{
  "urls": [
    "https://fonts.gstatic.com",
    "https://fonts.googleapis.com/css2?family=Signika:wght@300;500;700&amp;display=swap",
    "https://blog1seguimentmydomaine2bra.me/"
  ],
  "ips": [
    "137.184.34.4"
  ],
  "files": [],
  "sender": "BANCO DO BRADESCO LIVELO<banco.bradesco@atendimento.com.br>",
  "reply_to": "None",
  "subject": "CLIENTE PRIME - BRADESCO LIVELO: Seu cart\ufffd\ufffdo tem 92.990 pontos LIVELO expirando hoje!"
}
```

## Results
```
[
  {
    "url": "https://fonts.gstatic.com",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "https://fonts.gstatic.com",
    "scan_id": "019ed883-a670-7724-9e4c-606a0bcb531b",
    "report_url": "https://urlscan.io/result/019ed883-a670-7724-9e4c-606a0bcb531b/"
  },
  {
    "url": "https://fonts.googleapis.com/css2?family=Signika:wght@300;500;700&amp;display=swap",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "https://fonts.googleapis.com/css2?family=Signika:wght@300;500;700&amp;display=swap",
    "error": 400
  },
  {
    "url": "https://blog1seguimentmydomaine2bra.me/",
    "malicious": "pending",
    "suspicious": "pending"
  },
  {
    "url": "https://blog1seguimentmydomaine2bra.me/",
    "error": 400
  },
  {
    "ip": "137.184.34.4",
    "abuse_score": 13,
    "country": "US",
    "total_reports": 3
  }
]
```

## Verdict
SUSPICIOUS - Review recommended.

## MITRE ATT&CK Mapping
- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
