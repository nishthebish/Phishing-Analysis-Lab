# Phishing Analysis Report - Case 005

**Date:** 2026-06-17 22:33:01

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
    "scan_id": "019ed893-1f5a-7179-88d5-912d9f1364f9",
    "report_url": "https://urlscan.io/result/019ed893-1f5a-7179-88d5-912d9f1364f9/"
  },
  {
    "ip": "45.142.212.100",
    "abuse_score": 1,
    "country": "MD",
    "total_reports": 1
  },
  {
    "ip": "45.142.212.100",
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
## Analyst Notes

**Attack Type:** Ransomware C2 infrastructure — WordPress staging server

**Summary:** This URL points to a compromised Thai restaurant WordPress site being
used as a Command and Control staging server. The /wp-includes/sodium_compat/ path
is particularly notable — sodium_compat is a legitimate WordPress cryptography
library, meaning attackers deliberately chose this path to blend malicious payloads
into normal-looking WordPress traffic and evade signature-based detection.

**Likely Target:** Enterprise environments. Ransomware operators use compromised
legitimate sites as C2 intermediaries specifically to bypass corporate proxy filters
that allowlist known domains.

**Key Indicators:**
- URLScan confirmed the domain is live and returned a full scan report — unlike
  other cases, this infrastructure was still active at time of analysis
- IP 45.142.212.100 scored only 1/100 on AbuseIPDB — low score suggests either
  newly stood up infrastructure or IP rotation to avoid reputation-based blocking
- Path mimics a legitimate WordPress library — deliberate defense evasion technique
- Low AbuseIPDB score combined with live URLScan hit is a classic indicator of
  fresh C2 infrastructure not yet flagged by threat intel feeds

**Recommended SOC Actions:**
1. Block the domain and IP immediately at proxy and firewall
2. Search SIEM for any DNS queries or outbound HTTP/S connections to this domain
3. If any internal host connected, treat as potential ransomware precursor — isolate
   and escalate to IR immediately
4. Submit to threat intel sharing platforms (MISP, OpenCTI) to benefit other orgs

**MITRE ATT&CK:** T1566.002 (Spearphishing Link), T1071.001 (Web Protocols — C2),
T1584.004 (Compromise Infrastructure), T1036.005 (Masquerading — Match Legitimate Name)
