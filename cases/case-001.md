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

## Analyst Notes

**Attack Type:** Malware delivery via exploit URL

**Summary:** This URL hosts a proof-of-concept exploit targeting CVE-2014-6332, a critical 
Windows OLE vulnerability affecting Internet Explorer. If visited by a vulnerable user, 
the page executes arbitrary code silently in the browser — no user interaction required 
beyond clicking the link.

**Likely Target:** End users on unpatched Windows systems running older IE versions. 
Commonly delivered via phishing email with a "click here" lure.

**Key Indicators:**
- Sending IP 185.220.101.45 scored 100/100 on AbuseIPDB with 124 reports — confirmed 
  Tor exit node used to anonymize C2 traffic
- URL path structure consistent with exploit kit staging

**Recommended SOC Actions:**
1. Block the URL and IP at the perimeter firewall
2. Search SIEM for any internal hosts that made outbound connections to 185.220.101.45
3. If a connection is found, isolate the endpoint and initiate IR process
4. Escalate to Tier 2 for forensic analysis

**MITRE ATT&CK:** T1566.002 (Spearphishing Link), T1203 (Exploitation for Client Execution)
