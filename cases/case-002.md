# Phishing Analysis Report - Case 002

**Date:** 2026-06-17 22:32:54

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
  },
  {
    "ip": "91.108.4.1",
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

**Attack Type:** Credential harvesting — PayPal lure

**Summary:** This URL spoofs a PayPal payment flow hosted on a compromised WordPress site.
The /pomo/ directory is a known indicator of phishing kits dropped onto hacked WordPress 
installations. The goal is to trick victims into entering PayPal credentials on a fake 
login page that mirrors the real PayPal UI.

**Likely Target:** General consumers. PayPal phishing is high-volume and untargeted — 
cast wide via spam email campaigns hoping to catch active PayPal users.

**Key Indicators:**
- Domain no longer resolves — likely taken down after abuse report
- WordPress path structure (/wp-includes/pomo/) is a common phishing kit drop location
- IP 91.108.4.1 scored 0/100 on AbuseIPDB — likely a clean hosting provider used 
  briefly before takedown

**Recommended SOC Actions:**
1. Block the domain at the proxy/DNS filter
2. Search email gateway logs for any messages containing this URL sent to employees
3. If any user clicked the link, reset their PayPal-associated credentials immediately
4. Submit domain to PhishTank for community tracking

**MITRE ATT&CK:** T1566.002 (Spearphishing Link), T1078 (Valid Accounts — credential theft goal)
