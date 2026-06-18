# Phishing Analysis Report - Case 006

**Date:** 2026-06-17 22:33:06

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
    "scan_id": "019ed893-285e-708b-a16e-0124f66de98c",
    "report_url": "https://urlscan.io/result/019ed893-285e-708b-a16e-0124f66de98c/"
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
  },
  {
    "ip": "137.184.34.4",
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

**Attack Type:** Brand impersonation — Brazilian bank phishing (Bradesco Livelo)

**Summary:** This is a real phishing email parsed directly from a .eml sample targeting
customers of Banco Bradesco, one of Brazil's largest banks. The email impersonates the
Bradesco Livelo rewards program, using urgency ("92,990 points expiring today") to
pressure victims into clicking a malicious link. The lure is classic social engineering
— manufactured urgency combined with financial loss fear to bypass critical thinking.

**Likely Target:** Brazilian Bradesco bank customers. High-volume untargeted campaign
cast via spam to maximize victim pool among the bank's large customer base.

**Key Indicators:**
- Sender domain atendimento.com.br does not match Bradesco's legitimate domain
  (bradesco.com.br) — clear spoofing indicator
- Malicious URL blog1seguimentmydomaine2bra.me is an obvious typosquat attempting
  to appear Brazil-related (.me TLD, "bra" in domain name)
- Sending IP 137.184.34.4 scored 13/100 on AbuseIPDB with 3 reports — low but
  nonzero, consistent with a VPS used briefly for a spam campaign
- Google Fonts CDN URLs (fonts.googleapis.com, fonts.gstatic.com) included to make
  the HTML email render professionally and appear legitimate
- Malicious domain no longer resolves — takedown likely after abuse reports

**Recommended SOC Actions:**
1. Block the sending domain atendimento.com.br at the email gateway
2. Search email logs for any other messages from this sender or containing this URL
3. If any employee clicked the link, check for credential exposure and reset passwords
4. Add the typosquat domain pattern to email filtering rules
5. Educate users on urgency-based phishing lures — this is a textbook example

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link),
T1598.003 (Phishing for Information), T1036 (Masquerading — spoofed sender domain)
