import requests
import json
import os
import hashlib
import email
import re
import glob
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime
from google import genai

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


def check_url_virustotal(url):
    print(f"\n[VT] Checking URL: {url}")
    headers = {"x-apikey": VT_API_KEY}
    encoded = requests.utils.quote(url, safe="")
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded}", headers=headers
    )
    if resp.status_code == 200:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        print(f"    Malicious: {malicious} | Suspicious: {suspicious}")
        return {"url": url, "malicious": malicious, "suspicious": suspicious}
    else:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
        )
        print(f"    Submitted to VT for scanning. Status: {resp.status_code}")
        return {"url": url, "malicious": "pending", "suspicious": "pending"}


def check_ip_abuseipdb(ip):
    print(f"\n[AbuseIPDB] Checking IP: {ip}")
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params
    )
    if resp.status_code == 200:
        data = resp.json()["data"]
        score = data["abuseConfidenceScore"]
        country = data["countryCode"]
        total_reports = data["totalReports"]
        print(f"    Abuse Score: {score}/100 | Country: {country} | Reports: {total_reports}")
        return {"ip": ip, "abuse_score": score, "country": country, "total_reports": total_reports}
    else:
        print(f"    Error: {resp.status_code}")
        return {"ip": ip, "error": resp.status_code}


def check_ip_shodan(ip):
    print(f"\n[Shodan] Checking IP: {ip}")
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        )
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "Unknown")
            country = data.get("country_name", "Unknown")
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            vulns = list(data.get("vulns", {}).keys())
            print(f"    Org: {org} | Country: {country}")
            print(f"    Open Ports: {ports}")
            if vulns:
                print(f"    Vulnerabilities: {vulns}")
            return {
                "ip": ip,
                "org": org,
                "country": country,
                "open_ports": ports,
                "hostnames": hostnames,
                "vulns": vulns,
            }
        else:
            print(f"    Not found in Shodan.")
            return {"ip": ip, "found": False}
    except Exception as e:
        print(f"    Shodan error: {e}")
        return {"ip": ip, "error": str(e)}


def check_url_urlscan(url):
    print(f"\n[URLScan] Submitting URL: {url}")
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if resp.status_code == 200:
        result = resp.json()
        scan_id = result.get("uuid")
        report_url = result.get("result")
        print(f"    Scan submitted. Report: {report_url}")
        return {"url": url, "scan_id": scan_id, "report_url": report_url}
    else:
        print(f"    Error: {resp.status_code} - {resp.text}")
        return {"url": url, "error": resp.status_code}


def hash_file(filepath):
    print(f"\n[Hash] Hashing file: {filepath}")
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    print(f"    SHA256: {file_hash}")
    return file_hash


def check_hash_virustotal(file_hash):
    print(f"\n[VT] Checking hash: {file_hash}")
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers
    )
    if resp.status_code == 200:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        print(f"    Malicious detections: {malicious}/72")
        return {"hash": file_hash, "malicious": malicious}
    else:
        print(f"    Hash not found in VT database.")
        return {"hash": file_hash, "found": False}


def parse_eml(filepath):
    print(f"\n[EML] Parsing email: {filepath}")
    with open(filepath, "rb") as f:
        msg = email.message_from_bytes(f.read())

    sender = str(msg.get("From", "Unknown"))
    reply_to = str(msg.get("Reply-To", "None"))
    subject = str(msg.get("Subject", "Unknown"))
    received = msg.get_all("Received", [])

    print(f"    From: {sender}")
    print(f"    Reply-To: {reply_to}")
    print(f"    Subject: {subject}")

    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    extracted_ips = []
    for header in received:
        ips = ip_pattern.findall(header)
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                if ip not in extracted_ips:
                    extracted_ips.append(ip)

    print(f"    Extracted IPs: {extracted_ips}")

    extracted_urls = []
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    urls = url_pattern.findall(body)
                    extracted_urls.extend(urls)
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
            extracted_urls = url_pattern.findall(body)
        except:
            pass

    extracted_urls = list(set(extracted_urls))
    print(f"    Extracted URLs: {extracted_urls}")

    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            if filename:
                save_path = f"samples/{filename}"
                with open(save_path, "wb") as f:
                    f.write(part.get_payload(decode=True))
                attachments.append(save_path)
                print(f"    Saved attachment: {save_path}")

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "ips": extracted_ips,
        "urls": extracted_urls,
        "attachments": attachments,
    }


def generate_report(case_id, iocs, verdicts):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    iocs_json = json.dumps(iocs, indent=2)
    verdicts_json = json.dumps(verdicts, indent=2)

    malicious_hits = sum(
        1 for v in verdicts
        if v.get("malicious") and v["malicious"] not in [0, "pending", False]
    )

    if malicious_hits > 0:
        verdict_line = "MALICIOUS - One or more IOCs flagged as malicious."
    elif any(v.get("suspicious") for v in verdicts):
        verdict_line = "SUSPICIOUS - Review recommended."
    else:
        verdict_line = "BENIGN - No malicious indicators detected."

    lines = [
        "# Phishing Analysis Report - Case " + str(case_id),
        "",
        "**Date:** " + timestamp,
        "",
        "## IOCs Analyzed",
        "```",
        iocs_json,
        "```",
        "",
        "## Results",
        "```",
        verdicts_json,
        "```",
        "",
        "## Verdict",
        verdict_line,
        "",
        "## MITRE ATT&CK Mapping",
        "- T1566 - Phishing",
        "- T1566.001 - Spearphishing Attachment",
        "- T1566.002 - Spearphishing Link",
        "",
    ]

    filepath = f"cases/case-{case_id}.md"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[Report] Saved to {filepath}")


def run_analysis(case_id, urls=[], ips=[], files=[]):
    print("\n" + "=" * 50)
    print(f"Starting analysis for Case {case_id}")
    print("=" * 50)

    verdicts = []
    iocs = {"urls": urls, "ips": ips, "files": files}

    for url in urls:
        result = check_url_virustotal(url)
        verdicts.append(result)
        urlscan_result = check_url_urlscan(url)
        verdicts.append(urlscan_result)

    for ip in ips:
        result = check_ip_abuseipdb(ip)
        verdicts.append(result)
        shodan_result = check_ip_shodan(ip)
        verdicts.append(shodan_result)

    for filepath in files:
        file_hash = hash_file(filepath)
        result = check_hash_virustotal(file_hash)
        verdicts.append(result)

    generate_report(case_id, iocs, verdicts)
    print(f"\nAnalysis complete for Case {case_id}")


def run_analysis_from_eml(case_id, eml_path):
    print(f"\n{'='*50}")
    print(f"Starting EML analysis for Case {case_id}")
    print(f"{'='*50}")

    parsed = parse_eml(eml_path)

    verdicts = []
    iocs = {
        "urls": parsed["urls"],
        "ips": parsed["ips"],
        "files": parsed["attachments"],
        "sender": parsed["sender"],
        "reply_to": parsed["reply_to"],
        "subject": parsed["subject"],
    }

    for url in parsed["urls"]:
        result = check_url_virustotal(url)
        verdicts.append(result)
        urlscan_result = check_url_urlscan(url)
        verdicts.append(urlscan_result)

    for ip in parsed["ips"]:
        result = check_ip_abuseipdb(ip)
        verdicts.append(result)
        shodan_result = check_ip_shodan(ip)
        verdicts.append(shodan_result)

    for filepath in parsed["attachments"]:
        file_hash = hash_file(filepath)
        result = check_hash_virustotal(file_hash)
        verdicts.append(result)

    generate_report(case_id, iocs, verdicts)
    print(f"\nEML analysis complete for Case {case_id}")


def generate_detection_rules(case_id):
    print(f"\n[AI] Generating detection rules for Case {case_id}...")

    case_file = f"cases/case-{case_id}.md"
    with open(case_file, "r", encoding="utf-8", errors="ignore") as f:
        case_content = f.read()

    prompt = f"""You are a SOC detection engineer. Read this phishing analysis case report
and generate the following:

1. A Splunk SPL query to detect this threat in a SIEM
2. A firewall/proxy block rule recommendation
3. An email gateway filter rule recommendation

Be specific — use the actual IOCs (IPs, domains, URLs) from the report.
Format each section with a clear header.
Keep it concise and practical — these should be copy-paste ready for a SOC analyst.

Case Report:
{case_content}"""

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        rules = response.text

        with open(case_file, "a", encoding="utf-8") as f:
            f.write("\n## AI-Generated Detection Rules\n\n")
            f.write(rules)
            f.write("\n")

        print(f"    Detection rules appended to {case_file}")
        return rules
    except Exception as e:
        print(f"    Gemini error: {e}")
        return None


def generate_summary():
    cases = sorted(glob.glob("cases/case-*.md"))
    total = len(cases)

    malicious_count = 0
    suspicious_count = 0
    benign_count = 0
    case_verdicts = []

    for case_file in cases:
        case_id = os.path.basename(case_file).replace("case-", "").replace(".md", "")
        with open(case_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "MALICIOUS" in content:
            verdict = "MALICIOUS"
            malicious_count += 1
        elif "SUSPICIOUS" in content:
            verdict = "SUSPICIOUS"
            suspicious_count += 1
        else:
            verdict = "BENIGN"
            benign_count += 1
        case_verdicts.append((case_id, verdict))

    lines = [
        "# Phishing Analysis Lab - Threat Summary",
        "",
        f"**Total Cases Analyzed:** {total}",
        f"**Malicious:** {malicious_count}",
        f"**Suspicious:** {suspicious_count}",
        f"**Benign:** {benign_count}",
        "",
        "## Case Verdicts",
        "",
        "| Case | Verdict |",
        "|---|---|",
    ]

    for case_id, verdict in case_verdicts:
        lines.append(f"| {case_id} | {verdict} |")

    lines += [
        "",
        "## Top Malicious IPs",
        "",
        "| IP | Abuse Score | Country | Reports |",
        "|---|---|---|---|",
        "| 185.220.101.45 | 100/100 | DE | 124 |",
        "| 185.220.101.182 | 100/100 | DE | 97 |",
        "| 194.165.16.11 | 100/100 | LT | 201 |",
        "",
        "## MITRE ATT&CK Coverage",
        "",
        "| Technique | ID |",
        "|---|---|",
        "| Phishing | T1566 |",
        "| Spearphishing Attachment | T1566.001 |",
        "| Spearphishing Link | T1566.002 |",
        "",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
    ]

    with open("summary.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n[Summary] Saved to summary.md")


if __name__ == "__main__":
    # Case 002 - Credential harvesting phishing link
    run_analysis(
        case_id="002",
        urls=["http://www.360pps.net/wp-includes/pomo/paypal/"],
        ips=["91.108.4.1"],
        files=[],
    )

    # Case 003 - Malware delivery URL
    run_analysis(
        case_id="003",
        urls=["http://inexistente.lojaclothing.com.br/wp-admin/css/colors/midnight/"],
        ips=["185.220.101.182"],
        files=[],
    )

    # Case 004 - BEC / spoofed domain
    run_analysis(
        case_id="004",
        urls=["http://arraiolosmktplace.com/wp-admin/"],
        ips=["194.165.16.11"],
        files=[],
    )

    # Case 005 - Ransomware C2 infrastructure
    run_analysis(
        case_id="005",
        urls=["http://thaibangkokrestaurant.com/wp-includes/sodium_compat/"],
        ips=["45.142.212.100"],
        files=[],
    )

    # Case 006 - EML parsing from raw phishing email
    run_analysis_from_eml(
        case_id="006",
        eml_path="samples/sample-1.eml"
    )

    # Generate AI detection rules for each case
    for case_num in ["001", "002", "003", "004", "005", "006"]:
        generate_detection_rules(case_num)

    # Generate summary report
    generate_summary()