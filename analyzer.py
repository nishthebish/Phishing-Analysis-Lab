import requests
import json
import os
import hashlib
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")


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
    with open(filepath, "w") as f:
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

    for filepath in files:
        file_hash = hash_file(filepath)
        result = check_hash_virustotal(file_hash)
        verdicts.append(result)

    generate_report(case_id, iocs, verdicts)
    print(f"\nAnalysis complete for Case {case_id}")

if __name__ == "__main__":
    # Case 001 - already done

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
    