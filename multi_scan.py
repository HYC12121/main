"""
Multi-target scan for SRC assets - scans multiple domains in sequence
Targets with most likely API backends first
"""
import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

AUTH_DOMAINS = [
    "segwaydiscovery.com", "aprwork.com", "nimbleos.com", "nbo2o.com",
    "segwayrobotics.com", "loomo.com", "ninebot.com", "ninebot.cn",
    "willand.com", "navimow.com", "segway-ninebot.com"
]

# Targets sorted by likelihood of having backend APIs
TARGETS = [
    ("https://nbo2o.com", "NBO2O Mall"),
    ("https://www.ninebot.cn", "Ninebot CN"),
    ("https://navimow.com", "Navimow"),
    ("https://www.segway-ninebot.com", "Segway-Ninebot"),
    ("https://account.ninebot.com", "Ninebot Account"),
    ("https://api.ninebot.com", "Ninebot API"),
    ("https://app.ninebot.com", "Ninebot App Portal"),
]

def submit_scan(target_url, name):
    payload = {
        "name": f"SRC Scan: {name}",
        "target_url": target_url,
        "auth_domains": AUTH_DOMAINS,
        "max_depth": 3,
        "max_pages": 80,
        "qps_limit": 3.0,
        "enable_tamper_check": True,
        "enable_sensitive_check": True,
        "enable_vuln_check": True
    }
    resp = requests.post(f"{BASE_URL}/api/v1/tasks", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json().get("id")

def wait_for_task(task_id, timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BASE_URL}/api/v1/tasks/{task_id}", timeout=5)
            data = r.json()
            status = data.get("status")
            progress = data.get("progress", 0)
            stage = data.get("current_stage", "")
            print(f"  [{progress}%] {status} | {stage}", flush=True)
            if status in ("COMPLETED", "FAILED", "ERROR"):
                return status
        except Exception as e:
            print(f"  Status check error: {e}", flush=True)
        time.sleep(10)
    return "TIMEOUT"

def get_findings(task_id):
    try:
        r = requests.get(f"{BASE_URL}/api/v1/tasks/{task_id}/details", timeout=10)
        return r.json().get("findings", [])
    except Exception:
        return []

def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')
    print("=" * 70)
    print("DAS-SentinelAgent Multi-Target SRC Scan")
    print("=" * 70)

    all_medium_plus = []

    for target_url, name in TARGETS:
        print(f"\n[>>>] Scanning: {name} ({target_url})")
        print("-" * 60)

        try:
            task_id = submit_scan(target_url, name)
            print(f"  Task ID: {task_id}")
        except Exception as e:
            print(f"  Failed to submit: {e}")
            continue

        status = wait_for_task(task_id)
        findings = get_findings(task_id)

        medium_plus = [f for f in findings if f.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")]
        print(f"\n  Total: {len(findings)} findings | Medium+: {len(medium_plus)}")

        for f in findings:
            sev = f.get("severity", "")
            title = f.get("title", "")
            url = f.get("url", "")
            cvss = f.get("cvss_score", 0)
            marker = "🔴" if sev in ("HIGH", "CRITICAL") else ("🟡" if sev == "MEDIUM" else "⚪")
            print(f"  {marker} [{sev}] {title[:60]} (CVSS:{cvss})")
            print(f"     URL: {url}")

        all_medium_plus.extend(medium_plus)

        # If we found a medium+ vuln, highlight it
        if medium_plus:
            print(f"\n  ✅ FOUND {len(medium_plus)} MEDIUM+ FINDINGS on {name}!")
            for f in medium_plus:
                print(f"     -> [{f.get('severity')}] {f.get('title')}")
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    snippet = ev.get("matched_snippet", ev.get("sample_data", ""))
                    if snippet:
                        print(f"        Evidence: {str(snippet)[:200]}")
            print()

    print("\n" + "=" * 70)
    print(f"SCAN COMPLETE — Total Medium+ findings across all targets: {len(all_medium_plus)}")
    if all_medium_plus:
        print("\n🔴 CONFIRMED FINDINGS:")
        for f in all_medium_plus:
            print(f"  [{f.get('severity')}] {f.get('title')}")
            print(f"  URL: {f.get('url')}")
            print(f"  CVSS: {f.get('cvss_score')}")
            print()

if __name__ == "__main__":
    main()
