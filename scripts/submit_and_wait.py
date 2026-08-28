import requests
import time
import sys

def main():
    base_url = "http://127.0.0.1:8000"
    
    auth_domains = [
        "segwaydiscovery.com",
        "aprwork.com",
        "nimbleos.com",
        "nbo2o.com",
        "segwayrobotics.com",
        "loomo.com",
        "ninebot.com",
        "ninebot.cn",
        "willand.com",
        "navimow.com",
        "segway-ninebot.com"
    ]
    
    payload = {
        "name": "Ninebot SRC Scan",
        "target_url": "https://www.ninebot.com",
        "auth_domains": auth_domains,
        "max_depth": 3,
        "max_pages": 150,
        "qps_limit": 5.0,
        "enable_tamper_check": True,
        "enable_sensitive_check": True,
        "enable_vuln_check": True
    }
    
    print("[*] Submitting task...")
    try:
        resp = requests.post(f"{base_url}/api/v1/tasks", json=payload)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error submitting task: {e}")
        return
        
    task_id = resp.json().get("id")
    print(f"[*] Task submitted: {task_id}")
    
    while True:
        try:
            status_resp = requests.get(f"{base_url}/api/v1/tasks/{task_id}")
            status_data = status_resp.json()
            status = status_data.get("status")
            progress = status_data.get("progress")
            stage = status_data.get("current_stage")
            
            print(f"[{progress}%] Status: {status} | Stage: {stage}")
            if status in ["COMPLETED", "FAILED", "ERROR"]:
                break
        except Exception as e:
            print(f"Error checking status: {e}")
        time.sleep(10)
        
    print("\n[*] Task finished. Fetching details...")
    try:
        details_resp = requests.get(f"{base_url}/api/v1/tasks/{task_id}/details")
        details = details_resp.json()
        findings = details.get("findings", [])
        print(f"\n[*] Found {len(findings)} findings.")
        for f in findings:
            print(f"  - [{f.get('severity')}] {f.get('title')} (CVSS: {f.get('cvss_score')})")
            print(f"    URL: {f.get('url')}")
    except Exception as e:
        print(f"Error getting details: {e}")

if __name__ == "__main__":
    main()
