import pytest
import os
from backend.app.agent.verifier import FindingVerifier
from backend.app.baseline.report_service import ReportService
from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
from backend.app.database import init_db, get_db_connection

def test_url_normalization_dedup():
    findings = [
        {
            "category": "VULN",
            "title": "HSTS 缺失",
            "url": "http://127.0.0.1:8088/portal/index?_t=123456&PHPSESSID=abc",
            "param": ""
        },
        {
            "category": "VULN",
            "title": "HSTS 缺失",
            "url": "http://127.0.0.1:8088/portal/index?_t=789012&PHPSESSID=xyz",
            "param": ""
        },
        {
            "category": "VULN",
            "title": "不同漏洞",
            "url": "http://127.0.0.1:8088/portal/index",
            "param": ""
        }
    ]
    deduped = FindingVerifier.deduplicate_findings(findings)
    assert len(deduped) == 2
    assert deduped[0]["instance_count"] == 2
    assert deduped[1]["instance_count"] == 1

def test_architecture_fingerprint():
    pages = [
        {
            "url": "https://msgbox-merc.vercel.app/",
            "headers": {"server": "Vercel", "x-vercel-id": "hnd1::iad1"},
            "html_content": '<div id="__next">Hello Next.js React app</div>'
        }
    ]
    findings = []
    arch = ArchitectureFingerprintDetector.detect_architecture("https://msgbox-merc.vercel.app/", pages, findings)
    assert len(arch["layers"]) == 5
    # Frontend should detect React / Next.js
    assert "React" in arch["layers"][0]["component"]["name"]
    # Web server should detect Vercel Edge
    assert "Vercel" in arch["layers"][1]["component"]["name"]
    # Backend should be Serverless / Node.js
    assert "Node" in arch["layers"][2]["component"]["name"]

def test_light_report_generation():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # insert dummy task and finding
    cursor.execute("""
    INSERT OR REPLACE INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at, summary)
    VALUES ('task-test-rep', '测试报告任务', 'http://127.0.0.1:8088', '[]', '{}', 'COMPLETED', 100, '完成', '2026-08-26', '{"security_score": 92, "status_level": "HEALTHY", "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1}}')
    """)
    cursor.execute("""
    INSERT OR REPLACE INTO findings (id, task_id, category, title, severity, url, param, evidence, impact, remediation, verified, cvss_score, status, created_at)
    VALUES ('f-test-1', 'task-test-rep', 'VULN', 'Git 泄露', 'HIGH', 'http://127.0.0.1:8088/.git/config', '', '{"matched_snippet": "repositoryformatversion = 0"}', '影响源码安全', '禁止访问 .git', 1, 7.5, 'OPEN', '2026-08-26')
    """)
    conn.commit()
    conn.close()
    
    report_file = ReportService.generate_html_report('task-test-rep')
    assert os.path.exists(report_file)
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "background: #f8fafc" in content or "background: #ffffff" in content
        assert "Git 泄露" in content
        assert "92" in content
