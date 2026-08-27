import pytest
from backend.app.agent.hengnao_adapter import HengNaoAgentAdapter

def test_hengnao_manifest_schema():
    manifest = HengNaoAgentAdapter.get_agent_manifest()
    
    assert manifest["agent_name"] == "DAS-SentinelAgent (安恒星巡安全智能体)"
    assert "tools" in manifest
    assert len(manifest["tools"]) >= 4
    
    tool_names = [t["name"] for t in manifest["tools"]]
    assert "das_recon_assets" in tool_names
    assert "das_scan_vulnerabilities" in tool_names
    assert "das_inspect_tamper_malware" in tool_names
    assert "das_inspect_sensitive_leak" in tool_names
    assert "das_compare_baseline" in tool_names
