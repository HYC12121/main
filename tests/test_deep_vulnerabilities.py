import pytest
import asyncio
import aiohttp
from backend.app.scanners.vuln_detector import VulnerabilityDetector

@pytest.mark.anyio
async def test_deep_industrial_vulnerability_scanner():
    """测试工业级深度漏洞扫描引擎对靶场高危漏洞的全量精准检测能力"""
    target = "http://127.0.0.1:8088"
    detector = VulnerabilityDetector(target, ["127.0.0.1"])
    
    # 模拟真实爬虫提取的待探测参数集合
    url_parameters = [
        {"endpoint": f"{target}/api/search", "params": ["q"]},
        {"endpoint": f"{target}/api/user", "params": ["id"]},
        {"endpoint": f"{target}/api/view", "params": ["file"]},
        {"endpoint": f"{target}/api/render", "params": ["template"]},
        {"endpoint": f"{target}/api/ping", "params": ["host"]},
        {"endpoint": f"{target}/api/proxy", "params": ["url"]}
    ]
    
    discovered_apis = [
        f"{target}/api/profile"
    ]
    
    timeout = aiohttp.ClientTimeout(total=10.0)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # 1. 测试深度参数漏洞检测
        param_findings = await detector._probe_parameter_vulnerabilities(
            session=session,
            url_parameters=url_parameters,
            forms=[],
            crawled_pages=[]
        )
        
        # 2. 测试 BOLA / IDOR 越权与 API 数据泄露
        api_findings = await detector._probe_api_unauthorized_endpoints(
            session=session,
            discovered_apis=discovered_apis
        )
        
    all_findings = param_findings + api_findings
    found_titles = [f["title"] for f in all_findings]
    
    print("\n[Deep Scanner Verified Findings]:")
    for t in found_titles:
        print(f" -> {t}")
        
    # 断言关键高危漏洞全量命中
    assert any("XSS" in t for t in found_titles), "应该精准检出上下文感知 XSS 漏洞"
    assert any("SQL 注入" in t or "SQLi" in t for t in found_titles), "应该精准检出 SQL 注入漏洞 (报错/差分/时间盲注)"
    assert any("文件读取" in t or "Path Traversal" in t for t in found_titles), "应该精准检出 LFI 路径穿越漏洞"
    assert any("SSTI" in t or "模板注入" in t for t in found_titles), "应该精准检出 SSTI 模板注入漏洞"
    assert any("命令注入" in t or "Command Injection" in t for t in found_titles), "应该精准检出操作系统命令注入漏洞"
    assert any("SSRF" in t for t in found_titles), "应该精准检出 SSRF 服务端请求伪造漏洞"
    assert any("BOLA" in t or "越权" in t for t in found_titles), "应该精准检出 BOLA / IDOR 越权访问漏洞"
