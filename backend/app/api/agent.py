from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException
from backend.app.agent.brain import AgentBrain
from backend.app.agent.hengnao_adapter import HengNaoAgentAdapter
from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler
from plugins.scanner_core.vuln_detector import VulnerabilityDetector
from plugins.scanner_core.tamper_detector import TamperDetector
from plugins.scanner_core.sensitive_inspector import SensitiveInspector
from backend.app.baseline.baseline_service import BaselineService

router = APIRouter(prefix="/agent", tags=["智能体大脑与恒脑平台交互"])

class AgentChatRequest(BaseModel):
    prompt: str = Field(..., description="用户或系统自然语言指令")
    session_id: Optional[str] = Field(default=None, description="会话ID")

class ToolExecuteRequest(BaseModel):
    tool_name: str = Field(..., description="工具名称")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="工具调用参数")

@router.post("/chat")
async def agent_chat(chat_in: AgentChatRequest):
    """智能体交互入口：解析意图、自主生成任务规划、执行探测并归纳闭环响应"""
    res = await AgentBrain.chat_and_plan(chat_in.prompt, chat_in.session_id)
    return res

@router.get("/tools")
async def get_hengnao_tools_manifest():
    """导出符合恒脑安全智能体开发平台 (https://gc.das-ai.com) 标准的工具清单"""
    return HengNaoAgentAdapter.get_agent_manifest()

@router.post("/execute")
async def execute_tool(exec_in: ToolExecuteRequest):
    """恒脑安全智能体平台 / 外部大模型标准 Tool Calling 执行接口"""
    tool_name = exec_in.tool_name
    params = exec_in.parameters
    
    target_url = params.get("target_url", "")
    auth_domains = params.get("auth_domains", [])
    
    if not target_url and tool_name != "das_compare_baseline":
        raise HTTPException(status_code=400, detail="Missing required parameter: target_url")
        
    if tool_name == "das_recon_assets":
        crawler = AssetCrawler(
            base_url=target_url,
            auth_domains=auth_domains,
            max_depth=params.get("max_depth", 2),
            max_pages=params.get("max_pages", 20)
        )
        res = await crawler.crawl()
        return {"status": "SUCCESS", "data": {"total_pages": res["total_pages"], "assets": res["static_assets"]}}
        
    elif tool_name == "das_scan_vulnerabilities":
        crawler = AssetCrawler(base_url=target_url, auth_domains=auth_domains, max_depth=1, max_pages=5)
        crawled = await crawler.crawl()
        vuln_detector = VulnerabilityDetector(target_url, auth_domains)
        findings = await vuln_detector.scan_all(crawled["pages"], crawl_metadata=crawled)
        return {"status": "SUCCESS", "findings_count": len(findings), "findings": findings}
        
    elif tool_name == "das_inspect_tamper_malware":
        crawler = AssetCrawler(base_url=target_url, auth_domains=auth_domains, max_depth=1, max_pages=5)
        crawled = await crawler.crawl()
        tamper_detector = TamperDetector(auth_domains)
        findings = tamper_detector.scan_pages(crawled["pages"])
        return {"status": "SUCCESS", "findings_count": len(findings), "findings": findings}
        
    elif tool_name == "das_inspect_sensitive_leak":
        crawler = AssetCrawler(base_url=target_url, auth_domains=auth_domains, max_depth=1, max_pages=5)
        crawled = await crawler.crawl()
        inspector = SensitiveInspector(custom_keywords=params.get("custom_keywords", []))
        findings = inspector.scan_pages(crawled["pages"], js_scripts=crawled.get("js_scripts", []))
        return {"status": "SUCCESS", "findings_count": len(findings), "findings": findings}
        
    elif tool_name == "das_compare_baseline":
        diff = BaselineService.compare_baselines(params.get("base_task_id", ""), params.get("current_task_id", ""))
        return {"status": "SUCCESS", "diff": diff}
        
    else:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
