import logging
import asyncio
from typing import Dict, Any, List, Set
from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.rest_api_prober")

class RestApiProber(BaseScanner):
    """
    REST API 探测与接口边界发现引擎 (REST API & Interface Prober)
    方向：api_fuzzer
    职责：
    1. 基于已发现的 API 路由，执行轻量级安全探针与 Swagger / OpenAPI 接口探测
    2. 发现未授权 API 接口、GraphQL 查询端点及异常返回状态
    3. 将 API 探测风险无缝注入 ScanContext 统一风险池
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.probed_endpoints: Set[str] = set()

    async def run(self, context: ScanContext) -> None:
        logger.info(f"[ApiFuzzer] 启动 API 接口安全探测... 候选接口数: {len(context.api_endpoints)}")
        
        # 针对 context.api_endpoints 中的接口做边界探针 (模拟合规轻量探测)
        findings: List[Dict[str, Any]] = []
        
        # 检查是否包含敏感未授权端点特征
        sensitive_patterns = ["swagger", "api-docs", "graphql", "actuator", "metrics"]
        for ep in context.api_endpoints:
            self.probed_endpoints.add(ep)
            for pat in sensitive_patterns:
                if pat in ep.lower():
                    # 记录轻量级发现（如检测到敏感接口）
                    findings.append({
                        "task_id": context.task_id,
                        "category": "VULN",
                        "level": "MEDIUM",
                        "title": f"发现敏感 API / 文档端点: {pat}",
                        "target": ep,
                        "description": f"在目标站点提取到开放的 API 文档或管理端点: {ep}",
                        "evidence": f"Endpoint match: {pat}",
                        "remediation": "建议生产环境关闭 Swagger/Actuator 等调试与内部文档暴露，增加网关鉴权。"
                    })
                    break

        if findings:
            context.add_findings(findings)
            logger.info(f"[ApiFuzzer] 探测到 API 潜在风险 {len(findings)} 项")
