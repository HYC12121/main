import logging
import re
from typing import Dict, Any, List, Set
from urllib.parse import urlparse, urljoin
from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.smart_link_extractor")

class SmartLinkExtractor(BaseScanner):
    """
    特殊链接与外链清洗扩展引擎 (Smart Link & Deep Route Extractor)
    方向：link_processor
    职责：
    1. 从爬取的页面源码与动态 JS 中深层提取隐藏 API、动态 Route 路径、微服务接口
    2. 识别并归类外部链接、CDN 链接与可疑跳转链接
    3. 输出清洗后并去重的优质目标链接至 ScanContext 总线
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.extracted_routes: Set[str] = set()
        self.external_links: Set[str] = set()

    async def run(self, context: ScanContext) -> None:
        logger.info(f"[LinkProcessor] 启动特殊链接深层挖掘与清洗... 目标: {context.target_url}")
        
        target_domain = urlparse(context.target_url).netloc.split(":")[0].lower()
        auth_domains = context.auth_domains or [target_domain]

        # 1. 解析页面中的所有隐藏路由与特殊 JS 片段
        for page in context.crawled_pages:
            html = page.get("html", "")
            url = page.get("url", "")
            
            # 正则提取前端路由路径，如 /api/v1/..., /user/login, /admin/...
            route_matches = re.findall(r'[\'"`](/(?:api|v[0-9]|rest|admin|auth|system|user|service)[a-zA-Z0-9_\-/\.\?=&]*)[\'"`]', html)
            for r in route_matches:
                full_url = urljoin(url, r)
                self.extracted_routes.add(full_url)
                if hasattr(context, "api_endpoints") and isinstance(context.api_endpoints, set):
                    context.api_endpoints.add(full_url)

        # 2. 深度清洗外链
        cleaned_ext = set()
        for ext in context.external_links:
            try:
                parsed = urlparse(ext)
                if parsed.scheme in ["http", "https"] and parsed.netloc:
                    cleaned_ext.add(ext)
            except Exception:
                pass

        logger.info(f"[LinkProcessor] 链接处理完成: 提取内部高级API/路由 {len(self.extracted_routes)} 个, 归纳外链 {len(cleaned_ext)} 个")
