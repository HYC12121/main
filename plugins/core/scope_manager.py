import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("das_sentinel.scope")

class SRCScopingEngine:
    """SRC 实战授权边界与受限资产过滤引擎
    
    严格遵循企业 SRC 漏洞规则中的测试原则：
    1. 授权测试：仅对授权资产进行探测，排除测试范围外资产；
    2. 完全禁止项：禁止未经授权扫描、排除限制收录的特定子域 (如 join.*, gw.*)；
    3. 限规探测：对限制 Path FUZZ 的资产实施保守被动流量分析，不发起高频爆破；
    4. 无害原则：探测强度严格限速，采用只读或微探针验证。
    """

    def __init__(
        self,
        auth_domains: Optional[List[str]] = None,
        restricted_fuzz_domains: Optional[List[str]] = None,
        blacklisted_domains: Optional[List[str]] = None
    ):
        self.auth_domains = [d.strip().lower() for d in (auth_domains or []) if d.strip()]
        self.restricted_fuzz_domains = [
            d.strip().lower() for d in (restricted_fuzz_domains or [
                "oa.segway-ninebot.com",
                "srm2.segway-ninebot.com",
                "srm2-mobile.segway-ninebot.com"
            ]) if d.strip()
        ]
        self.blacklisted_domains = [
            d.strip().lower() for d in (blacklisted_domains or [
                "join.ninebot.com",
                "gw.segway-ninebot.com"
            ]) if d.strip()
        ]

    def is_in_scope(self, url: str) -> bool:
        """判断目标 URL 是否属于已授权测试范围且未被黑名单排除"""
        if not url:
            return False
            
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or "").split(":")[0].lower()
            if not host:
                return False
                
            # 1. 检查黑名单 (禁止测试资产)
            for b_dom in self.blacklisted_domains:
                if host == b_dom or host.endswith("." + b_dom):
                    logger.warning(f"[Scope] Target domain is blacklisted by SRC rules: {host}")
                    return False
                    
            # 2. 如果未指定授权域名，默认放行
            if not self.auth_domains:
                return True
                
            # 3. 检查是否匹配授权域名或通配子域 (*.domain.com)
            for a_dom in self.auth_domains:
                clean_auth = a_dom.lstrip("*.")
                if host == clean_auth or host.endswith("." + clean_auth):
                    return True
                    
            logger.info(f"[Scope] Target domain {host} is outside authorized domains: {self.auth_domains}")
            return False
        except Exception as e:
            logger.warning(f"[Scope] Error checking scope for {url}: {e}")
            return False

    def is_path_fuzzing_allowed(self, url: str) -> bool:
        """检查特定域名是否禁止高频路径爆破/账号爆破"""
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or "").split(":")[0].lower()
            for r_dom in self.restricted_fuzz_domains:
                if host == r_dom or host.endswith("." + r_dom):
                    return False
            return True
        except Exception:
            return True

    def filter_crawled_urls(self, urls: List[str]) -> List[str]:
        """过滤爬虫与资产发现队列中的 URL"""
        return [u for u in urls if self.is_in_scope(u)]
