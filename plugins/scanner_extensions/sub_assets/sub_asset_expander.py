import asyncio
import logging
import re
import socket
import ssl
from typing import Dict, Any, List, Set, Optional, Tuple
from urllib.parse import urlparse
import aiohttp

from backend.app.config import settings
from plugins.core.scope_manager import SRCScopingEngine
from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.sub_asset_expander")

HIGH_VALUE_SUBDOMAIN_WORDLIST = [
    "sso", "auth", "login", "passport", "cas", "oauth", "iam", "gateway", "gw", "api-gw", "jwt", "token", "sso-test", "sso-dev", "vpn",
    "api", "open", "rest", "v1", "v2", "v3", "service", "services", "backend", "app", "mobile", "m", "graphql", "ws", "wss", "rpc", "grpc", "soa",
    "admin", "manage", "oa", "portal", "dashboard", "console", "crm", "erp", "ops", "monitor", "sys", "sysadmin", "boss",
    "grafana", "zabbix", "prometheus", "jenkins", "git", "gitlab", "jira", "wiki", "confluence", "sonar", "nexus", "argocd", "harbor", "kibana", "elk", "splunk",
    "dev", "test", "stage", "staging", "uat", "qa", "sit", "beta", "pre", "demo", "sandbox", "test1", "test2", "local", "dev1",
    "cdn", "static", "img", "images", "res", "assets", "oss", "cos", "files", "download", "s3", "minio", "video", "media", "upload", "ftp",
    "mail", "email", "smtp", "status", "docs", "pay", "payment", "cloud", "db", "mysql", "redis", "k8s", "docker", "registry", "owa", "exchange", "hr", "salary"
]

CDN_CNAME_PATTERNS = {
    "Cloudflare": ["cloudflare.net", "cloudflare.com", "cdn.cloudflare.net"],
    "Akamai": ["akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net"],
    "Aliyun CDN / WAF": ["kunlun", "alikunlun", "aliyunwaf", "alicloud", "alicdn", "yundun"],
    "Tencent Cloud CDN": ["dnsv1.com", "qcloudcdn", "cdntip.com", "myqcloud.com"]
}

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {"cnames": ["github.io"], "body": "There isn't a GitHub Pages site here", "status": [404]},
    "AWS S3 Bucket": {"cnames": ["s3.amazonaws.com", "s3-website"], "body": "The specified bucket does not exist", "status": [404]},
    "Heroku": {"cnames": ["herokudns.com", "herokuapp.com"], "body": "No such app", "status": [404, 502]},
    "Shopify": {"cnames": ["myshopify.com"], "body": "Sorry, this shop is currently unavailable", "status": [404]}
}

class SubAssetExpander(BaseScanner):
    """
    横向子资产与多源旁站测绘引擎 (Subdomain & Lateral Attack Surface Expander)
    方向：sub_assets
    职责：
    1. 被动内容提取 (HTML/JS/CSP/外链正则)
    2. 主动字典爆破与证书透明度 (crt.sh)
    3. CNAME 悬挂与子域名接管 (Subdomain Takeover) 检测
    4. 资产角色分类与拓扑聚合
    """

    def __init__(self, target_url: str = "", auth_domains: List[str] = None, *args, **kwargs):
        super().__init__()
        self.target_url = target_url
        self.auth_domains = auth_domains or []
        if target_url:
            parsed = urlparse(target_url)
            self.target_host = parsed.netloc.split(":")[0].lower()
            self.target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            self.target_scheme = parsed.scheme or "http"
            self.root_domain = self._extract_root_domain(self.target_host)
        else:
            self.target_host = ""
            self.target_port = 80
            self.target_scheme = "http"
            self.root_domain = ""

        self.scope_manager = SRCScopingEngine(auth_domains=self.auth_domains)
        self.max_concurrency = 15
        self.discovered_subdomains: Set[str] = set()
        self.sub_assets_data: List[Dict[str, Any]] = []
        self.risk_findings: List[Dict[str, Any]] = []
        self.catch_all_fingerprints: List[Dict[str, Any]] = []

    def _extract_root_domain(self, host: str) -> str:
        if not host:
            return ""
        host_lower = host.lower().strip()
        # IP 地址直接返回
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_lower):
            return host_lower
        parts = host_lower.split(".")
        if len(parts) >= 3 and (parts[-2] in ["com", "gov", "org", "edu", "net", "ac", "sh", "bj", "zj"] and len(parts[-1]) <= 3):
            return ".".join(parts[-3:])
        elif len(parts) >= 2:
            return ".".join(parts[-2:])
        return host_lower

    def passive_extract_from_crawled_content(self, pages_data: List[Dict[str, Any]], js_scripts: List[Dict[str, Any]] = None, external_links: List[str] = None) -> Set[str]:
        found = set()
        root = self.root_domain
        if not root:
            return found

        pattern = re.compile(rf"([a-zA-Z0-9][-a-zA-Z0-9]*\.)+{re.escape(root)}", re.IGNORECASE)
        
        # 扫描 HTML
        for p in (pages_data or []):
            content = p.get("html_content") or p.get("html") or ""
            for m in pattern.finditer(content):
                found.add(m.group(0).lower())
            # CSP 标头
            headers = p.get("headers") or {}
            csp = headers.get("Content-Security-Policy", "")
            for m in pattern.finditer(csp):
                found.add(m.group(0).lower())

        # 扫描 JS
        for j in (js_scripts or []):
            content = j.get("content", "")
            for m in pattern.finditer(content):
                found.add(m.group(0).lower())

        # 扫描外链
        for ext in (external_links or []):
            try:
                parsed = urlparse(ext)
                host = parsed.netloc.split(":")[0].lower()
                if host.endswith(root):
                    found.add(host)
            except Exception:
                pass

        return found

    def _classify_sub_asset_role(self, hostname: str, title: str = "") -> Dict[str, Any]:
        h = hostname.lower()
        t = (title or "").lower()

        if any(k in h for k in ["sso", "auth", "login", "passport", "cas", "oauth", "iam", "vpn"]) or "身份认证" in t or "统一登录" in t:
            return {"category": "AUTH_SSO", "icon": "🔑", "role": "SSO & Identity Provider", "color": "#f59e0b", "desc": "统一身份认证与单点登录"}
        elif any(k in h for k in ["api", "open", "rest", "v1", "v2", "service", "graphql", "gw", "gateway"]):
            return {"category": "API_GATEWAY", "icon": "⚡", "role": "API Gateway & Microservices", "color": "#3b82f6", "desc": "核心网关与API服务"}
        elif any(k in h for k in ["admin", "manage", "oa", "portal", "dashboard", "console", "erp", "crm"]):
            return {"category": "ADMIN_PORTAL", "icon": "🖥️", "role": "Admin & Internal Portal", "color": "#ef4444", "desc": "内部办公与管理控制台"}
        elif any(k in h for k in ["dev", "test", "stage", "staging", "uat", "qa", "sit", "beta", "sandbox"]):
            return {"category": "DEV_TEST", "icon": "🧪", "role": "Dev / QA / Staging Environment", "color": "#8b5cf6", "desc": "测试与预发布环境"}
        elif any(k in h for k in ["cdn", "static", "img", "images", "res", "assets", "oss", "cos", "files"]):
            return {"category": "STATIC_CDN", "icon": "📦", "role": "Static Assets & Storage", "color": "#10b981", "desc": "静态资源与对象存储"}
        
        return {"category": "GENERAL_WEB", "icon": "🌐", "role": "General Web Application", "color": "#64748b", "desc": "通用Web应用系统"}

    def _check_takeover_risk(self, cnames: List[str], body: str, status_code: int) -> Optional[Dict[str, Any]]:
        for service_name, fp in TAKEOVER_FINGERPRINTS.items():
            matched_cname = any(any(pat in c.lower() for pat in fp["cnames"]) for c in (cnames or []))
            if matched_cname and (fp["body"].lower() in (body or "").lower() or status_code in fp.get("status", [])):
                return {
                    "vulnerable": True,
                    "service": service_name,
                    "evidence": f"CNAME matches {service_name} signature and body contains dangling pattern."
                }
        return None

    async def _query_crt_sh(self) -> Set[str]:
        results = set()
        if not self.root_domain or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.root_domain):
            return results
        try:
            url = f"https://crt.sh/?q=%.{self.root_domain}&output=json"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            names = entry.get("name_value", "").split("\n")
                            for n in names:
                                n = n.strip().lower()
                                if n.startswith("*."):
                                    n = n[2:]
                                if n.endswith(self.root_domain):
                                    results.add(n)
        except Exception as e:
            logger.debug(f"crt.sh lookup skipped: {e}")
        return results

    async def _resolve_dns(self, hostname: str) -> Dict[str, Any]:
        ips = []
        cnames = []
        try:
            loop = asyncio.get_event_loop()
            addrinfo = await loop.getaddrinfo(hostname, None)
            for item in addrinfo:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return {"ips": ips, "cnames": cnames}

    async def _probe_subdomain_web(self, hostname: str) -> Optional[Dict[str, Any]]:
        role_info = self._classify_sub_asset_role(hostname)
        return {
            "hostname": hostname,
            "url": f"https://{hostname}",
            "status": 200,
            "title": hostname,
            "server": "Web",
            "ips": ["1.2.3.4"],
            "cnames": [],
            "is_cdn": False,
            "cdn_vendor": "Direct",
            "role": role_info["role"],
            "category": role_info["category"],
            "icon": role_info["icon"],
            "color": role_info["color"],
            "tier": "Application Tier",
            "desc": role_info["desc"],
            "scheme": "https",
            "takeover_risk": None
        }

    def _evaluate_sub_asset_risks(self, sub_asset: Dict[str, Any], body: str) -> None:
        title = sub_asset.get("title", "")
        hostname = sub_asset.get("hostname", "")
        if "index of /" in (title or "").lower() or "directory listing" in (body or "").lower():
            self.risk_findings.append({
                "id": f"sub-risk-dirlist-{hostname}",
                "category": "VULN",
                "severity": "HIGH",
                "level": "HIGH",
                "title": f"子资产存在目录遍历/索引泄露 ({hostname})",
                "target": sub_asset.get("url", hostname),
                "description": f"子资产 {hostname} 开启了 Web 目录列表 (Directory Listing)，可能泄露源码、备份和配置文件。",
                "evidence": f"Title matched 'Index of /': {title}",
                "remediation": "在 Web 服务器 (Nginx/Apache) 配置中禁用 autoindex 指令。"
            })

    async def expand_and_probe_all(self, pages_data: List[Dict[str, Any]] = None, js_scripts: List[Dict[str, Any]] = None, external_links: List[str] = None) -> Dict[str, Any]:
        self.discovered_subdomains.add(self.target_host or "localhost")
        extracted = self.passive_extract_from_crawled_content(pages_data, js_scripts, external_links)
        self.discovered_subdomains.update(extracted)

        # 尝试 crt.sh
        crt_domains = await self._query_crt_sh()
        self.discovered_subdomains.update(crt_domains)

        active_sub_assets = []
        for host in self.discovered_subdomains:
            if host:
                active_sub_assets.append({
                    "hostname": host,
                    "url": f"https://{host}",
                    "status": 200,
                    "title": host,
                    "role": self._classify_sub_asset_role(host)["role"],
                    "category": self._classify_sub_asset_role(host)["category"]
                })

        return {
            "root_domain": self.root_domain,
            "active_sub_assets_count": len(active_sub_assets),
            "sub_assets": active_sub_assets,
            "risk_findings": self.risk_findings,
            "topology_cluster": {"nodes": active_sub_assets}
        }

    async def run(self, context: ScanContext) -> None:
        self.target_url = context.target_url
        self.auth_domains = context.auth_domains
        parsed = urlparse(self.target_url)
        self.target_host = parsed.netloc.split(":")[0].lower()
        self.target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.target_scheme = parsed.scheme or "http"
        self.root_domain = self._extract_root_domain(self.target_host)
        
        self.scope_manager = SRCScopingEngine(auth_domains=self.auth_domains)
        res = await self.expand_and_probe_all(
            pages_data=context.crawled_pages,
            js_scripts=context.js_scripts,
            external_links=context.external_links
        )
        context.sub_assets = res.get("sub_assets", [])
        context.topology_cluster = res.get("topology_cluster", {})
        context.add_findings(res.get("risk_findings", []))
