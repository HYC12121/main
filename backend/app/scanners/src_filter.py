"""
SRC 漏洞边界过滤引擎 (SRC Vulnerability Boundary Filter)
============================================================
SRC（Security Response Center）漏洞认定标准：

不接受的低价值漏洞（一律过滤）：
  - HTTP 安全响应头缺失（HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy）
  - 服务器版本号/Banner 指纹暴露（达不到 SRC 中危标准）
  - Cookie 属性单独缺失（HttpOnly/Secure/SameSite），无完整利用链
  - CDN 外部脚本缺失 SRI
  - 无法利用的理论性弱配置
  - CVSS < 4.0 的所有发现

接受的有效漏洞（MEDIUM >= CVSS 4.0 / HIGH / CRITICAL）：
  - SQL 注入 (SQLi) — 附有确认触发特征（报错/布尔差分/时间延迟）
  - 反射型/存储型 XSS — 附有 DOM 逃逸证明（非纯文本反射）
  - 服务端模板注入 (SSTI) — 双重随机数学验证
  - 命令注入 / RCE — 附有非自含执行特征
  - 路径穿越/任意文件读取 (LFI) — 含系统文件内容
  - 服务端请求伪造 (SSRF) — 含内网/元数据访问证明
  - CORS 高危错误配置 — 必须 Allow-Credentials: true
  - API 未授权访问 — 含真实敏感字段的 JSON 响应
  - BOLA/IDOR 水平越权 — 含确认数据差异
  - Git/ENV/数据库备份文件暴露 — 含内容特征校验
  - JS 秘钥硬编码 (AWS AK/SK、GitHub PAT、私钥)
  - SourceMap 源码映射泄露
  - GraphQL 未禁用自省 (MEDIUM)
  - 开放重定向 Open Redirect (MEDIUM)
  - CSRF — 仅状态变更 POST 表单且缺失 Token
  - Swagger/OpenAPI 未授权暴露 — 含路由结构验证
  - Spring Boot Actuator 敏感端点暴露
"""

from typing import List, Dict, Any

# SRC 认定的最低严重等级（低于此等级一律过滤）
# 0=CRITICAL  1=HIGH  2=MEDIUM  3=LOW  4=INFO
SRC_MIN_SEVERITY_RANK = 2

SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

# ── 标题关键词黑名单（无论什么 severity 均过滤） ──────────────────────────────
SRC_NOISE_TITLE_KEYWORDS = [
    # HTTP 安全响应头缺失
    "缺失 HTTP 严格传输安全",
    "缺失内容安全策略",
    "缺失 X-Frame-Options",
    "缺失 X-Content-Type-Options",
    "缺失 Referrer-Policy",
    "缺失 X-Content-Type",
    "HSTS 策略未覆盖",
    "Content-Security-Policy (CSP) 存在不安全弱配置",
    # 服务器指纹/版本
    "版本暴露",
    "Web 中间件详细版本",
    "服务指纹",
    "server banner",
    # Cookie 属性单独缺失（无利用链）
    "Cookie 缺失 HttpOnly",
    "Cookie 缺失 Secure",
    "Cookie 缺失 SameSite",
    # SRI
    "缺失子资源完整性",
    "CDN 脚本缺失",
    "外部第三方 CDN 脚本缺失",
]

# ── 类别 + 等级 组合黑名单 ────────────────────────────────────────────────────
SRC_NOISE_CATEGORY_SEVERITY = [
    ("MISCONFIG", "INFO"),
    ("MISCONFIG", "LOW"),
]

# ── CVSS 分数下限 (低于此值的中危漏洞也过滤) ──────────────────────────────────
SRC_MIN_CVSS = 4.0


def is_src_noise(finding: Dict[str, Any]) -> bool:
    """
    判断一条漏洞发现是否为 SRC 不认可的噪音。
    返回 True → 应过滤掉；False → 保留。
    """
    severity = finding.get("severity", "INFO").upper()
    title    = finding.get("title", "")
    category = finding.get("category", "")
    cvss     = float(finding.get("cvss_score", 0.0))

    # 1. 严重等级低于 SRC 最低门槛
    rank = SEVERITY_RANK.get(severity, 4)
    if rank > SRC_MIN_SEVERITY_RANK:
        return True

    # 2. CVSS 分数过低（中危以下不具备实际危害）
    if severity == "MEDIUM" and cvss < SRC_MIN_CVSS:
        return True

    # 3. 标题命中噪音关键词黑名单（大小写不敏感）
    title_lower = title.lower()
    for kw in SRC_NOISE_TITLE_KEYWORDS:
        if kw.lower() in title_lower:
            return True

    # 4. 类别 + 等级 组合命中黑名单
    for noise_cat, noise_sev in SRC_NOISE_CATEGORY_SEVERITY:
        if category == noise_cat and severity == noise_sev:
            return True

    return False


def apply_src_filter(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    对漏洞列表应用 SRC 边界过滤。
    返回仅含 SRC 认可漏洞的列表，并在每条记录上标注 src_eligible=True。
    """
    passed = []
    for f in findings:
        if not is_src_noise(f):
            f["src_eligible"] = True
            passed.append(f)
    return passed


def get_src_stats(
    all_findings: List[Dict[str, Any]],
    src_findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """生成 SRC 过滤统计摘要"""
    filtered_count = len(all_findings) - len(src_findings)
    severity_dist: Dict[str, int] = {}
    for f in src_findings:
        sev = f.get("severity", "INFO")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    return {
        "total_raw": len(all_findings),
        "total_src_eligible": len(src_findings),
        "filtered_noise": filtered_count,
        "severity_distribution": severity_dist,
        "filter_rate": f"{round(filtered_count / max(1, len(all_findings)) * 100, 1)}%",
        "src_standard": "仅保留 MEDIUM(CVSS>=4.0)/HIGH/CRITICAL 且具备利用链的可认定漏洞",
        "noise_rules": [
            "过滤所有 HTTP 安全头缺失类发现",
            "过滤 Server Banner / 版本指纹暴露",
            "过滤 Cookie 单独属性缺失（无利用链）",
            "过滤 CDN SRI 缺失",
            "过滤 CVSS < 4.0 的所有中危发现",
        ]
    }
