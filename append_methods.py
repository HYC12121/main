"""
Script to append new methods to vuln_detector.py
"""

new_methods = r'''
    # ==========================================================================
    # GraphQL Probe
    # ==========================================================================
    async def _probe_graphql_endpoints(self, session) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        base = self.target_url.rstrip("/")
        paths = [
            f"{base}/graphql", f"{base}/api/graphql", f"{base}/v1/graphql",
            f"{base}/gql", f"{base}/api/gql", f"{base}/query",
        ]
        payload = '{"query":"{__schema{types{name}}}"}'
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        for url in paths:
            try:
                async with session.post(url, data=payload, headers=hdrs,
                        timeout=_aiohttp.ClientTimeout(total=6.0), allow_redirects=False) as r:
                    if r.status == 200:
                        body = await r.text(errors="replace")
                        if '"__schema"' in body and '"types"' in body and not self._is_false_positive_spa_response(body, r.status):
                            findings.append({
                                "id": str(_uuid.uuid4()), "category": "VULN",
                                "title": f"GraphQL端点未授权自省暴露Schema [{url}]",
                                "severity": "MEDIUM", "url": url, "param": "POST introspection",
                                "evidence": {
                                    "matched_snippet": body[:400],
                                    "introspection_payload": payload,
                                    "verification_steps": [
                                        f"curl -sk -X POST '{url}' -H 'Content-Type: application/json' -d '{payload}'",
                                        "返回 __schema.types 说明自省未禁用"
                                    ]
                                },
                                "impact": "攻击者可获取完整API schema用于构造未授权查询",
                                "remediation": "生产环境禁用GraphQL Introspection",
                                "verified": 1, "cvss_score": 5.3, "status": "OPEN"
                            })
            except Exception as e:
                import logging
                logging.getLogger("das_sentinel.vuln").debug(f"GraphQL {url}: {e}")
        return findings

    # ==========================================================================
    # API Routes Bruteforce Probe
    # ==========================================================================
    async def _probe_api_routes_bruteforce(self, session) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        base = self.target_url.rstrip("/")
        paths = [
            "/admin", "/admin/api", "/admin/users", "/api/admin",
            "/api/internal", "/api/users", "/api/user/list",
            "/api/v1/users", "/api/v2/users", "/api/config",
            "/api/settings", "/api/env", "/actuator", "/actuator/env",
            "/actuator/beans", "/actuator/heapdump", "/actuator/mappings",
            "/actuator/loggers", "/metrics", "/prometheus",
            "/server-status", "/debug",
        ]
        sensitive = [
            '"email"', '"phone"', '"password"', '"token"', '"role"',
            '"admin"', '"secret"', '"key"', "DATABASE_URL", "SECRET_KEY",
            "APP_KEY", "activeProfiles",
        ]
        for path in paths:
            probe_url = f"{base}{path}"
            try:
                async with session.get(probe_url, allow_redirects=False,
                        timeout=_aiohttp.ClientTimeout(total=5.0)) as r:
                    if r.status not in (200, 201, 206):
                        continue
                    body = await r.text(errors="replace")
                    if not body or self._is_false_positive_spa_response(body, r.status):
                        continue
                    ctype = r.headers.get("Content-Type", "")
                    matched = [s for s in sensitive if s in body]
                    if matched and ("application/json" in ctype or body.strip().startswith(("{", "["))):
                        sev = "HIGH" if any(k in path for k in ["/admin", "heapdump", "/internal", "/config"]) else "MEDIUM"
                        findings.append({
                            "id": str(_uuid.uuid4()), "category": "VULN",
                            "title": f"敏感API路径未授权访问 [{path}]",
                            "severity": sev, "url": probe_url, "param": f"Path: {path}",
                            "evidence": {
                                "matched_snippet": body[:350],
                                "sensitive_indicators": matched,
                                "response_status": r.status,
                                "verification_steps": [
                                    f"curl -sk '{probe_url}'",
                                    f"HTTP {r.status}, sensitive fields: {matched[:5]}",
                                    "无需任何认证即可访问"
                                ]
                            },
                            "impact": f"未授权攻击者可访问 {path} 获取敏感数据",
                            "remediation": f"为 {path} 添加认证或在WAF/网络层禁止外网访问",
                            "verified": 1, "cvss_score": 7.5, "status": "OPEN"
                        })
            except Exception as e:
                import logging
                logging.getLogger("das_sentinel.vuln").debug(f"Brute {probe_url}: {e}")
        return findings

    # ==========================================================================
    # Open Redirect Probe
    # ==========================================================================
    async def _probe_open_redirect(self, session, url_parameters) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        rparams = {
            "redirect", "return", "returnurl", "returnto", "next", "goto",
            "url", "target", "destination", "dest", "from", "callback",
            "redirect_uri", "continue", "forward", "location", "jump"
        }
        evil = "https://evil-attacker-das-sentinel.com/steal"
        tested = set()
        for p_info in (url_parameters or [])[:15]:
            ep = p_info.get("endpoint", "")
            for param in p_info.get("params", []):
                if param.lower() not in rparams:
                    continue
                key = f"{ep}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                probe = f"{ep}?{param}={evil}"
                try:
                    async with session.get(probe, allow_redirects=False,
                            timeout=_aiohttp.ClientTimeout(total=5.0)) as r:
                        loc = r.headers.get("Location", "")
                        if r.status in (301, 302, 303, 307, 308) and "evil-attacker-das-sentinel.com" in loc:
                            findings.append({
                                "id": str(_uuid.uuid4()), "category": "VULN",
                                "title": f"开放重定向漏洞 (Open Redirect) [{param}]",
                                "severity": "MEDIUM", "url": ep, "param": f"Param: {param}",
                                "evidence": {
                                    "probe_url": probe,
                                    "redirect_to": loc,
                                    "status_code": r.status,
                                    "matched_snippet": f"GET {probe} -> {r.status} Location: {loc}",
                                    "verification_steps": [
                                        f"curl -skI '{probe}'",
                                        f"返回 {r.status} Location: {loc}",
                                        "攻击者可构造钓鱼链接或劫持OAuth令牌"
                                    ]
                                },
                                "impact": "攻击者可构造带合法域名外观的恶意链接，用于钓鱼攻击或OAuth令牌劫持",
                                "remediation": f"对参数 {param} 实施跳转目标白名单校验",
                                "verified": 1, "cvss_score": 6.1, "status": "OPEN"
                            })
                except Exception as e:
                    import logging
                    logging.getLogger("das_sentinel.vuln").debug(f"Redirect {probe}: {e}")
        return findings

    # Keep backward compatibility alias
    async def _probe_api_unauthorized_endpoints(self, session, discovered_apis) -> list:
        return await self._probe_api_unauthorized_endpoints_v2(session, discovered_apis)
'''

with open('backend/app/scanners/vuln_detector.py', 'a', encoding='utf-8') as f:
    f.write(new_methods)
print('OK - new methods appended successfully')
