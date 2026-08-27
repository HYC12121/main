import os

filepath = r"d:\Gemini Work\DAS_SentinelAgent\backend\app\scanners\vuln_detector.py"
with open(filepath, "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

split_marker = "            # =========================================================================" + "\n" + "            # 5. ⚡ 命令注入"

# Let's find where step 4 (SSTI) ends:
ssti_end_marker = "                                        break\n                except Exception:\n                    pass\n\n            # ========================================================================="

idx = content.find(ssti_end_marker)
if idx == -1:
    # try looser search
    idx = content.find("SSTI")
    idx = content.find("except Exception:\n                    pass", idx) + len("except Exception:\n                    pass")

top_part = content[:idx]

clean_tail = """

            # =========================================================================
            # 5. ⚡ 命令注入 (动态非自含算术执行验证，彻底杜绝 URL 埋点/JS 回显造成的误报)
            # =========================================================================
            math_a = 48218
            math_b = 19283
            math_expected = str(math_a + math_b) # "67501"

            cmd_vectors = [
                (f"; expr {math_a} + {math_b} ;", math_expected, "分号动态算术命令注入"),
                (f"| expr {math_a} + {math_b}", math_expected, "管道符动态算术命令注入"),
                (f"& expr {math_a} + {math_b} &", math_expected, "后台符动态算术命令注入"),
                (f"`expr {math_a} + {math_b}`", math_expected, "反引号动态算术命令执行"),
                ("; echo das_cmd_exec_8394 ;", "das_cmd_exec_8394", "分号分隔符回显命令注入")
            ]
            for cmd_payload, marker, desc in cmd_vectors:
                try:
                    test_url = f"{url}?{param}={cmd_payload}"
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as cmd_resp:
                        if cmd_resp.status == 200:
                            cmd_body = await cmd_resp.text(errors="replace")
                            is_reflection_only = False
                            if "das_cmd_exec_8394" in cmd_payload:
                                if f"url={cmd_payload}" in cmd_body or f'"{cmd_payload}"' in cmd_body or f"'{cmd_payload}'" in cmd_body or "window.location" in cmd_body:
                                    is_reflection_only = True
                            
                            if marker in cmd_body and not is_reflection_only and not self._is_false_positive_spa_response(cmd_body, cmd_resp.status):
                                baseline_url = f"{url}?{param}=das_cmd_baseline_check"
                                async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=4.0)) as base_resp:
                                    base_body = await base_resp.text(errors="replace")
                                    if marker not in base_body:
                                        findings.append({
                                            "id": str(uuid.uuid4()),
                                            "category": "VULN",
                                            "title": f"参数存在操作系统命令注入漏洞 (Command Injection) [{param}] ({desc})",
                                            "severity": "CRITICAL",
                                            "url": url,
                                            "param": f"Param: {param}",
                                            "evidence": {
                                                "probe_payload": cmd_payload,
                                                "execution_marker": marker,
                                                "matched_snippet": f"系统成功执行子命令并返回非自含计算特征: {marker}"
                                            },
                                            "impact": "攻击者可直接获取底层操作系统服务器 Shell 权限，控制宿主服务器",
                                            "remediation": f"禁止使用 system()/exec()/os.system() 拼接参数 {param}，改用安全参数列表方式调用",
                                            "verified": 1,
                                            "cvss_score": 9.8,
                                            "status": "OPEN"
                                        })
                                        break
                except Exception:
                    pass

            # =========================================================================
            # 6. 🌐 SSRF 服务端请求伪造 (云元数据与内网探测，排除 HTML 404 伪响应)
            # =========================================================================
            if any(k in param.lower() for k in ["url", "proxy", "link", "target", "src", "fetch", "domain", "api"]):
                ssrf_targets = [
                    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"], "云厂商元数据接口 (AWS/AliCloud Metadata)"),
                    ("http://127.0.0.1:6379/", ["redis", "internal_service", "connected"], "本地 Redis / 内部管理接口"),
                    ("http://2130706433/", ["redis", "internal_service"], "十进制 IP 绕过本地环回")
                ]
                for ssrf_url, markers, desc in ssrf_targets:
                    try:
                        test_url = f"{url}?{param}={ssrf_url}"
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as ssrf_resp:
                            if ssrf_resp.status == 200:
                                ssrf_body = await ssrf_resp.text(errors="replace")
                                is_html_webpage = "<!doctype html" in ssrf_body.lower() or "<html" in ssrf_body.lower()
                                if any(m in ssrf_body.lower() for m in markers) and not is_html_webpage and not self._is_false_positive_spa_response(ssrf_body, ssrf_resp.status):
                                    findings.append({
                                        "id": str(uuid.uuid4()),
                                        "category": "VULN",
                                        "title": f"参数存在服务端请求伪造漏洞 (SSRF) [{param}] ({desc})",
                                        "severity": "HIGH",
                                        "url": url,
                                        "param": f"Param: {param}",
                                        "evidence": {
                                            "ssrf_target": ssrf_url,
                                            "matched_snippet": f"服务端向内部目标发起请求并回显元数据特征: {desc}"
                                        },
                                        "impact": "攻击者可探测内网未公开服务、窃取云主机 IAM 凭证并攻击内网数据库",
                                        "remediation": f"对参数 {param} 实施严格协议白名单 (仅限 http/https)，并在网络层禁止访问私有网段",
                                        "verified": 1,
                                        "cvss_score": 8.6,
                                        "status": "OPEN"
                                    })
                                    break
                    except Exception:
                        pass

        # 7. 🌐 扫描页面中的 Subresource Integrity (SRI) 与表单 CSRF Token 缺失
        sri_csrf_findings = self._check_sri_and_csrf_hygiene(crawled_pages)
        findings.extend(sri_csrf_findings)

        return findings

    def _check_sri_and_csrf_hygiene(self, crawled_pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        \"\"\"检测外部 CDN 脚本缺失 SRI 完整性校验与敏感表单缺失 Anti-CSRF Token\"\"\"
        findings = []
        seen_sri_hosts = set()
        
        for p in crawled_pages:
            url = p.get("url", "")
            html = p.get("html_content", "")
            if not html:
                continue
            try:
                soup = BeautifulSoup(html, "html.parser")
                
                # 1. 外部第三方 CDN 脚本未配置 integrity 属性 (SRI)
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                        parsed_src = urlparse(src if not src.startswith("//") else "https:" + src)
                        script_netloc = parsed_src.netloc.lower().split(':')[0]
                        
                        # 排除同源、主域名子域及常用首方 CDN
                        is_own_domain = False
                        for auth in self.auth_domains:
                            auth_clean = auth.lower().split(':')[0]
                            if script_netloc == auth_clean or script_netloc.endswith("." + auth_clean) or auth_clean.endswith("." + script_netloc):
                                is_own_domain = True
                                break
                            base_root = ".".join(auth_clean.split('.')[-2:]) if '.' in auth_clean else auth_clean
                            if base_root in script_netloc:
                                is_own_domain = True
                                break

                        if script_netloc and not is_own_domain:
                            if not script.get("integrity") and script_netloc not in seen_sri_hosts:
                                seen_sri_hosts.add(script_netloc)
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "category": "VULN",
                                    "title": f"外部第三方 CDN 脚本缺失子资源完整性校验 (SRI) [{script_netloc}]",
                                    "severity": "INFO",
                                    "url": url,
                                    "param": f"Script: {src[:60]}",
                                    "evidence": {
                                        "script_src": src,
                                        "missing_attribute": "integrity"
                                    },
                                    "impact": "若第三方 CDN 服务商遭受供应链污染或 DNS 劫持，恶意脚本将在本站用户浏览器中直接执行",
                                    "remediation": "在加载外部 CDN 脚本时增加 integrity 属性 (例如 integrity='sha384-...' crossorigin='anonymous')",
                                    "verified": 1,
                                    "cvss_score": 3.5,
                                    "status": "OPEN"
                                })

                # 2. 敏感 POST 表单未配置 CSRF Token
                for form in soup.find_all("form"):
                    method = form.get("method", "GET").upper()
                    if method == "POST":
                        has_csrf = False
                        for inp in form.find_all("input"):
                            name = inp.get("name", "").lower()
                            if any(k in name for k in ["csrf", "token", "xsrf", "_csrf_token"]):
                                has_csrf = True
                                break
                        if not has_csrf:
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": "敏感 POST 数据提交表单缺失 Anti-CSRF Token 防御机制",
                                "severity": "MEDIUM",
                                "url": url,
                                "param": f"Form Action: {form.get('action', '')}",
                                "evidence": {
                                    "form_action": form.get("action", ""),
                                    "missing_defense": "Anti-CSRF Token"
                                },
                                "impact": "第三方恶意网站可通过跨站伪造请求诱使用户在不知情的情况下提交敏感表单或修改账户设置",
                                "remediation": "为所有状态改变的 POST 表单增加不可预测的随机 Anti-CSRF Token 校验",
                                "verified": 1,
                                "cvss_score": 5.8,
                                "status": "OPEN"
                            })
            except Exception as e:
                logger.debug(f"Error checking SRI/CSRF on {url}: {e}")

        return findings
"""

with open(filepath, "w", encoding="utf-8") as f:
    f.write(top_part + clean_tail)

print("SUCCESS: Cleanly formatted and restored vuln_detector.py!")
