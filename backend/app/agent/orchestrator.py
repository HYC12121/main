import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.config import settings
from backend.app.database import get_db_connection
from backend.app.scanners.asset_crawler import AssetCrawler
from backend.app.scanners.vuln_detector import VulnerabilityDetector
from backend.app.scanners.tamper_detector import TamperDetector
from backend.app.scanners.sensitive_inspector import SensitiveInspector
from backend.app.agent.verifier import FindingVerifier
from backend.app.agent.advisor import RemediationAdvisor

logger = logging.getLogger("das_sentinel.orchestrator")

class InspectionOrchestrator:
    """智能巡检编排执行引擎"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.task_data = self._load_task()
        
    def _load_task(self) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (self.task_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise ValueError(f"Task {self.task_id} not found in database.")
        return dict(row)

    def _update_task_status(self, status: str, progress: int, stage: str, summary: Optional[Dict[str, Any]] = None):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        if status == "RUNNING" and not self.task_data.get("started_at"):
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ?, started_at = ? WHERE id = ?",
                           (status, progress, stage, now, self.task_id))
        elif status in ("COMPLETED", "FAILED"):
            summary_json = json.dumps(summary or {}, ensure_ascii=False)
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ?, finished_at = ?, summary = ? WHERE id = ?",
                           (status, progress, stage, now, summary_json, self.task_id))
        else:
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ? WHERE id = ?",
                           (status, progress, stage, self.task_id))
        conn.commit()
        conn.close()

    def _log_audit(self, action: str, target: str, details: str, status: str = "SUCCESS"):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
        INSERT INTO audit_logs (timestamp, action, operator, target, details, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (now, action, "DAS_SENTINEL_AGENT", target, details, status))
        conn.commit()
        conn.close()

    async def run(self) -> Dict[str, Any]:
        """执行端到端全量智能巡检闭环流程"""
        target_url = self.task_data["target_url"]
        auth_domains = json.loads(self.task_data["auth_domains"])
        scan_scope = json.loads(self.task_data["scan_scope"])
        
        logger.info(f"Starting inspection task [{self.task_id}] for {target_url}")
        self._update_task_status("RUNNING", 5, "正在进行授权边界校验与环境预检...")
        self._log_audit("TASK_START", target_url, f"启动巡检任务: {self.task_data['name']}")

        try:
            # 阶段 1：站点资产与页面深度发现
            self._update_task_status("RUNNING", 15, "正在执行站点资源发现与拓扑测绘 (Crawler)...")
            crawler = AssetCrawler(
                base_url=target_url,
                auth_domains=auth_domains,
                max_depth=scan_scope.get("max_depth", 3),
                max_pages=scan_scope.get("max_pages", 50),
                qps_limit=scan_scope.get("qps_limit", 5.0)
            )
            crawl_results = await crawler.crawl()
            crawled_pages = crawl_results["pages"]
            logger.info(f"Crawl completed. Total pages discovered: {len(crawled_pages)}")
            self._log_audit("RECON_PAGE", target_url, f"发现有效页面 {len(crawled_pages)} 个，外链 {len(crawl_results['external_links'])} 个")

            # 阶段 2：常见漏洞与弱配置检测 (包含抗误报基线、安全标头、Cookie、CORS、JS 秘钥、API 文档与参数探针)
            self._update_task_status("RUNNING", 35, "正在编排开源工具检测配置缺陷、安全标头与参数探针 (Vuln Probe)...")
            vuln_detector = VulnerabilityDetector(target_url, auth_domains)
            vuln_findings = await vuln_detector.scan_all(crawled_pages, crawl_metadata=crawl_results)

            # 阶段 2.5：🔥 启动【专项深入测试与漏洞利用链闭环】(Deep Exploit & Chaining Engine)
            if vuln_findings:
                self._update_task_status("RUNNING", 50, f"发现 {len(vuln_findings)} 个潜在隐患，正在启动 SQL/LFI/SSTI/BOLA 专项深入渗透与利用链推演...")
                from backend.app.scanners.deep_exploit_engine import DeepExploitEngine
                vuln_findings = await DeepExploitEngine.run_specialized_deep_audit(vuln_findings)
                self._log_audit("DEEP_AUDIT", target_url, f"完成对 {len(vuln_findings)} 项漏洞的专项深度利用验证与链式闭环组装")

            # 阶段 3：页面篡改、暗链与挂马脚本检测
            self._update_task_status("RUNNING", 65, "正在执行页面完整性比对、暗链与恶意挂马脚本检测 (Tamper Engine)...")
            tamper_detector = TamperDetector(auth_domains)
            tamper_findings = tamper_detector.scan_pages(crawled_pages)

            # 阶段 4：敏感信息与数据泄露深度检查 (覆盖 HTML 与 JS 脚本)
            self._update_task_status("RUNNING", 80, "正在执行多模态敏感数据、个人隐私与凭证泄露检查 (Sensitive Inspector)...")
            custom_keywords = scan_scope.get("custom_sensitive_keywords", [])
            sensitive_inspector = SensitiveInspector(custom_keywords=custom_keywords)
            sensitive_findings = sensitive_inspector.scan_pages(crawled_pages, js_scripts=crawl_results.get("js_scripts", []))

            # 阶段 5：智能去重、关联验证、风险定级与架构拓扑指纹分析
            self._update_task_status("RUNNING", 90, "正在执行智能体去重、技术栈拓扑指纹识别与风险定级归纳...")
            all_raw_findings = vuln_findings + tamper_findings + sensitive_findings
            deduped_findings = FindingVerifier.deduplicate_findings(all_raw_findings)
            
            # 为每一条发现注入专家整改建议
            enriched_findings = [RemediationAdvisor.enhance_finding_advisory(f) for f in deduped_findings]
            
            # 技术栈架构与拓扑指纹识别 (前端/后端/Web容器/数据库/安全防护)
            from backend.app.scanners.fingerprint_detector import ArchitectureFingerprintDetector
            architecture_info = ArchitectureFingerprintDetector.detect_architecture(target_url, crawled_pages, enriched_findings)
            
            # 计算风险总览
            risk_summary = FindingVerifier.calculate_risk_summary(enriched_findings)
            risk_summary["total_pages_scanned"] = len(crawled_pages)
            risk_summary["total_assets_discovered"] = len(crawl_results["static_assets"])
            risk_summary["total_external_links"] = len(crawl_results["external_links"])
            risk_summary["architecture"] = architecture_info

            # 阶段 6：持久化入库与保存基线快照
            self._save_findings_and_baseline(enriched_findings, crawl_results, risk_summary)

            self._update_task_status("COMPLETED", 100, "智能巡检闭环完成，报告已生成", summary=risk_summary)
            self._log_audit("TASK_COMPLETE", target_url, f"巡检完成，发现总风险数: {len(enriched_findings)}，架构识别: {architecture_info['layers'][0]['component']['name']} + {architecture_info['layers'][1]['component']['name']}")
            
            return {
                "task_id": self.task_id,
                "target_url": target_url,
                "summary": risk_summary,
                "findings": enriched_findings,
                "architecture": architecture_info
            }

        except Exception as e:
            logger.exception(f"Inspection task failed: {e}")
            self._update_task_status("FAILED", 0, f"巡检中断异常: {str(e)}")
            self._log_audit("TASK_ERROR", target_url, f"巡检异常: {str(e)}", status="FAILED")
            raise

    def _save_findings_and_baseline(self, findings: List[Dict[str, Any]], crawl_results: Dict[str, Any], summary: Dict[str, Any]):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        pages = crawl_results.get("pages", [])
        static_assets = crawl_results.get("static_assets", set())
        api_endpoints = crawl_results.get("api_endpoints", set())
        external_links = crawl_results.get("external_links", set())
        
        # 1. 写入 findings
        for f in findings:
            ev_dict = dict(f.get("evidence", {}))
            if f.get("deep_audit"):
                ev_dict["deep_audit"] = f["deep_audit"]
            if f.get("exploit_chain"):
                ev_dict["exploit_chain"] = f["exploit_chain"]
            evidence_str = json.dumps(ev_dict, ensure_ascii=False)
            cursor.execute("""

            INSERT OR REPLACE INTO findings (id, task_id, category, title, severity, url, param, evidence, impact, remediation, verified, cvss_score, status, src_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f["id"], self.task_id, f["category"], f["title"], f["severity"],
                f["url"], f.get("param", ""), evidence_str, f["impact"], f["remediation"],
                f.get("verified", 1), f.get("cvss_score", 0.0), f.get("status", "OPEN"),
                f.get("src_type", "BASELINE_HYGIENE"), now
            ))

            
        # 2. 构造结构化资产拓扑地图
        assets_list = []
        for p in pages:
            assets_list.append({
                "url": p["url"],
                "title": p.get("title", ""),
                "status": p.get("status", 200),
                "type": "PAGE",
                "depth": p.get("depth", 0)
            })
        for api in api_endpoints:
            assets_list.append({
                "url": api,
                "title": "API 接口端点",
                "status": 200,
                "type": "API",
                "depth": 1
            })
        for st in static_assets:
            assets_list.append({
                "url": st,
                "title": "静态资源文件",
                "status": 200,
                "type": "STATIC",
                "depth": 1
            })
        for ext in external_links:
            assets_list.append({
                "url": ext,
                "title": "外部引用链接",
                "status": 0,
                "type": "EXTERNAL",
                "depth": 1
            })

        # 3. 写入 baselines 快照
        baseline_id = str(uuid.uuid4())
        dom_hashes = {p["url"]: p["dom_hash"] for p in pages if "url" in p and "dom_hash" in p}
        findings_hash = str(hash(tuple(sorted(f["title"] for f in findings))))
        
        cursor.execute("""
        INSERT INTO baselines (id, target_url, task_id, snapshot_time, pages_count, assets_json, dom_hashes_json, findings_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            baseline_id, self.task_data["target_url"], self.task_id, now,
            len(pages), json.dumps(assets_list, ensure_ascii=False),
            json.dumps(dom_hashes, ensure_ascii=False), findings_hash
        ))
        
        conn.commit()
        conn.close()

