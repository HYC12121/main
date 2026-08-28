import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.config import settings
from backend.app.database import get_db_connection
from backend.app.agent.verifier import FindingVerifier
from plugins.core.base import ScanContext
from plugins.core.registry import scanner_registry

# 预先加载插件
scanner_registry.discover_scanners(['scanner_core', 'scanner_extensions'])
from plugins.core.src_filter import apply_src_filter, get_src_stats
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
        """执行端到端全量智能巡检闭环流程 (已解耦)"""
        target_url = self.task_data["target_url"]
        auth_domains = json.loads(self.task_data["auth_domains"])
        scan_scope = json.loads(self.task_data["scan_scope"])
        
        logger.info(f"Starting inspection task [{self.task_id}] for {target_url}")
        self._update_task_status("RUNNING", 5, "正在进行授权边界校验与环境预检...")
        self._log_audit("TASK_START", target_url, f"启动巡检任务: {self.task_data['name']}")

        try:
            from plugins.core.base import ScanContext
            from plugins.core.registry import scanner_registry
            
            scanner_registry.discover_scanners(['plugins.scanner_core', 'plugins.scanner_extensions'])
            
            context = ScanContext(
                task_id=self.task_id,
                target_url=target_url,
                auth_domains=auth_domains,
                scan_scope=scan_scope
            )
            
            scanners_dict = {cls.__name__: cls for cls in scanner_registry.get_all_scanners()}
            
            # 阶段 1：资产发现
            if 'AssetCrawler' in scanners_dict:
                self._update_task_status("RUNNING", 15, "执行资产发现...")
                crawler = scanners_dict['AssetCrawler'](
                    base_url=target_url,
                    auth_domains=auth_domains,
                    max_depth=scan_scope.get("max_depth", 3),
                    max_pages=scan_scope.get("max_pages", 50),
                    qps_limit=scan_scope.get("qps_limit", 5.0)
                )
                await crawler.run(context)
                
            # 阶段 1.2：特殊链接提取与外链清洗 (link_processor 方向)
            if 'SmartLinkExtractor' in scanners_dict:
                link_ext = scanners_dict['SmartLinkExtractor']()
                await link_ext.run(context)
                
            # 阶段 1.5：子资产扩展 (sub_assets 方向)
            if 'SubAssetExpander' in scanners_dict:
                self._update_task_status("RUNNING", 25, "执行子资产扩展...")
                sub = scanners_dict['SubAssetExpander']()
                await sub.run(context)
                
            # 阶段 2：漏洞探测 (scanner_core)
            if 'VulnerabilityDetector' in scanners_dict:
                self._update_task_status("RUNNING", 35, "执行漏洞探测...")
                vuln = scanners_dict['VulnerabilityDetector'](target_url, auth_domains)
                await vuln.run(context)

            # 阶段 2.2：REST API 接口轻量探针 (api_fuzzer 方向)
            if 'RestApiProber' in scanners_dict:
                api_prober = scanners_dict['RestApiProber']()
                await api_prober.run(context)
                
            # 阶段 2.5：深度渗透
            if 'DeepExploitEngine' in scanners_dict:
                self._update_task_status("RUNNING", 50, "执行深度渗透...")
                deep = scanners_dict['DeepExploitEngine']()
                await deep.run(context)
                
            # 阶段 3 & 4：篡改和敏感数据
            if 'TamperDetector' in scanners_dict:
                self._update_task_status("RUNNING", 65, "执行篡改检测...")
                tamper = scanners_dict['TamperDetector'](auth_domains)
                await tamper.run(context)
                
            if 'SensitiveInspector' in scanners_dict:
                self._update_task_status("RUNNING", 80, "执行敏感信息检测...")
                sens = scanners_dict['SensitiveInspector'](custom_keywords=scan_scope.get('custom_sensitive_keywords', []))
                await sens.run(context)

            all_raw_findings = context.findings

            # 智能体去重与指纹归纳
            self._update_task_status("RUNNING", 90, "正在执行智能体去重、技术栈拓扑指纹识别与风险定级归纳...")
            all_raw_findings_pre_src = all_raw_findings.copy()
            all_raw_findings = apply_src_filter(all_raw_findings)
            deduped_findings = FindingVerifier.deduplicate_findings(all_raw_findings)
            
            enriched_findings = [RemediationAdvisor.enhance_finding_advisory(f) for f in deduped_findings]
            
            from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
            architecture_info = ArchitectureFingerprintDetector.detect_architecture(
                target_url,
                context.crawled_pages,
                enriched_findings
            )
            
            risk_summary = FindingVerifier.calculate_risk_summary(enriched_findings)
            risk_summary["total_pages_scanned"] = len(context.crawled_pages)
            risk_summary["total_assets_discovered"] = len(context.static_assets)
            risk_summary["total_external_links"] = len(context.external_links)
            risk_summary["total_sub_assets"] = len(context.sub_assets)
            risk_summary["sub_assets"] = context.sub_assets
            risk_summary["topology_cluster"] = context.topology_cluster
            risk_summary["architecture"] = architecture_info

            crawl_results = {
                "pages": context.crawled_pages,
                "static_assets": context.static_assets,
                "api_endpoints": context.api_endpoints,
                "external_links": context.external_links,
                "sub_assets": context.sub_assets
            }
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

