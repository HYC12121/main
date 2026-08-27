import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger("das_sentinel.hengnao")

class HengNaoAgentAdapter:
    """安恒恒脑安全智能体开发平台 (https://gc.das-ai.com) 标准适配层"""

    @classmethod
    def get_agent_manifest(cls) -> Dict[str, Any]:
        """导出符合恒脑智能体平台的 Agent Tool Definition 清单"""
        return {
            "schema_version": "v1.0",
            "agent_name": "DAS-SentinelAgent (安恒星巡安全智能体)",
            "description": "面向政企网站安全风险评估、页面防篡改/挂马与敏感信息防泄露的自动化智能巡检智能体",
            "vendor": "DAS-Security (杭州安恒信息技术股份有限公司)",
            "tools": [
                {
                    "name": "das_recon_assets",
                    "description": "在授权边界内自动递归爬取目标站点的页面、静态资源与 API 端点",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_url": {"type": "string", "description": "目标网站根地址"},
                            "auth_domains": {"type": "array", "items": {"type": "string"}, "description": "授权域名列表"},
                            "max_depth": {"type": "integer", "default": 3, "description": "爬取最大深度"},
                            "max_pages": {"type": "integer", "default": 50, "description": "最大抓取页面数"}
                        },
                        "required": ["target_url"]
                    }
                },
                {
                    "name": "das_scan_vulnerabilities",
                    "description": "执行非破坏性安全漏洞与弱配置排查 (包含安全响应头缺失、CORS跨域缺陷、Git/.env敏感文件泄露等)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_url": {"type": "string", "description": "目标网站根地址"},
                            "auth_domains": {"type": "array", "items": {"type": "string"}, "description": "授权域名列表"}
                        },
                        "required": ["target_url"]
                    }
                },
                {
                    "name": "das_inspect_tamper_malware",
                    "description": "检测网站是否存在隐蔽暗链、黑产博彩外链、恶意挖矿挂马脚本及页面涂鸦篡改",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_url": {"type": "string", "description": "目标网站根地址"},
                            "auth_domains": {"type": "array", "items": {"type": "string"}, "description": "授权域名列表"}
                        },
                        "required": ["target_url"]
                    }
                },
                {
                    "name": "das_inspect_sensitive_leak",
                    "description": "排查身份证号、手机号、银行卡、AK/SK云凭证、数据库连接串及本单位自定义敏感信息泄露",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_url": {"type": "string", "description": "目标网站根地址"},
                            "custom_keywords": {"type": "array", "items": {"type": "string"}, "description": "本单位特定敏感关键词"}
                        },
                        "required": ["target_url"]
                    }
                },
                {
                    "name": "das_compare_baseline",
                    "description": "对比目标站点两次历史巡检基线，计算新增/修复漏洞及被篡改页面差异",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_url": {"type": "string", "description": "目标网站"},
                            "base_task_id": {"type": "string", "description": "基准任务ID"},
                            "current_task_id": {"type": "string", "description": "当前任务ID"}
                        },
                        "required": ["target_url"]
                    }
                }
            ]
        }
