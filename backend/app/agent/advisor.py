import logging
from typing import Dict, Any

logger = logging.getLogger("das_sentinel.advisor")

class RemediationAdvisor:
    """智能安全建议与整改处置方案生成专家系统"""

    REMEDIATION_KNOWLEDGE_BASE = {
        "GIT_LEAK": {
            "title": "Git 元数据泄露修复方案",
            "nginx_config": """location ~ /\\.git {
    deny all;
    return 404;
}""",
            "steps": [
                "1. 立即在 Web 服务器（Nginx/Apache）中配置针对隐藏目录（以.开头）的全局访问拦截规则。",
                "2. 检查生产环境部署流程，在 CI/CD 发布时排除 .git 目录（例如 rsync --exclude='.git'）。",
                "3. 排查历史提交记录中是否包含硬编码账号密码，若存在须立即重置密钥凭据。"
            ]
        },
        "ENV_LEAK": {
            "title": "环境变量与配置文件暴露整改方案",
            "nginx_config": """location ~* \\.(env|bak|sql|tar|gz|zip|swp|yaml|yml)$ {
    deny all;
    return 404;
}""",
            "steps": [
                "1. 严禁将 .env、config.json、备份 sql 等敏感文件放置在 Web 根目录下。",
                "2. 立即在 Nginx 中追加敏感后缀拦截规则。",
                "3. 立即更换 .env 中暴露的全部数据库密码、第三方 API Token 和 APP_KEY。"
            ]
        },
        "HIDDEN_LINK": {
            "title": "恶意外链与暗链处置方案",
            "steps": [
                "1. 隔离受影响页面文件，使用版本控制系统比对差异，清除被非法植入的 <a> 隐藏标签。",
                "2. 检查网站后台管理员账号与弱密码，重置所有后台凭证。",
                "3. 审查 CMS 上传漏洞及富文本编辑器安全策略，启用 WAF 防护。"
            ]
        },
        "SENSITIVE_DATA": {
            "title": "公民个人隐私与敏感信息防泄露整改建议",
            "steps": [
                "1. 在前端展示与 API 响应接口中统一实施敏感数据脱敏规则（如身份证保留前6后4、手机号保留前3后4）。",
                "2. 建立网站信息发布“三审三校”审批机制，防范运维及采编人员误将含隐私表格或附件公开发布。",
                "3. 开展历史已发布文档与新闻公告的全面排查与清理。"
            ]
        }
    }

    @classmethod
    def enhance_finding_advisory(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """为发现的问题注入更丰富的代码级修复样例与长效整改建议"""
        title = finding.get("title", "")
        category = finding.get("category", "")
        
        if "Git" in title:
            finding["remediation_details"] = cls.REMEDIATION_KNOWLEDGE_BASE["GIT_LEAK"]
        elif ".env" in title or "备份" in title or "配置" in title:
            finding["remediation_details"] = cls.REMEDIATION_KNOWLEDGE_BASE["ENV_LEAK"]
        elif "暗链" in title or "挂马" in title or "篡改" in title:
            finding["remediation_details"] = cls.REMEDIATION_KNOWLEDGE_BASE["HIDDEN_LINK"]
        elif category == "SENSITIVE":
            finding["remediation_details"] = cls.REMEDIATION_KNOWLEDGE_BASE["SENSITIVE_DATA"]
            
        return finding
