import asyncio
import logging
from typing import Dict, Any, List
import aiohttp
from backend.app.config import settings
from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.alert")

class AlertService:
    """多渠道安全告警中心 (支持 Webhook / 钉钉机器人 / 企业微信 / 邮件)"""

    @classmethod
    async def send_alert(cls, task_name: str, target_url: str, findings: List[Dict[str, Any]], summary: Dict[str, Any], webhook_url: str = "") -> bool:
        webhook = webhook_url.strip() or settings.DEFAULT_WEBHOOK_URL
        if not webhook:
            logger.info("No webhook URL configured. Alert logged to console & audit log.")
            return True
            
        high_critical = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if not high_critical:
            logger.info("No HIGH or CRITICAL issues found. Skipping external alert.")
            return True
            
        # 构造 Markdown 告警卡片
        markdown_text = (
            f"### 🚨 【安恒星巡】网站安全巡检告警通知\n\n"
            f"- **任务名称**：{task_name}\n"
            f"- **巡检目标**：{target_url}\n"
            f"- **安全态势**：{summary.get('security_score', 0)} 分 ({summary.get('status_level', '')})\n"
            f"- **高危/严重风险**：{len(high_critical)} 项\n\n"
            f"**重点隐患清单**：\n"
        )
        for idx, item in enumerate(high_critical[:5], 1):
            markdown_text += f"{idx}. [{item.get('severity')}] **{item.get('title')}**\n   - 路径：`{item.get('url')}`\n"
            
        markdown_text += f"\n> 请管理员立即登录 DAS-SentinelAgent 控制台完成复测与整改闭环。"
        
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": "【安恒星巡】网站安全风险告警",
                "text": markdown_text
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook, json=payload, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    logger.info(f"Alert sent to webhook with status: {resp.status}")
                    return resp.status == 200
        except Exception as e:
            logger.warning(f"Failed to deliver alert to webhook {webhook}: {e}")
            return False
