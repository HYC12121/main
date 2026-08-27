from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any

class TaskCreateRequest(BaseModel):
    name: str = Field(..., description="巡检任务名称")
    target_url: str = Field(..., description="目标站点根 URL")
    auth_domains: List[str] = Field(default_factory=list, description="授权域名清单，如 ['example.com', 'sub.example.com']")
    max_depth: int = Field(default=3, ge=1, le=5, description="爬取最大深度")
    max_pages: int = Field(default=100, ge=5, le=500, description="最大发现页面数")
    qps_limit: float = Field(default=5.0, ge=0.5, le=20.0, description="请求并发速率限制")
    cron_expr: Optional[str] = Field(default="", description="定时 Cron 表达式，例如 '0 2 * * *' (每天凌晨2点)")
    enable_tamper_check: bool = Field(default=True, description="是否启用暗链与挂马篡改检测")
    enable_sensitive_check: bool = Field(default=True, description="是否启用敏感信息检测")
    enable_vuln_check: bool = Field(default=True, description="是否启用常见漏洞与配置缺陷检测")
    custom_sensitive_keywords: List[str] = Field(default_factory=list, description="临时追加的本单位特定敏感关键词")

class TaskResponse(BaseModel):
    id: str
    name: str
    target_url: str
    auth_domains: List[str]
    status: str
    progress: int
    current_stage: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    summary: Optional[Dict[str, Any]]
