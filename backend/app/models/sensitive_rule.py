from pydantic import BaseModel, Field
from typing import Optional

class SensitiveRuleCreate(BaseModel):
    name: str = Field(..., description="规则名称，如：内部财务项目代号")
    category: str = Field(..., description="规则分类：ID_CARD, PHONE, BANK_CARD, SECRET_KEY, CUSTOM_REGEX, KEYWORD, FILE_TYPE")
    pattern: str = Field(..., description="匹配正则表达式或关键词")
    sample_data: Optional[str] = Field(default="", description="测试示例数据")
    risk_level: str = Field(default="HIGH", description="风险等级：CRITICAL, HIGH, MEDIUM, LOW")
    description: Optional[str] = Field(default="", description="规则说明")
    enabled: bool = Field(default=True, description="是否启用")

class SensitiveRuleResponse(BaseModel):
    id: str
    name: str
    category: str
    pattern: str
    sample_data: str
    risk_level: str
    description: str
    is_builtin: int
    enabled: int
    created_at: str

class SensitiveRuleTestRequest(BaseModel):
    pattern: str
    category: str
    test_text: str
