import re
import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, HTTPException, Query
from backend.app.database import get_db_connection
from backend.app.models.sensitive_rule import SensitiveRuleCreate, SensitiveRuleResponse, SensitiveRuleTestRequest
from backend.app.scanners.sensitive_inspector import SensitiveInspector

router = APIRouter(prefix="/rules", tags=["敏感信息规则库管理"])

@router.get("", response_model=List[SensitiveRuleResponse])
async def list_rules():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensitive_rules ORDER BY is_builtin DESC, created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [SensitiveRuleResponse(**dict(r)) for r in rows]

@router.post("", response_model=SensitiveRuleResponse)
async def create_rule(rule_in: SensitiveRuleCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    rule_id = f"rule-custom-{uuid.uuid4().hex[:6]}"
    now = datetime.now().isoformat()
    
    cursor.execute("""
    INSERT INTO sensitive_rules (id, name, category, pattern, sample_data, risk_level, description, is_builtin, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    """, (
        rule_id, rule_in.name, rule_in.category, rule_in.pattern,
        rule_in.sample_data or "", rule_in.risk_level, rule_in.description or "",
        1 if rule_in.enabled else 0, now
    ))
    conn.commit()
    conn.close()
    
    return SensitiveRuleResponse(
        id=rule_id,
        name=rule_in.name,
        category=rule_in.category,
        pattern=rule_in.pattern,
        sample_data=rule_in.sample_data or "",
        risk_level=rule_in.risk_level,
        description=rule_in.description or "",
        is_builtin=0,
        enabled=1 if rule_in.enabled else 0,
        created_at=now
    )

@router.post("/test")
async def test_rule_pattern(test_in: SensitiveRuleTestRequest):
    """在线测试正则表达式或关键词匹配效果"""
    try:
        matches = []
        for m in re.finditer(test_in.pattern, test_in.test_text, re.IGNORECASE):
            matched_val = m.group(0)
            valid = True
            if test_in.category == "ID_CARD":
                valid = SensitiveInspector.validate_id_card(matched_val)
            elif test_in.category == "BANK_CARD":
                valid = SensitiveInspector.validate_luhn(matched_val)
                
            matches.append({
                "value": matched_val,
                "masked": SensitiveInspector.mask_sensitive_value(matched_val, test_in.category),
                "is_valid_checksum": valid,
                "start": m.start(),
                "end": m.end()
            })
        return {
            "success": True,
            "match_count": len(matches),
            "matches": matches
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"正则表达式语法错误: {str(e)}",
            "match_count": 0,
            "matches": []
        }

@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_builtin FROM sensitive_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")
    if row["is_builtin"] == 1:
        conn.close()
        raise HTTPException(status_code=400, detail="内置规则不可删除，但可禁用")
    cursor.execute("DELETE FROM sensitive_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return {"message": "Rule deleted successfully"}
