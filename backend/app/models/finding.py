from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

class FindingEvidence(BaseModel):
    matched_snippet: Optional[str] = None
    matched_value_masked: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body_sample: Optional[str] = None
    location_dom_or_line: Optional[str] = None

class FindingResponse(BaseModel):
    id: str
    task_id: str
    category: str  # VULN, SENSITIVE, TAMPER, ASSET
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    param: Optional[str] = ""
    evidence: Dict[str, Any]
    impact: str
    remediation: str
    verified: int
    cvss_score: float
    status: str
    src_type: Optional[str] = "BASELINE_HYGIENE"
    created_at: str
    verified_at: Optional[str]


class FindingRetestRequest(BaseModel):
    finding_ids: Optional[List[str]] = None
