from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class BaselineSnapshot(BaseModel):
    id: str
    target_url: str
    task_id: str
    snapshot_time: str
    pages_count: int
    assets_json: List[Dict[str, Any]]
    dom_hashes_json: Dict[str, str]
    findings_hash: str

class BaselineDiffResponse(BaseModel):
    target_url: str
    base_snapshot_id: str
    current_snapshot_id: str
    base_time: str
    current_time: str
    new_pages: List[str]
    removed_pages: List[str]
    tampered_pages: List[Dict[str, Any]]
    new_findings: List[Dict[str, Any]]
    fixed_findings: List[Dict[str, Any]]
    retained_findings: List[Dict[str, Any]]
    risk_trend: str  # INCREASED, DECREASED, STABLE
