from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.app.database import get_db_connection
from backend.app.models.baseline import BaselineDiffResponse
from backend.app.baseline.baseline_service import BaselineService

router = APIRouter(prefix="/baselines", tags=["基线对比与安全异动"])

@router.get("/snapshots")
async def list_snapshots(target_url: str = Query(..., description="目标站点 URL")):
    return BaselineService.get_latest_snapshots(target_url)

@router.get("/compare", response_model=BaselineDiffResponse)
async def compare_baselines(
    base_task_id: str = Query(..., description="基准任务 ID (前次巡检)"),
    current_task_id: str = Query(..., description="当前任务 ID (本次巡检)")
):
    diff_result = BaselineService.compare_baselines(base_task_id, current_task_id)
    if "error" in diff_result:
        raise HTTPException(status_code=400, detail=diff_result["error"])
    return diff_result
