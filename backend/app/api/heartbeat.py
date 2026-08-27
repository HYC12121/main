"""
心跳检测路由 - 30 秒定时心跳，前端可轮询确认后端存活
"""
import time
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["Heartbeat"])

_start_time = time.time()


@router.get("/heartbeat", summary="后端心跳检测")
async def heartbeat():
    """
    前端每 30 秒轮询一次，确认后端服务存活。
    返回：服务状态 / 版本 / 运行时长
    """
    uptime_seconds = int(time.time() - _start_time)
    h = uptime_seconds // 3600
    m = (uptime_seconds % 3600) // 60
    s = uptime_seconds % 60
    return JSONResponse({
        "status": "ALIVE",
        "uptime": f"{h:02d}:{m:02d}:{s:02d}",
        "uptime_seconds": uptime_seconds,
        "timestamp": int(time.time() * 1000),
    })
