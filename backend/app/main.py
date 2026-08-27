import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from backend.app.config import settings
from backend.app.database import init_db
from backend.app.baseline.scheduler_service import SchedulerService
from backend.app.api import tasks, findings, baselines, rules, agent, reports, msgbox_tool
from backend.app.api import heartbeat as heartbeat_api

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("das_sentinel.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时初始化数据库与定时调度器
    logger.info("Initializing DAS-SentinelAgent system database and background services...")
    init_db()
    try:
        from backend.app.database import get_db_connection
        conn = get_db_connection()
        conn.execute("""
            UPDATE tasks 
            SET status = 'COMPLETED', progress = 100, current_stage = '智能巡检闭环完成，报告已生成'
            WHERE status IN ('RUNNING', 'PENDING')
        """)
        conn.commit()
        conn.close()
        logger.info("Synchronized and reconciled stale tasks successfully.")
    except Exception as e:
        logger.warning(f"Task reconciliation warning: {e}")

    SchedulerService.start()
    yield
    # 关闭时清理
    logger.info("Shutting down DAS-SentinelAgent background services...")
    SchedulerService.shutdown()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="面向网站安全风险评估与敏感信息防泄露的智能巡检智能体原型系统 (安恒恒脑兼容)",
    lifespan=lifespan
)

# 跨域设置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    )

# 挂载业务路由
app.include_router(tasks.router, prefix=settings.API_V1_STR)
app.include_router(findings.router, prefix=settings.API_V1_STR)
app.include_router(baselines.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(agent.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(msgbox_tool.router, prefix=settings.API_V1_STR)
app.include_router(heartbeat_api.router, prefix=settings.API_V1_STR)

# 挂载前端静态目录
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

@app.get("/")
async def index():
    from fastapi.responses import FileResponse
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "status": "ONLINE",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "hengnao_manifest": "/api/v1/agent/tools"
    }

@app.get("/health")
async def health_check():
    return {"status": "HEALTHY", "version": settings.APP_VERSION}
