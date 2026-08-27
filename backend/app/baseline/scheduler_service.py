import asyncio
import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from typing import Dict, Any, List

from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.scheduler")

class SchedulerService:
    """定时与周期性巡检任务调度服务"""
    
    _scheduler: AsyncIOScheduler = None

    @classmethod
    def start(cls):
        if not cls._scheduler:
            cls._scheduler = AsyncIOScheduler()
            cls._scheduler.start()
            logger.info("AsyncIOScheduler started successfully.")
            cls._load_existing_scheduled_tasks()

    @classmethod
    def shutdown(cls):
        if cls._scheduler and cls._scheduler.running:
            cls._scheduler.shutdown()
            logger.info("AsyncIOScheduler stopped.")

    @classmethod
    def _load_existing_scheduled_tasks(cls):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, cron_expr FROM tasks WHERE cron_expr != '' AND cron_expr IS NOT NULL")
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            cls.add_cron_job(r["id"], r["cron_expr"])

    @classmethod
    def add_cron_job(cls, task_id: str, cron_expr: str):
        if not cls._scheduler:
            cls.start()
        try:
            # 格式：分 时 日 月 星期 (例如: 0 2 * * *)
            parts = cron_expr.strip().split()
            if len(parts) == 5:
                minute, hour, day, month, day_of_week = parts
                trigger = CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
                
                async def run_task_job():
                    from backend.app.agent.orchestrator import InspectionOrchestrator
                    logger.info(f"Triggering scheduled periodic inspection task {task_id}")
                    orchestrator = InspectionOrchestrator(task_id)
                    await orchestrator.run()

                cls._scheduler.add_job(
                    run_task_job,
                    trigger=trigger,
                    id=f"job_{task_id}",
                    replace_existing=True
                )
                logger.info(f"Added periodic cron job for task {task_id} with expr: {cron_expr}")
        except Exception as e:
            logger.error(f"Failed to add cron job for task {task_id}: {e}")

    @classmethod
    def remove_cron_job(cls, task_id: str):
        if cls._scheduler:
            try:
                cls._scheduler.remove_job(f"job_{task_id}")
                logger.info(f"Removed cron job for task {task_id}")
            except Exception:
                pass

    @classmethod
    def get_job_info(cls, task_id: str) -> Dict[str, Any]:
        if not cls._scheduler:
            return {"scheduled": False}
        job = cls._scheduler.get_job(f"job_{task_id}")
        if job:
            next_run = job.next_run_time.isoformat() if job.next_run_time else None
            return {
                "scheduled": True,
                "job_id": job.id,
                "next_run_time": next_run
            }
        return {"scheduled": False}
