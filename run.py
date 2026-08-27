import asyncio
import multiprocessing
import threading
import time
import sys
import os

if sys.platform == "win32":
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn
from backend.app.config import settings

def run_target_lab():
    from target_lab.lab_server import lab_app
    print(f"[Target Lab] 正在启动政企模拟测试靶场: http://127.0.0.1:{settings.LAB_PORT}")
    uvicorn.run(lab_app, host="127.0.0.1", port=settings.LAB_PORT, log_level="warning")

def run_main_server():
    from backend.app.main import app
    print(f"[DAS-SentinelAgent] 正在启动智能巡检主系统与控制台: http://127.0.0.1:{settings.SERVER_PORT}")
    print(f"[API Docs] 交互式 Swagger 文档: http://127.0.0.1:{settings.SERVER_PORT}/docs")
    print(f"[HengNao Manifest] 恒脑平台工具定义: http://127.0.0.1:{settings.SERVER_PORT}/api/v1/agent/tools")
    uvicorn.run(app, host="127.0.0.1", port=settings.SERVER_PORT, log_level="info")

if __name__ == "__main__":
    print("=" * 70)
    print("DAS-SentinelAgent (安恒星巡 - 网站安全智能巡检系统)")
    print("=" * 70)
    
    # 启动后台靶场线程
    lab_thread = threading.Thread(target=run_target_lab, daemon=True)
    lab_thread.start()
    
    time.sleep(1)
    
    # 启动主服务
    run_main_server()
