@echo off
chcp 65001 >nul
title DAS-SentinelAgent
echo ======================================================================
echo DAS-SentinelAgent
echo ======================================================================
echo.
echo [1/2] Checking Python dependencies...
python -m pip install -r requirements.txt -q

echo.
echo [2/2] Starting DAS-SentinelAgent and Target Lab...
echo Web Dashboard: http://127.0.0.1:8000
echo Target Lab:    http://127.0.0.1:8088
echo.
python run.py
pause
