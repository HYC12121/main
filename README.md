# DAS-SentinelAgent 🛡️
### 自动化 Web 漏洞智能巡检与企业级系统架构拓扑推演平台

DAS-SentinelAgent 是一款集成了**全自动化 Web 资产爬取、漏洞主动探测研判、企业级 21 节点架构拓扑动态推演与可视化溯源**的安全巡检平台。

---

## ✨ 核心特性

- 🔍 **智能漏洞巡检**：全自动探测 SQL 注入、敏感文件泄露（.env/.git）、XSS 跨站脚本、未授权访问等漏洞。
- 🏛️ **21 节点企业拓扑动态推演**：根据探测结果，动态标红漏洞源头组件与受波及链路，提供深度架构卡片与加固指南。
- 📊 **Burp Scanner 交互视图**：提供 Site Map 资产树过滤、HTTP 请求/响应报文深度解析与漏洞利用链分析。
- 📑 **合规与报告导出**：一键生成符合等保 2.0 及 SRC 标准的安全巡检与整改报告。

---

## 🚀 本地极速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务 (控制台 + 内置靶场)
python run.py
```
- 控制台前端地址: `http://127.0.0.1:8000`
- 内置测试靶场地址: `http://127.0.0.1:8088`

---

## 🌐 免费公网一键部署指南

### 推荐方案：Render (100% 永久免费)
1. 将本项目代码推送到您的 **GitHub** 仓库。
2. 登录 [Render.com](https://render.com)（支持使用 GitHub 账号一键登录）。
3. 点击 **New +** ➔ 选择 **Web Service** ➔ 选择刚导入的 GitHub 仓库。
4. 配置信息填写：
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
5. 点击 **Create Web Service**，等待 1-2 分钟即可获得公网可访问的专属免费 HTTPS 域名（例如 `https://das-sentinel.onrender.com`）！
