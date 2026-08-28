import pytest
from bs4 import BeautifulSoup
from plugins.scanner_core.tamper_detector import TamperDetector
from plugins.scanner_core.sensitive_inspector import SensitiveInspector

def test_tamper_detector_benign_travel_site():
    """测试真实旅游网站（如携程）包含澳门酒店/地名时，不应误报涉赌暗链"""
    detector = TamperDetector(auth_domains=["ctrip.com", "tripcdn.cn"])
    
    mock_html = """
    <html>
      <body>
        <div class="header">
          <a class="nav-item" href="https://hotels.ctrip.com/hotel/macau59">澳门酒店预订</a>
          <a class="nav-item" href="https://vacations.ctrip.com/tours/d-macau-39">澳门旅游度假攻略</a>
          <a class="assist-voice" assist-speak-text="true" style="display:none" href="/accessibility">无障碍语音导览</a>
        </div>
      </body>
    </html>
    """
    findings = detector.scan_pages([{"url": "https://www.ctrip.com", "html_content": mock_html}])
    assert len(findings) == 0, f"Expected 0 findings on benign travel site, but got: {findings}"

def test_sensitive_inspector_build_timestamp_immunity():
    """测试 Webpack / CDN 静态分块构建时间戳（如 1742000253896）不应误报为银行卡"""
    inspector = SensitiveInspector()
    
    mock_html = """
    <html>
      <head>
        <link rel="stylesheet" href="https://bd-s.tripcdn.cn/NFES/mfe_marketPlayer/1742000253896/marketPlayer.css" crossorigin>
        <script src="https://static.tripcdn.com/packages/chunk-1742000253896.js"></script>
      </head>
      <body>
        <h1>携程旅行网欢迎您</h1>
      </body>
    </html>
    """
    findings = inspector.scan_pages([{"url": "https://www.ctrip.com", "html_content": mock_html}])
    card_findings = [f for f in findings if f.get("category") == "SENSITIVE" and "卡" in f.get("title", "")]
    assert len(card_findings) == 0, f"Expected 0 card findings on CDN build timestamps, but got: {card_findings}"
