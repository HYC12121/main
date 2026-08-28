import pytest
from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler

def test_crawler_authorization_boundary():
    crawler = AssetCrawler(
        base_url="http://city-data.gov.cn",
        auth_domains=["city-data.gov.cn", "sub.city-data.gov.cn"]
    )
    
    # 授权范围内的子域名与主域名
    assert crawler.is_authorized("http://city-data.gov.cn/news/index.html") is True
    assert crawler.is_authorized("https://sub.city-data.gov.cn/api/v1") is True
    
    # 未经授权的第三方外部域名 (防止越界探查)
    assert crawler.is_authorized("https://www.baidu.com") is False
    assert crawler.is_authorized("https://evil-hacker.com/malicious.js") is False
    assert crawler.is_authorized("javascript:void(0)") is False
