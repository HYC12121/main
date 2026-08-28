import sys
sys.path.insert(0, '.')
from plugins.scanner_core.sensitive_inspector import SensitiveInspector
import inspect

src = inspect.getsource(SensitiveInspector.scan_pages)
# Check if new filter code is present
check_str = 'prev_ctx = content'
if check_str in src:
    print('NEW code is LOADED (prev_ctx filter present)')
else:
    print('OLD code loaded! Filter not present.')
    
# Also test the actual scanning with a fake page
insp = SensitiveInspector()
fake_page = [{
    "url": "https://www.ninebot.com/test",
    "html_content": """
    <html><body>
    <script>
    var sitemap = [
        {"title": "support@ninebot.com", "url": "", "active": false},
        {"title": "Home", "url": "/", "active": true}
    ];
    </script>
    </body></html>
    """
}]
results = insp.scan_pages(fake_page)
# Test vendor JS author comment
fake_vendor_js = [{
    "url": "https://account.ninebot.com/auth-v5/dist/assets/vendor-other-packages-DWo-fVbp.js",
    "html_content": """
    /**
     * @license
     * Lodash <https://lodash.com/>
     * Copyright JS Foundation and other contributors <https://by.org/>
     * @author Chen, Yi-Cyuan <chenyicyuan@example.org>
     * @copyright Chen, Yi-Cyuan 2014
     */
    function foo() {}
    """
}]
vendor_results = insp.scan_pages(fake_vendor_js)
vendor_email_findings = [r for r in vendor_results if 'email' in r.get('param', '').lower() or 'rule-email' in str(r.get('evidence', {}))]
print(f"Vendor JS author findings: {len(vendor_email_findings)}")
if not vendor_email_findings:
    print("  -> SUCCESS: Vendor JS open source author email was successfully filtered out!")
