"""
Trace exactly what happens during scan with the specific HTML structure
"""
import sys, re
sys.path.insert(0, '.')
from plugins.scanner_core.sensitive_inspector import SensitiveInspector

insp = SensitiveInspector()

# Minimal test to trace the exact matching
test_html = '<script>var x=[{title:"support@ninebot.com",url:""}]</script>'

# Find all email pattern matches
email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
for m in re.finditer(email_pattern, test_html, re.IGNORECASE):
    print(f"Matched: {m.group(0)!r} at pos {m.start()}")
    prev_ctx = test_html[max(0, m.start()-100):m.start()].lower()
    print(f"prev_ctx: {prev_ctx!r}")
    
    # Check all filter keys
    filter_keys = [
        '"title":', "'title':", 'title:',
        '"url":', "'url':", 'url:',
        '"label":', '"name":', "'name':", 'name:',
        '"key":', '"route":', '"path":',
        '"link":', '"href":',
        'data-email=', 'placeholder=', 'value=',
        'var ', 'const ', 'let ',
    ]
    for k in filter_keys:
        if k in prev_ctx:
            print(f"  -> Would be filtered by: {k!r}")
            break
    else:
        print("  -> NOT FILTERED! Would be reported as finding.")

print()
# Now run the actual scan
fake_page = [{"url": "https://www.ninebot.com/test", "html_content": test_html}]
results = insp.scan_pages(fake_page)
print(f"Results: {len(results)}")
for r in results:
    print(f"  [{r['severity']}] {r['title']}: {r.get('evidence', {}).get('matched_value_masked')}")
