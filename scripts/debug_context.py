import sys, re
sys.path.insert(0, '.')
from plugins.scanner_core.sensitive_inspector import SensitiveInspector
import inspect

# Test with the exact structure from actual ninebot page
insp = SensitiveInspector()

# The actual HTML structure - in ninebot pages, the sitemap JS might be:
# var routes = JSON.parse('[{"title":"support@ninebot.com"...}]')
# OR it could be embedded differently
# Let's test different embeddings

tests = [
    # Test 1: Direct JSON in script
    '<script>var routes=[{"title":"support@ninebot.com","url":""}]</script>',
    # Test 2: With escaped quotes (JSON.parse of string)
    '<script>var x=\'[{"title":"support@ninebot.com"}]\'</script>',
    # Test 3: Without quotes (JS object)
    '<script>var x=[{title:"support@ninebot.com",url:""}]</script>',
    # Test 4: In HTML attribute
    '<div data-email="support@ninebot.com">text</div>',
]

email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
target = 'support@ninebot.com'

print("Context analysis for different HTML structures:")
print("=" * 60)
for i, html in enumerate(tests, 1):
    m = re.search(re.escape(target), html)
    if m:
        prev_ctx = html[max(0, m.start()-80):m.start()].lower()
        has_title = '"title":' in prev_ctx
        has_title2 = "'title':" in prev_ctx
        has_title3 = "title:" in prev_ctx
        print(f"Test {i}: Found at pos {m.start()}")
        print(f"  prev_ctx: {prev_ctx!r}")
        print(f"  Has '\"title\":': {has_title}")
        print(f"  Has \"'title':\": {has_title2}")
        print(f"  Has 'title:': {has_title3}")
        print()
