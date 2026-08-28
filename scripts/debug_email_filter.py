"""
Debug why the email filter is not working
"""
import re

# Simulate the actual content from the page
# The snippet shows: "title": "su****om" which means original was support@ninebot.com
test_content = '''
},
        {
          "title": "support@ninebot.com",
          "url": "",
          "active": false
        }
'''

email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'

for match in re.finditer(email_pattern, test_content, re.IGNORECASE):
    matched_val = match.group(0)
    print(f"Match: {matched_val!r} at pos {match.start()}-{match.end()}")
    
    # Test the full validation
    if not re.match(r'^[a-zA-Z0-9._%+\-]{2,64}@[a-zA-Z0-9.\-]{2,253}\.[a-zA-Z]{2,10}$', matched_val):
        print("  -> SKIP: failed full format check")
        continue
    
    # Test prev_ctx filter
    prev_ctx = test_content[max(0, match.start()-80):match.start()].lower()
    print(f"  prev_ctx: {prev_ctx!r}")
    
    filter_keys = ['"title":', '"url":', '"label":', '"name":', '"key":', '"route":', '"path":']
    found_key = None
    for k in filter_keys:
        if k in prev_ctx:
            found_key = k
            break
    
    if found_key:
        print(f"  -> SKIP: found '{found_key}' in prev_ctx")
    else:
        print(f"  -> PASS: not filtered, would be reported as finding!")

print("\nDone")
