"""
Trace inside scan_pages to find why filter is not working
"""
import sys, re
sys.path.insert(0, '.')
from backend.app.database import get_db_connection

# Check what category the email rule has
conn = get_db_connection()
row = conn.execute('SELECT id, name, category, pattern FROM sensitive_rules WHERE id="rule-email"').fetchone()
if row:
    print(f"Email rule: id={row[0]}, name={row[1]}, category={row[2]}")
    print(f"  pattern: {row[3]!r}")
    print()
    
    # Check: does "email" appear in rule['name'].lower()?
    name_lower = row[1].lower()
    print(f"  name.lower() = {name_lower!r}")
    print(f"  'email' in name.lower() = {'email' in name_lower}")
else:
    print("Rule not found!")

conn.close()
