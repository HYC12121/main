import sqlite3, json

conn = sqlite3.connect('data/das_sentinel.db')
rows = conn.execute('SELECT id, name, category, pattern FROM sensitive_rules WHERE enabled=1').fetchall()
print("== All enabled sensitive rules ==")
for r in rows:
    print(f"  [{r[0]}] {r[1]} (cat={r[2]}) pattern={r[3][:80]}")
print()

# Check what the email rule actually matched
# Find the matched value in evidence
task_id = conn.execute('SELECT id FROM tasks ORDER BY created_at DESC LIMIT 1').fetchone()[0]
findings = conn.execute(
    'SELECT title, evidence FROM findings WHERE task_id=? AND title LIKE "%地址%"',
    (task_id,)
).fetchall()
print(f"== Address findings (task {task_id}): {len(findings)} ==")
for f in findings[:3]:
    ev = json.loads(f[1]) if f[1] else {}
    print(f"  title: {f[0]}")
    print(f"  rule_id: {ev.get('rule_id')}")
    print(f"  masked: {ev.get('matched_value_masked')}")
    snippet = ev.get('matched_snippet', '')
    print(f"  snippet raw: {repr(snippet[:300])}")
    print()
conn.close()
