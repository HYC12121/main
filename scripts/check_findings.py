import sqlite3, json

conn = sqlite3.connect('data/das_sentinel.db')
conn.row_factory = sqlite3.Row
rows = conn.execute(
    'SELECT title, severity, url, evidence FROM findings WHERE task_id=(SELECT id FROM tasks ORDER BY created_at DESC LIMIT 1) ORDER BY cvss_score DESC'
).fetchall()

print(f"Total findings in latest task: {len(rows)}")
print("=" * 60)
for r in rows[:15]:
    ev = json.loads(r['evidence']) if r['evidence'] else {}
    snippet = str(ev.get('matched_snippet', ''))[:150]
    print(f"[{r['severity']}] {r['title']}")
    print(f"  URL: {r['url']}")
    print(f"  snippet: {snippet}")
    print()
conn.close()
