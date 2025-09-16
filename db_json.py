import sqlite3, json
con = sqlite3.connect("naiz.db")
cur = con.cursor()
cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name;")
print(json.dumps(cur.fetchall(), ensure_ascii=False, indent=2))
