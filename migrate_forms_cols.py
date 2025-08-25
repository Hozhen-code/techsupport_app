# migrate_forms_cols.py
import sqlite3

DB = "app.db"
conn = sqlite3.connect(DB)
cur = conn.cursor()

# 현재 forms 테이블의 컬럼 목록
cols = {r[1] for r in cur.execute("PRAGMA table_info(forms)")}

def add(coldef: str):
    name = coldef.split()[0]
    if name not in cols:
        print(f"adding column: {name}")
        cur.execute(f"ALTER TABLE forms ADD COLUMN {coldef}")

# 앱 코드가 기대하는 컬럼들 추가
add("stored_name TEXT")
add("orig_name TEXT")
add("mime TEXT")
add("size INTEGER DEFAULT 0")

conn.commit()
conn.close()
print("done.")
