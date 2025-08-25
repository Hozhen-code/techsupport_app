# migrate_once.py
import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")
con = sqlite3.connect(DB_PATH)
cur = con.cursor()

def has_col(table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return col in {r[1] for r in cur.fetchall()}

# sites.db_server 없으면 추가
if not has_col("sites", "db_server"):
    cur.execute("ALTER TABLE sites ADD COLUMN db_server INTEGER")
    print("Added sites.db_server")

# forms.orig_name 없으면 추가
if not has_col("forms", "orig_name"):
    cur.execute("ALTER TABLE forms ADD COLUMN orig_name TEXT")
    print("Added forms.orig_name")

# forms.uploaded_at 없으면 추가(아주 예전 DB 대비)
if not has_col("forms", "uploaded_at"):
    cur.execute("ALTER TABLE forms ADD COLUMN uploaded_at TEXT")
    print("Added forms.uploaded_at")

con.commit()
con.close()
print("Migration done.")
