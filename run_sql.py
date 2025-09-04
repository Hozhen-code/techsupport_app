# run_sql.py
import sqlite3, pathlib
db = r"C:\techsupport_app\naiz.db"
sql_file = r"C:\techsupport_app\seed.sql"
sql = pathlib.Path(sql_file).read_text(encoding="utf-8")
con = sqlite3.connect(db)
con.executescript("PRAGMA foreign_keys=ON; BEGIN; " + sql + " COMMIT;")
con.close()
print("OK")