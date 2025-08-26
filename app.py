# app.py
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route as StarletteRoute
import sqlite3, os, shutil, hashlib, secrets
import datetime as dt
from typing import Optional, List

app = FastAPI()

# ===== Paths =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "app.db")

os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_ROOT), name="uploads")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

APP_LOGO_DEFAULT = "img/logo.png"

def logo_src(request: Request) -> str:
    val = os.getenv("APP_LOGO", APP_LOGO_DEFAULT).strip()
    if val.startswith("http://") or val.startswith("https://") or val.startswith("//"):
        return val                         # 절대 URL
    if val.startswith("/"):
        return val                         # /static/... 처럼 이미 절대 경로
    # 그 외에는 static 하위 상대경로로 간주
    return request.url_for("static", path=val)

# Jinja2 전역 함수로 등록 → 템플릿에서 {{ logo_src(request) }} 로 사용
templates.env.globals["logo_src"] = logo_src

class AuthGuard(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path

        # 화이트리스트: 로그인/정적/문서/진단 + .well-known
        open_exact = {"/login", "/logout", "/favicon.ico", "/_whoami", "/_routes"}
        open_prefix = ("/static", "/uploads", "/docs", "/redoc", "/openapi.json", "/.well-known")
        if path in open_exact or any(path.startswith(p) for p in open_prefix):
            return await call_next(request)

        # ★ 여기서 request.session 을 직접 쓰지 말고 scope에서 안전하게 읽음
        sess = request.scope.get("session") or {}
        if sess.get("uid"):
            return await call_next(request)

        return RedirectResponse("/login", status_code=303)

# ⬇️ 미들웨어 추가 순서 중요
#   Starlette 는 "마지막에 add_middleware 한 것"이 가장 먼저 실행됩니다(가장 바깥).
#   세션이 먼저 실행되어야 하므로 SessionMiddleware 를 **마지막에** 추가합니다.
app.add_middleware(AuthGuard)

app.add_middleware(
    SessionMiddleware,
    secret_key="change-this-to-a-long-random-secret",
    session_cookie="session",   # 쿠키명 고정
    https_only=False,
    same_site="lax",
    max_age=60 * 60 * 8,        # 8시간
)

# ===== Utilities =====
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def secure_filename(name: str) -> str:
    keep = "._-()[]{}@~^+=,"
    return "".join(ch for ch in name if ch.isalnum() or ch in keep)

COLORS = [
    "#2563eb", "#16a34a", "#f59e0b", "#dc2626", "#7c3aed", "#06b6d4",
    "#10b981", "#f43f5e", "#a855f7", "#0ea5e9", "#84cc16", "#ef4444"
]
def color_for_manager(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    h = 0
    for ch in name:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return COLORS[h % len(COLORS)]

def color_palette():
    return [
        {"name": "빨", "hex": "#ef4444"},
        {"name": "주", "hex": "#f59e0b"},
        {"name": "노", "hex": "#facc15"},
        {"name": "초", "hex": "#16a34a"},
        {"name": "파", "hex": "#2563eb"},
        {"name": "남", "hex": "#1e40af"},
        {"name": "보", "hex": "#7c3aed"},
    ]

# ===== DB init & migrations =====
def init_db():
    conn = db()
    cur = conn.cursor()

    def has_col(table: str, col: str) -> bool:
        cur.execute(f"PRAGMA table_info({table})")
        return any(r[1] == col for r in cur.fetchall())

    # events
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title   TEXT NOT NULL,
            start   TEXT NOT NULL,
            end     TEXT,
            manager TEXT,
            site    TEXT,
            status  TEXT,
            color   TEXT
        )
    """)

    # reports
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date    TEXT NOT NULL,
            site    TEXT NOT NULL,
            detail  TEXT NOT NULL,
            manager TEXT,
            status  TEXT,
            note    TEXT
        )
    """)

    # report_files
    cur.execute("""
        CREATE TABLE IF NOT EXISTS report_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   INTEGER NOT NULL,
            file_path   TEXT NOT NULL,
            orig_name   TEXT NOT NULL,
            content_type TEXT,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)

    # sites
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            camera_count INTEGER,
            db_server INTEGER,
            ip TEXT,
            server_location TEXT
        )
    """)
    if not has_col("sites", "db_server"):
        cur.execute("ALTER TABLE sites ADD COLUMN db_server INTEGER")

    # forms
    cur.execute("""
        CREATE TABLE IF NOT EXISTS forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            purpose TEXT,
            file_path TEXT,
            orig_name TEXT,
            content_type TEXT,
            uploaded_at TEXT
        )
    """)
    if not has_col("forms", "orig_name"):
        cur.execute("ALTER TABLE forms ADD COLUMN orig_name TEXT")
    if not has_col("forms", "content_type"):
        cur.execute("ALTER TABLE forms ADD COLUMN content_type TEXT")
    if not has_col("forms", "uploaded_at"):
        cur.execute("ALTER TABLE forms ADD COLUMN uploaded_at TEXT")

    # users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    if not has_col("users", "password_hash"):
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if not has_col("users", "salt"):
        cur.execute("ALTER TABLE users ADD COLUMN salt TEXT")
    if not has_col("users", "role"):
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT")
    if not has_col("users", "created_at"):
        cur.execute("ALTER TABLE users ADD COLUMN created_at TEXT")

    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
    conn.commit()

    # seed admin if empty
    cur.execute("SELECT COUNT(*) FROM users")
    if (cur.fetchone()[0] or 0) == 0:
        salt = secrets.token_hex(8)
        pwd = "admin123!"
        pw_hash = hashlib.sha256((salt + pwd).encode()).hexdigest()
        cur.execute(
            "INSERT INTO users(username, password_hash, salt, role) VALUES (?,?,?,?)",
            ("admin", pw_hash, salt, "A"),
        )
        conn.commit()

    conn.close()

init_db()

# ===== helpers =====
def get_sites():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, name FROM sites ORDER BY name")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_event_managers():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT DISTINCT manager FROM events WHERE IFNULL(manager,'')<>'' ORDER BY manager")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

def current_user(request: Request):
    s = request.scope.get("session") or {}
    uid = s.get("uid")
    uname = s.get("username")  # 로그인 시 넣은 키와 일치
    role = s.get("role")
    return {"id": uid, "username": uname, "role": role} if uid else None

def require_roles(request: Request, allowed: List[str]) -> Optional[Response]:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] not in allowed:
        return HTMLResponse("권한이 없습니다.", status_code=403)
    return None

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.get("/_whoami")
def whoami(request: Request):
    s = dict(request.session)
    # 민감한 값만 추려서 보여주자
    return JSONResponse({
        "uid": s.get("uid"),
        "username": s.get("username"),
        "role": s.get("role"),
        "raw_keys": list(s.keys())
    })

@app.get("/_routes")
def show_routes():
    out = []
    for r in app.router.routes:
        if isinstance(r, StarletteRoute):
            methods = sorted((r.methods or set()) - {'HEAD', 'OPTIONS'})
            out.append({"path": r.path, "methods": methods})
    return JSONResponse(out)

# ===== Auth pages =====
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, msg: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg or ""})

@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    conn = db(); cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash, salt, role FROM users WHERE username=?",
        (username.strip(),)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return RedirectResponse("/login?msg=아이디나 비밀번호가 올바르지 않습니다.", status_code=303)

    digest = hashlib.sha256((row["salt"] + password).encode()).hexdigest()
    if digest != row["password_hash"]:
        return RedirectResponse("/login?msg=아이디나 비밀번호가 올바르지 않습니다.", status_code=303)

    request.session.clear()
    request.session["uid"] = row["id"]
    request.session["username"] = row["username"]
    request.session["role"] = row["role"]
    return RedirectResponse("/calendar", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

# ===== Home =====
@app.get("/", response_class=HTMLResponse)
def home():
    return RedirectResponse(url="/calendar")

# ===== Calendar =====
@app.get("/calendar", response_class=HTMLResponse)
def calendar_page(request: Request):
    managers = get_event_managers()
    statuses = ["진행", "완료", "보류"]
    return templates.TemplateResponse("calendar.html", {
        "request": request,
        "managers": managers,
        "statuses": statuses
    })

@app.get("/api/events")
def api_events(
    start: Optional[str] = None,
    end: Optional[str] = None,
    manager: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    site: Optional[str] = None
):
    conn = db(); cur = conn.cursor()
    where, args = [], []

    if start and end:
        where.append("(date(start) < date(?) AND (end IS NULL OR date(end) >= date(?)))")
        args += [end, start]
    if manager:
        where.append("manager=?"); args.append(manager)
    if status:
        where.append("status=?"); args.append(status)
    if site:
        where.append("site LIKE ?"); args.append(f"%{site}%")
    if q:
        where.append("(title LIKE ? OR site LIKE ?)"); args += [f"%{q}%", f"%{q}%"]

    sql = "SELECT id,title,start,end,manager,site,status,color FROM events"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY date(start)"
    cur.execute(sql, args)
    rows = cur.fetchall()
    conn.close()

    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "title": r["title"],
            "start": r["start"],
            "end": r["end"],
            "color": r["color"] or color_for_manager(r["manager"]),
            "extendedProps": {
                "manager": r["manager"],
                "site": r["site"],
                "status": r["status"],
            }
        })
    return JSONResponse(events)

# ===== Event CRUD =====
@app.get("/events/new", response_class=HTMLResponse)
def events_new_page(request: Request, date: Optional[str] = None):
    today = dt.date.today()
    data = {
        "title": "",
        "start": date or str(today),
        "end": "",
        "manager": "",
        "site": "",
        "status": "진행",
        "color": "#2563eb",
    }
    return templates.TemplateResponse(
        "events_form.html",
        {"request": request, "mode": "new", "data": data,
         "sites": get_sites(), "color_palette": color_palette(),
         "default_color": "#2563eb"}
    )

@app.post("/events/new")
def events_new_submit(
    request: Request,
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
    color: str = Form("#2563eb"),
):
    deny = require_roles(request, ["A", "B"])
    if deny: return deny

    conn = db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO events(title,start,end,manager,site,status,color)
        VALUES (?,?,?,?,?,?,?)
    """, (title.strip(), start.strip(),
          (end or "").strip() or None,
          (manager or "").strip() or None,
          (site or "").strip() or None,
          (status or "").strip() or None,
          (color or "#2563eb").strip()))
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

@app.get("/events/edit/{eid}", response_class=HTMLResponse)
def events_edit_page(request: Request, eid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,title,start,end,manager,site,status,color FROM events WHERE id=?", (eid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 일정입니다.", status_code=404)
    data = dict(row)
    if not data.get("color"):
        data["color"] = "#2563eb"
    return templates.TemplateResponse(
        "events_form.html",
        {"request": request, "mode": "edit", "data": data,
         "sites": get_sites(), "color_palette": color_palette(),
         "default_color": "#2563eb"}
    )

@app.post("/events/edit/{eid}")
def events_edit_submit(
    request: Request,
    eid: int,
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
    color: str = Form("#2563eb"),
):
    deny = require_roles(request, ["A"])
    if deny: return deny

    conn = db(); cur = conn.cursor()
    cur.execute("""
        UPDATE events
           SET title=?, start=?, end=?, manager=?, site=?, status=?, color=?
         WHERE id=?
    """, (title.strip(), start.strip(),
          (end or "").strip() or None,
          (manager or "").strip() or None,
          (site or "").strip() or None,
          (status or "").strip() or None,
          (color or "#2563eb").strip(),
          eid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

@app.post("/events/delete/{eid}")
def events_delete(request: Request, eid: int):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE id=?", (eid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

# ===== Reports =====
def get_report_managers():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT DISTINCT manager FROM reports WHERE IFNULL(manager,'')<>'' ORDER BY manager")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

@app.get("/reports", response_class=HTMLResponse)
def reports_list(
    request: Request,
    fdate: Optional[str] = None,
    tdate: Optional[str] = None,
    manager: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
):
    conn = db(); cur = conn.cursor()
    where, args = [], []
    if fdate: where.append("date(date) >= date(?)"); args.append(fdate)
    if tdate: where.append("date(date) <= date(?)"); args.append(tdate)
    if manager: where.append("manager = ?"); args.append(manager)
    if status: where.append("status = ?"); args.append(status)
    if q:
        where.append("(site LIKE ? OR detail LIKE ? OR IFNULL(note,'') LIKE ?)")
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]
    sql = "SELECT id,date,site,detail,manager,status,note FROM reports"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY date(date) DESC, id DESC"
    cur.execute(sql, args)
    items = [dict(r) for r in cur.fetchall()]
    conn.close()

    return templates.TemplateResponse("reports_list.html", {
        "request": request,
        "items": items,
        "fdate": fdate or "",
        "tdate": tdate or "",
        "manager": manager or "",
        "status": status or "",
        "q": q or "",
        "managers": get_report_managers(),
    })

@app.get("/reports/new", response_class=HTMLResponse)
def reports_new_page(request: Request, date: Optional[str] = None):
    data = {"date": date or str(dt.date.today()),
            "site": "", "detail": "", "manager": "", "status": "진행", "note": ""}
    return templates.TemplateResponse("reports_form.html", {"request": request, "mode": "new", "data": data})

@app.post("/reports/new")
def reports_new_submit(
    request: Request,
    date: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(None),
    status: str = Form(None),
    note: str = Form(None),
):
    deny = require_roles(request, ["A", "B"])
    if deny: return deny

    conn = db(); cur = conn.cursor()
    cur.execute("INSERT INTO reports(date,site,detail,manager,status,note) VALUES (?,?,?,?,?,?)",
                (date, site, detail, manager or "", status or "", note or ""))
    conn.commit(); conn.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.get("/reports/edit/{rid}", response_class=HTMLResponse)
def reports_edit_page(request: Request, rid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,date,site,detail,manager,status,note FROM reports WHERE id=?", (rid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 보고서입니다.", status_code=404)
    return templates.TemplateResponse("reports_form.html", {"request": request, "mode": "edit", "data": dict(row)})

@app.post("/reports/edit/{rid}")
def reports_edit_submit(
    request: Request,
    rid: int,
    date: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(None),
    status: str = Form(None),
    note: str = Form(None),
):
    deny = require_roles(request, ["A"])
    if deny: return deny

    conn = db(); cur = conn.cursor()
    cur.execute("""
        UPDATE reports SET date=?, site=?, detail=?, manager=?, status=?, note=? WHERE id=?
    """, (date, site, detail, manager or "", status or "", note or "", rid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.post("/reports/delete/{rid}")
def reports_delete(request: Request, rid: int):
    deny = require_roles(request, ["A"])
    if deny: return deny

    folder = os.path.join(UPLOAD_ROOT, "reports", str(rid))
    if os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM report_files WHERE report_id=?", (rid,))
    cur.execute("DELETE FROM reports WHERE id=?", (rid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.get("/reports/export")
def reports_export_csv(
    fdate: Optional[str] = None,
    tdate: Optional[str] = None,
    manager: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
):
    conn = db(); cur = conn.cursor()
    where, args = [], []
    if fdate: where.append("date(date) >= date(?)"); args.append(fdate)
    if tdate: where.append("date(date) <= date(?)"); args.append(tdate)
    if manager: where.append("manager = ?"); args.append(manager)
    if status: where.append("status = ?"); args.append(status)
    if q:
        where.append("(site LIKE ? OR detail LIKE ? OR IFNULL(note,'') LIKE ?)")
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]

    sql = "SELECT id,date,site,detail,manager,status,note FROM reports"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY date(date) DESC, id DESC"

    cur.execute(sql, args)
    rows = cur.fetchall(); conn.close()

    lines = ["id,date,site,detail,manager,status,note"]
    for r in rows:
        vals = [str(r["id"]), r["date"], r["site"], r["detail"], r["manager"] or "", r["status"] or "", r["note"] or ""]
        vals = [v.replace('"','""') for v in vals]
        lines.append(",".join(f'"{v}"' for v in vals))
    csv_bytes = ("\n".join(lines)).encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":"attachment; filename=reports.csv"})

# file uploads
ALLOWED_REPORT_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif"}

@app.post("/reports/{rid}/upload")
async def reports_upload_files(request: Request, rid: int, files: List[UploadFile] = File(...)):
    deny = require_roles(request, ["A", "B"])
    if deny: return deny
    target_dir = os.path.join(UPLOAD_ROOT, "reports", str(rid))
    os.makedirs(target_dir, exist_ok=True)

    conn = db(); cur = conn.cursor()
    now = dt.datetime.now().isoformat(timespec="seconds")

    for uf in files:
        ext = os.path.splitext(uf.filename)[1].lower()
        if ext not in ALLOWED_REPORT_EXT:
            continue
        safe_name = secure_filename(uf.filename)
        final_name = f"{dt.datetime.now().strftime('%Y%m%d%H%M%S%f')}_{safe_name}"
        disk_path = os.path.join(target_dir, final_name)
        with open(disk_path, "wb") as out:
            out.write(await uf.read())
        rel_path = os.path.relpath(disk_path, UPLOAD_ROOT).replace("\\", "/")
        cur.execute("""
            INSERT INTO report_files(report_id, file_path, orig_name, content_type, uploaded_at)
            VALUES(?,?,?,?,?)
        """, (rid, rel_path, uf.filename, uf.content_type or "", now))

    conn.commit(); conn.close()
    return RedirectResponse(url=f"/reports/edit/{rid}", status_code=303)

@app.post("/reports/{rid}/file/{fid}/delete")
def reports_delete_file(request: Request, rid: int, fid: int):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT file_path FROM report_files WHERE id=? AND report_id=?", (fid, rid))
    row = cur.fetchone()
    if row:
        abs_path = os.path.join(UPLOAD_ROOT, row["file_path"])
        if os.path.isfile(abs_path):
            os.remove(abs_path)
        cur.execute("DELETE FROM report_files WHERE id=?", (fid,))
        conn.commit()
    conn.close()
    return RedirectResponse(url=f"/reports/edit/{rid}", status_code=303)

# ===== Sites =====
@app.get("/sites", response_class=HTMLResponse)
def sites_list(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,address,camera_count,db_server,ip,server_location FROM sites ORDER BY name")
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse("sites_list.html", {"request": request, "items": items})

@app.get("/sites/new", response_class=HTMLResponse)
def sites_new_page(request: Request):
    data = {"name":"", "address":"", "camera_count":"", "db_server":"", "ip":"", "server_location":""}
    return templates.TemplateResponse("sites_form.html", {"request": request, "mode":"new", "data": data})

@app.post("/sites/new")
def sites_new_submit(
    request: Request,
    name: str = Form(...),
    address: str = Form(...),
    camera_count: Optional[int] = Form(None),
    db_server: Optional[int] = Form(None),
    ip: Optional[str] = Form(None),
    server_location: Optional[str] = Form(None),
):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO sites(name, address, camera_count, db_server, ip, server_location)
        VALUES(?,?,?,?,?,?)
    """, (name.strip(), address.strip(), camera_count, db_server,
          (ip or "").strip(), (server_location or "").strip()))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

@app.get("/sites/edit/{sid}", response_class=HTMLResponse)
def sites_edit_page(request: Request, sid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,address,camera_count,db_server,ip,server_location FROM sites WHERE id=?", (sid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 현장입니다.", status_code=404)
    return templates.TemplateResponse("sites_form.html", {"request": request, "mode":"edit", "data": dict(row)})

@app.post("/sites/edit/{sid}")
def sites_edit_submit(
    request: Request,
    sid: int,
    name: str = Form(...),
    address: str = Form(...),
    camera_count: Optional[int] = Form(None),
    db_server: Optional[int] = Form(None),
    ip: Optional[str] = Form(None),
    server_location: Optional[str] = Form(None),
):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("""
        UPDATE sites
           SET name=?, address=?, camera_count=?, db_server=?, ip=?, server_location=?
         WHERE id=?
    """, (name.strip(), address.strip(), camera_count, db_server,
          (ip or "").strip(), (server_location or "").strip(), sid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

@app.post("/sites/delete/{sid}")
def sites_delete(request: Request, sid: int):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM sites WHERE id=?", (sid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

# ===== Forms =====
ALLOWED_FORM_EXT = {".csv", ".doc", ".docx", ".hwp", ".pdf"}

@app.get("/forms", response_class=HTMLResponse)
def forms_list(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,purpose,IFNULL(orig_name,'') AS orig_name,uploaded_at FROM forms ORDER BY id DESC")
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse("forms_list.html", {"request": request, "items": items})

@app.get("/forms/new", response_class=HTMLResponse)
def forms_new_page(request: Request):
    data = {"name":"", "purpose":""}
    return templates.TemplateResponse("forms_form.html", {"request": request, "mode":"new", "data": data})

@app.post("/forms/new")
async def forms_new_submit(
    request: Request,
    name: str = Form(...),
    purpose: str = Form(None),
    file: UploadFile = File(None),
):
    deny = require_roles(request, ["A"])
    if deny: return deny

    rel_path = None; orig = None; ctype = None
    if file and file.filename:
        ext = os.path.splitext(file.filename)[1].lower()
        if ext in ALLOWED_FORM_EXT:
            folder = os.path.join(UPLOAD_ROOT, "forms")
            os.makedirs(folder, exist_ok=True)
            safe = secure_filename(file.filename)
            final = f"{dt.datetime.now().strftime('%Y%m%d%H%M%S%f')}_{safe}"
            disk = os.path.join(folder, final)
            with open(disk, "wb") as out:
                out.write(await file.read())
            rel_path = os.path.relpath(disk, UPLOAD_ROOT).replace("\\","/")
            orig = file.filename
            ctype = file.content_type or ""

    conn = db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO forms(name,purpose,file_path,orig_name,content_type,uploaded_at)
        VALUES(?,?,?,?,?,?)
    """, (name.strip(), (purpose or "").strip(), rel_path, orig, ctype,
          dt.datetime.now().isoformat(timespec="seconds")))
    conn.commit(); conn.close()
    return RedirectResponse(url="/forms", status_code=303)

@app.get("/forms/edit/{fid}", response_class=HTMLResponse)
def forms_edit_page(request: Request, fid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,purpose,file_path,orig_name FROM forms WHERE id=?", (fid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 서류입니다.", status_code=404)
    return templates.TemplateResponse("forms_form.html", {"request": request, "mode":"edit", "data": dict(row)})

@app.post("/forms/edit/{fid}")
async def forms_edit_submit(
    request: Request,
    fid: int,
    name: str = Form(...),
    purpose: str = Form(None),
    file: UploadFile = File(None),
):
    deny = require_roles(request, ["A"])
    if deny: return deny

    conn = db(); cur = conn.cursor()
    cur.execute("SELECT file_path FROM forms WHERE id=?", (fid,))
    old = cur.fetchone()
    rel_path = old["file_path"] if old else None
    orig = None; ctype = None

    if file and file.filename:
        ext = os.path.splitext(file.filename)[1].lower()
        if ext in ALLOWED_FORM_EXT:
            if rel_path:
                old_abs = os.path.join(UPLOAD_ROOT, rel_path)
                if os.path.isfile(old_abs):
                    os.remove(old_abs)
            folder = os.path.join(UPLOAD_ROOT, "forms")
            os.makedirs(folder, exist_ok=True)
            safe = secure_filename(file.filename)
            final = f"{dt.datetime.now().strftime('%Y%m%d%H%M%S%f')}_{safe}"
            disk = os.path.join(folder, final)
            with open(disk, "wb") as out:
                out.write(await file.read())
            rel_path = os.path.relpath(disk, UPLOAD_ROOT).replace("\\","/")
            orig = file.filename
            ctype = file.content_type or ""

    cur.execute("""
        UPDATE forms SET name=?, purpose=?, file_path=?, orig_name=?, content_type=?, uploaded_at=?
        WHERE id=?
    """, (name.strip(), (purpose or "").strip(), rel_path, orig, ctype,
          dt.datetime.now().isoformat(timespec="seconds"), fid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/forms", status_code=303)

@app.post("/forms/delete/{fid}")
def forms_delete(request: Request, fid: int):
    deny = require_roles(request, ["A"])
    if deny: return deny
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT file_path FROM forms WHERE id=?", (fid,))
    row = cur.fetchone()
    if row and row["file_path"]:
        abs_path = os.path.join(UPLOAD_ROOT, row["file_path"])
        if os.path.isfile(abs_path):
            os.remove(abs_path)
    cur.execute("DELETE FROM forms WHERE id=?", (fid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/forms", status_code=303)
