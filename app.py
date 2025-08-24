# app.py
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sqlite3, os, shutil
import datetime as dt
from typing import Optional, List

app = FastAPI()

# 정적/템플릿
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_ROOT, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_ROOT), name="uploads")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

DB_PATH = os.path.join(BASE_DIR, "app.db")

# ---------- 공용 유틸 ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def secure_filename(name: str) -> str:
    # 매우 단순한 파일명 정리 (공백/경로 분리자 제거)
    keep = "._-()[]{}@~^+=,"
    return "".join(ch for ch in name if ch.isalnum() or ch in keep)

# 담당자 색상 팔레트(이름 해시 → 12색)
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

# 이벤트 폼용 고정 팔레트 (빨/주/노/초/파/남/보)
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

# ---------- DB 초기화 (샘플 데이터 없음) ----------
def init_db():
    conn = db(); cur = conn.cursor()

    # 일정(events)
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

    # 현장관리보고서(reports)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date    TEXT NOT NULL,  -- YYYY-MM-DD
            site    TEXT NOT NULL,
            detail  TEXT NOT NULL,
            manager TEXT,
            status  TEXT,           -- 진행/완료/보류
            note    TEXT
        )
    """)

    # 보고서 첨부파일 (사진 등)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS report_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            orig_name TEXT NOT NULL,
            content_type TEXT,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)

    # 현장 정보(sites)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            camera_count INTEGER,
            ip TEXT,
            server_location TEXT
        )
    """)

    # 서류 양식(forms)
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

    conn.commit(); conn.close()

init_db()

# 편의 함수: 사이트 목록
def get_sites():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id, name FROM sites ORDER BY name")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

# ----------------------------------------------------
# 라우팅
# ----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return RedirectResponse(url="/calendar")

# ========== 달력 ==========
@app.get("/calendar", response_class=HTMLResponse)
def calendar_page(request: Request):
    managers = get_event_managers()
    statuses = ["진행", "완료", "보류"]
    return templates.TemplateResponse("calendar.html", {
        "request": request,
        "managers": managers,
        "statuses": statuses
    })

def get_event_managers():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT DISTINCT manager FROM events WHERE IFNULL(manager,'')<>'' ORDER BY manager")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

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

# ========== 일정(이벤트) 작성/수정/삭제 ==========
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
        {
            "request": request,
            "mode": "new",
            "data": data,
            "sites": get_sites(),
            "color_palette": color_palette(),
            "default_color": "#2563eb",
        },
    )

@app.post("/events/new")
def events_new_submit(
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
    color: str = Form("#2563eb"),
):
    conn = db(); cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events(title,start,end,manager,site,status,color)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            title.strip(),
            start.strip(),
            (end or "").strip() or None,
            (manager or "").strip() or None,
            (site or "").strip() or None,
            (status or "").strip() or None,
            (color or "#2563eb").strip(),
        ),
    )
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
        {
            "request": request,
            "mode": "edit",
            "data": data,
            "sites": get_sites(),
            "color_palette": color_palette(),
            "default_color": "#2563eb",
        },
    )

@app.post("/events/edit/{eid}")
def events_edit_submit(
    eid: int,
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
    color: str = Form("#2563eb"),
):
    conn = db(); cur = conn.cursor()
    cur.execute(
        """
        UPDATE events
           SET title=?, start=?, end=?, manager=?, site=?, status=?, color=?
         WHERE id=?
        """,
        (
            title.strip(),
            start.strip(),
            (end or "").strip() or None,
            (manager or "").strip() or None,
            (site or "").strip() or None,
            (status or "").strip() or None,
            (color or "#2563eb").strip(),
            eid,
        ),
    )
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

@app.post("/events/delete/{eid}")
def events_delete(eid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE id=?", (eid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

# ========== 현장관리보고서 ==========
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
    data = {
        "date": date or str(dt.date.today()),
        "site": "", "detail": "", "manager": "", "status": "진행", "note": ""
    }
    return templates.TemplateResponse("reports_form.html", {"request": request, "mode": "new", "data": data})

@app.post("/reports/new")
def reports_new_submit(
    date: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(None),
    status: str = Form(None),
    note: str = Form(None),
):
    conn = db(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO reports(date,site,detail,manager,status,note) VALUES (?,?,?,?,?,?)",
        (date, site, detail, manager or "", status or "", note or "")
    )
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
    rid: int,
    date: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(None),
    status: str = Form(None),
    note: str = Form(None),
):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        UPDATE reports SET date=?, site=?, detail=?, manager=?, status=?, note=? WHERE id=?
    """, (date, site, detail, manager or "", status or "", note or "", rid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.post("/reports/delete/{rid}")
def reports_delete(rid: int):
    # 첨부파일 폴더도 같이 제거
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
    rows = cur.fetchall()
    conn.close()

    lines = ["id,date,site,detail,manager,status,note"]
    for r in rows:
        vals = [str(r["id"]), r["date"], r["site"], r["detail"], r["manager"] or "", r["status"] or "", r["note"] or ""]
        vals = [v.replace('"','""') for v in vals]
        lines.append(",".join(f'"{v}"' for v in vals))
    csv_bytes = ("\n".join(lines)).encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":"attachment; filename=reports.csv"})

# ---- 보고서 첨부 파일 업로드/삭제 (이미지 + HEIC 허용) ----
ALLOWED_REPORT_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif"}

@app.post("/reports/{rid}/upload")
async def reports_upload_files(rid: int, files: List[UploadFile] = File(...)):
    target_dir = os.path.join(UPLOAD_ROOT, "reports", str(rid))
    os.makedirs(target_dir, exist_ok=True)

    conn = db(); cur = conn.cursor()
    now = dt.datetime.now().isoformat(timespec="seconds")

    for uf in files:
        ext = os.path.splitext(uf.filename)[1].lower()
        if ext not in ALLOWED_REPORT_EXT:
            continue
        safe_name = secure_filename(uf.filename)
        # 중복 방지
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
def reports_delete_file(rid: int, fid: int):
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

# ========== 현장 정보 CRUD ==========
@app.get("/sites", response_class=HTMLResponse)
def sites_list(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,address,camera_count,ip,server_location FROM sites ORDER BY name")
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse("sites_list.html", {"request": request, "items": items})

@app.get("/sites/new", response_class=HTMLResponse)
def sites_new_page(request: Request):
    data = {"name":"", "address":"", "camera_count":"", "ip":"", "server_location":""}
    return templates.TemplateResponse("sites_form.html", {"request": request, "mode":"new", "data": data})

@app.post("/sites/new")
def sites_new_submit(
    name: str = Form(...),
    address: str = Form(...),
    camera_count: Optional[int] = Form(None),
    ip: Optional[str] = Form(None),
    server_location: Optional[str] = Form(None),
):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO sites(name,address,camera_count,ip,server_location)
        VALUES(?,?,?,?,?)
    """, (name.strip(), address.strip(), camera_count, (ip or "").strip(), (server_location or "").strip()))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

@app.get("/sites/edit/{sid}", response_class=HTMLResponse)
def sites_edit_page(request: Request, sid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,address,camera_count,ip,server_location FROM sites WHERE id=?", (sid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 현장입니다.", status_code=404)
    return templates.TemplateResponse("sites_form.html", {"request": request, "mode":"edit", "data": dict(row)})

@app.post("/sites/edit/{sid}")
def sites_edit_submit(
    sid: int,
    name: str = Form(...),
    address: str = Form(...),
    camera_count: Optional[int] = Form(None),
    ip: Optional[str] = Form(None),
    server_location: Optional[str] = Form(None),
):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        UPDATE sites SET name=?, address=?, camera_count=?, ip=?, server_location=? WHERE id=?
    """, (name.strip(), address.strip(), camera_count, (ip or "").strip(), (server_location or "").strip(), sid))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

@app.post("/sites/delete/{sid}")
def sites_delete(sid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM sites WHERE id=?", (sid,))
    conn.commit(); conn.close()
    return RedirectResponse(url="/sites", status_code=303)

# ========== 서류 양식(forms) ==========
ALLOWED_FORM_EXT = {".csv", ".doc", ".docx", ".hwp", ".pdf"}

@app.get("/forms", response_class=HTMLResponse)
def forms_list(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,name,purpose,orig_name,uploaded_at FROM forms ORDER BY id DESC")
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return templates.TemplateResponse("forms_list.html", {"request": request, "items": items})

@app.get("/forms/new", response_class=HTMLResponse)
def forms_new_page(request: Request):
    data = {"name":"", "purpose":""}
    return templates.TemplateResponse("forms_form.html", {"request": request, "mode":"new", "data": data})

@app.post("/forms/new")
async def forms_new_submit(
    name: str = Form(...),
    purpose: str = Form(None),
    file: UploadFile = File(None),
):
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
    """, (name.strip(), (purpose or "").strip(), rel_path, orig, ctype, dt.datetime.now().isoformat(timespec="seconds")))
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
    fid: int,
    name: str = Form(...),
    purpose: str = Form(None),
    file: UploadFile = File(None),
):
    conn = db(); cur = conn.cursor()
    # 기존 파일 조회
    cur.execute("SELECT file_path FROM forms WHERE id=?", (fid,))
    old = cur.fetchone()
    rel_path = old["file_path"] if old else None
    orig = None; ctype = None

    if file and file.filename:
        ext = os.path.splitext(file.filename)[1].lower()
        if ext in ALLOWED_FORM_EXT:
            # 기존 파일 삭제
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
def forms_delete(fid: int):
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

# 디버그: 라우트 리스트
@app.get("/_routes")
def show_routes():
    return [{"path": r.path, "methods": sorted(r.methods - {'HEAD', 'OPTIONS'})} for r in app.router.routes]
