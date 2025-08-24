from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sqlite3
import datetime as dt
from typing import Optional

app = FastAPI()

# 정적/템플릿
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DB_PATH = "app.db"

# ---------- 공용 유틸 ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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

def init_db():
    conn = db()
    cur = conn.cursor()

    # 일정 테이블
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

    # 보고서 테이블
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date    TEXT NOT NULL,      -- YYYY-MM-DD
            site    TEXT NOT NULL,
            detail  TEXT NOT NULL,
            manager TEXT,
            status  TEXT,               -- 진행/완료/보류
            note    TEXT
        )
    """)

    # 샘플 데이터 (최초 1회)
    cur.execute("SELECT COUNT(*) FROM events")
    if cur.fetchone()[0] == 0:
        today = dt.date.today()
        sample_events = [
            ("네트워크 점검 - A현장", str(today), None, "김담당", "A현장", "진행", color_for_manager("김담당")),
            ("장비 교체 - B현장", str(today.replace(day=1)), str(today.replace(day=1)), "이담당", "B현장", "완료", color_for_manager("이담당")),
            ("고객 CS - C현장", str(today + dt.timedelta(days=3)), None, "박담당", "C현장", "진행", color_for_manager("박담당")),
        ]
        cur.executemany(
            "INSERT INTO events(title,start,end,manager,site,status,color) VALUES (?,?,?,?,?,?,?)",
            sample_events
        )

    cur.execute("SELECT COUNT(*) FROM reports")
    if cur.fetchone()[0] == 0:
        sample_reports = [
            (str(dt.date.today()), "A현장", "스위치 포트 불량 확인 및 교체.", "김담당", "진행", "추가 자재 요청"),
            (str(dt.date.today() - dt.timedelta(days=1)), "B현장", "AP 펌웨어 업데이트 완료.", "이담당", "완료", ""),
            (str(dt.date.today() + dt.timedelta(days=2)), "C현장", "고객 민원 대응: 무선 끊김 현상 진단 예정.", "박담당", "보류", "방문 일정 조율"),
        ]
        cur.executemany(
            "INSERT INTO reports(date,site,detail,manager,status,note) VALUES (?,?,?,?,?,?)",
            sample_reports
        )

    conn.commit()
    conn.close()

def get_report_managers():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT manager FROM reports WHERE IFNULL(manager,'')<>'' ORDER BY manager")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

def get_event_managers():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT manager FROM events WHERE IFNULL(manager,'')<>'' ORDER BY manager")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

init_db()

# ---------- 라우팅 ----------
@app.get("/", response_class=HTMLResponse)
def home():
    return RedirectResponse(url="/calendar")

# ========== 달력 ==========
@app.get("/calendar", response_class=HTMLResponse)
def calendar_page(request: Request):
    managers = get_event_managers()
    statuses = ["진행", "완료", "보류"]
    return templates.TemplateResponse("calendar.html", {"request": request, "managers": managers, "statuses": statuses})

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

# ========== 현장관리보고서 ==========
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
    conn = db(); cur = conn.cursor()
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
    return Response(
        content=csv_bytes,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":"attachment; filename=reports.csv"}
    )

# ========== 일정(이벤트) 작성/수정 ==========
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
    }
    return templates.TemplateResponse("events_form.html", {"request": request, "mode": "new", "data": data})

@app.post("/events/new")
def events_new_submit(
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
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
            color_for_manager(manager),
        ),
    )
    conn.commit(); conn.close()
    return RedirectResponse(url="/calendar", status_code=303)

@app.get("/events/edit/{eid}", response_class=HTMLResponse)
def events_edit_page(request: Request, eid: int):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT id,title,start,end,manager,site,status FROM events WHERE id=?", (eid,))
    row = cur.fetchone(); conn.close()
    if not row:
        return HTMLResponse("존재하지 않는 일정입니다.", status_code=404)
    return templates.TemplateResponse("events_form.html", {"request": request, "mode": "edit", "data": dict(row)})

@app.post("/events/edit/{eid}")
def events_edit_submit(
    eid: int,
    title: str = Form(...),
    start: str = Form(...),
    end: str = Form(None),
    manager: str = Form(None),
    site: str = Form(None),
    status: str = Form(None),
):
    conn = db(); cur = conn.cursor()
    cur.execute(
        """
        UPDATE events
           SET title=?,
               start=?,
               end=?,
               manager=?,
               site=?,
               status=?,
               color=?
         WHERE id=?
        """,
        (
            title.strip(),
            start.strip(),
            (end or "").strip() or None,
            (manager or "").strip() or None,
            (site or "").strip() or None,
            (status or "").strip() or None,
            color_for_manager(manager),
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

# (디버그용) 등록된 라우트 확인
@app.get("/_routes")
def list_routes():
    routes = []
    for r in app.router.routes:
        path = getattr(r, "path", None)
        methods = sorted(getattr(r, "methods", []) or [])
        if path:
            routes.append({"path": path, "methods": methods})
    return JSONResponse(routes)
