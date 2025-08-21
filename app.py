from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, StreamingResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy import create_engine, Column, Integer, String, Date, Text
from sqlalchemy.orm import sessionmaker, declarative_base

from jinja2 import Environment, FileSystemLoader, select_autoescape

from datetime import datetime, date
from typing import Optional
from dotenv import load_dotenv
import os, io, csv

# -------------------------
# Config
# -------------------------
load_dotenv()
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8000"))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")
MANAGERS = [m.strip() for m in os.getenv("MANAGERS", "관리자").split(",") if m.strip()]

# -------------------------
# FastAPI, Static, Templates
# -------------------------
app = FastAPI(title="기술지원 전산처리시스템")
app.add_middleware(SessionMiddleware, secret_key="replace-this-with-a-random-string")

# 정적 파일/템플릿 폴더가 없으면 만들어 둠(최초 실행 안전장치)
if not os.path.isdir("static"):
    os.makedirs("static", exist_ok=True)
if not os.path.isdir("templates"):
    os.makedirs("templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

def render(template_name: str, **ctx) -> HTMLResponse:
    tmpl = templates.get_template(template_name)
    return HTMLResponse(tmpl.render(**ctx))

# -------------------------
# Auth (Basic)
# -------------------------
security = HTTPBasic()

def check_auth(credentials: HTTPBasicCredentials = Depends(security)) -> bool:
    if credentials.username == ADMIN_USER and credentials.password == ADMIN_PASS:
        return True
    raise HTTPException(status_code=401, detail="Unauthorized")

# -------------------------
# DB (SQLite + SQLAlchemy)
# -------------------------
Base = declarative_base()
engine = create_engine(
    "sqlite:///techsupport.db", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date, nullable=False)
    site = Column(String(200), nullable=False)
    detail = Column(Text, nullable=False)
    manager = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False, default="진행")  # 진행/완료/보류
    note = Column(String(500), nullable=True)

class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date, nullable=False)
    title = Column(String(200), nullable=False)
    site = Column(String(200), nullable=True)
    manager = Column(String(100), nullable=False)
    start_time = Column(String(5), nullable=True)  # HH:MM
    end_time = Column(String(5), nullable=True)    # HH:MM
    memo = Column(String(500), nullable=True)

Base.metadata.create_all(engine)

# -------------------------
# Helpers
# -------------------------
def parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%d").date()

# -------------------------
# Routes
# -------------------------
@app.get("/health")
def health():
    return PlainTextResponse("ok")

@app.get("/")
def index():
    # 템플릿 없을 때 임시 안내
    if not os.path.isfile(os.path.join("templates", "index.html")):
        return HTMLResponse(
            "<h1>기술지원 전산처리시스템</h1>"
            "<p>템플릿이 아직 없습니다. /reports 또는 /schedule 로 이동해 사용하세요.</p>"
        )
    return render("index.html")

# ----- Reports -----
@app.get("/reports")
def reports_list(
    request: Request,
    q: Optional[str] = None,
    fdate: Optional[str] = None,
    tdate: Optional[str] = None,
    manager: Optional[str] = None,
    status: Optional[str] = None,
):
    db = SessionLocal()
    qry = db.query(Report)
    if fdate:
        qry = qry.filter(Report.date >= parse_date(fdate))
    if tdate:
        qry = qry.filter(Report.date <= parse_date(tdate))
    if manager:
        qry = qry.filter(Report.manager == manager)
    if status:
        qry = qry.filter(Report.status == status)
    if q:
        like = f"%{q}%"
        from sqlalchemy import or_
        qry = qry.filter(
            or_(Report.site.like(like), Report.detail.like(like), Report.note.like(like))
        )
    data = qry.order_by(Report.date.desc(), Report.id.desc()).all()
    db.close()

    # 템플릿 없으면 기본 HTML로라도 렌더
    if not os.path.isfile(os.path.join("templates", "reports_list.html")):
        rows = "".join(
            f"<tr><td>{r.id}</td><td>{r.date:%Y-%m-%d}</td><td>{r.site}</td>"
            f"<td>{r.detail}</td><td>{r.manager}</td><td>{r.status}</td>"
            f"<td>{r.note or ''}</td></tr>"
            for r in data
        )
        return HTMLResponse(
            "<h2>현장관리보고서</h2>"
            '<p><a href="/reports/new">+ 새 보고서</a></p>'
            f"<table border=1 cellpadding=6>"
            f"<tr><th>ID</th><th>날짜</th><th>현장</th><th>CS내역</th>"
            f"<th>담당자</th><th>상태</th><th>비고</th></tr>{rows}</table>"
        )

    return render(
        "reports_list.html",
        items=data,
        managers=MANAGERS,
        fdate=fdate or "",
        tdate=tdate or "",
        manager=manager or "",
        status=status or "",
        q=q or "",
    )

@app.get("/reports/new", dependencies=[Depends(check_auth)])
def reports_new():
    today = date.today().strftime("%Y-%m-%d")
    if not os.path.isfile(os.path.join("templates", "reports_form.html")):
        # 템플릿 없을 때 간단 폼
        options = "".join(f'<option value="{m}">{m}</option>' for m in MANAGERS)
        return HTMLResponse(
            "<h2>보고서 등록</h2>"
            '<form method="post" action="/reports/new">'
            f'<label>날짜 <input type="date" name="date_" value="{today}" required></label><br>'
            '<label>현장이름 <input type="text" name="site" required></label><br>'
            '<label>CS내역 <textarea name="detail" rows="6" required></textarea></label><br>'
            f'<label>담당자 <select name="manager" required>{options}</select></label><br>'
            '<label>상태 <select name="status">'
            '<option>진행</option><option>완료</option><option>보류</option>'
            '</select></label><br>'
            '<label>비고 <input type="text" name="note"></label><br>'
            '<button type="submit">등록</button>'
            "</form>"
        )
    return render("reports_form.html", item=None, managers=MANAGERS, today=today, mode="new")

@app.post("/reports/new", dependencies=[Depends(check_auth)])
def reports_create(
    date_: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(...),
    status: str = Form("진행"),
    note: str = Form(""),
):
    db = SessionLocal()
    obj = Report(
        date=parse_date(date_),
        site=site.strip(),
        detail=detail.strip(),
        manager=manager.strip(),
        status=status.strip(),
        note=note.strip(),
    )
    db.add(obj)
    db.commit()
    db.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.get("/reports/edit/{rid}", dependencies=[Depends(check_auth)])
def reports_edit(rid: int):
    db = SessionLocal()
    item = db.query(Report).get(rid)
    db.close()
    if not item:
        raise HTTPException(status_code=404, detail="Not found")

    if not os.path.isfile(os.path.join("templates", "reports_form.html")):
        options = "".join(
            f'<option value="{m}" {"selected" if item.manager==m else ""}>{m}</option>'
            for m in MANAGERS
        )
        return HTMLResponse(
            f"<h2>보고서 수정 #{item.id}</h2>"
            f'<form method="post" action="/reports/edit/{item.id}">'
            f'<label>날짜 <input type="date" name="date_" value="{item.date:%Y-%m-%d}" required></label><br>'
            f'<label>현장이름 <input type="text" name="site" value="{item.site}" required></label><br>'
            f'<label>CS내역 <textarea name="detail" rows="6" required>{item.detail}</textarea></label><br>'
            f'<label>담당자 <select name="manager" required>{options}</select></label><br>'
            '<label>상태 <select name="status">'
            f'<option {"selected" if item.status=="진행" else ""}>진행</option>'
            f'<option {"selected" if item.status=="완료" else ""}>완료</option>'
            f'<option {"selected" if item.status=="보류" else ""}>보류</option>'
            '</select></label><br>'
            f'<label>비고 <input type="text" name="note" value="{item.note or ""}"></label><br>'
            '<button type="submit">저장</button>'
            "</form>"
        )

    return render(
        "reports_form.html",
        item=item,
        managers=MANAGERS,
        today=item.date.strftime("%Y-%m-%d"),
        mode="edit",
    )

@app.post("/reports/edit/{rid}", dependencies=[Depends(check_auth)])
def reports_update(
    rid: int,
    date_: str = Form(...),
    site: str = Form(...),
    detail: str = Form(...),
    manager: str = Form(...),
    status: str = Form("진행"),
    note: str = Form(""),
):
    db = SessionLocal()
    item = db.query(Report).get(rid)
    if not item:
        db.close()
        raise HTTPException(status_code=404, detail="Not found")
    item.date = parse_date(date_)
    item.site = site.strip()
    item.detail = detail.strip()
    item.manager = manager.strip()
    item.status = status.strip()
    item.note = note.strip()
    db.commit()
    db.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.post("/reports/delete/{rid}", dependencies=[Depends(check_auth)])
def reports_delete(rid: int):
    db = SessionLocal()
    item = db.query(Report).get(rid)
    if item:
        db.delete(item)
        db.commit()
    db.close()
    return RedirectResponse(url="/reports", status_code=303)

@app.get("/reports/export")
def reports_export(
    q: Optional[str] = None,
    fdate: Optional[str] = None,
    tdate: Optional[str] = None,
    manager: Optional[str] = None,
    status: Optional[str] = None,
):
    db = SessionLocal()
    qry = db.query(Report)
    if fdate:
        qry = qry.filter(Report.date >= parse_date(fdate))
    if tdate:
        qry = qry.filter(Report.date <= parse_date(tdate))
    if manager:
        qry = qry.filter(Report.manager == manager)
    if status:
        qry = qry.filter(Report.status == status)
    if q:
        like = f"%{q}%"
        from sqlalchemy import or_
        qry = qry.filter(
            or_(Report.site.like(like), Report.detail.like(like), Report.note.like(like))
        )
    data = qry.order_by(Report.date.asc(), Report.id.asc()).all()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "날짜", "현장이름", "CS내역", "담당자", "상태", "비고"])
    for r in data:
        writer.writerow(
            [
                r.id,
                r.date.strftime("%Y-%m-%d"),
                r.site,
                r.detail,
                r.manager,
                r.status,
                r.note or "",
            ]
        )
    output.seek(0)
    filename = f"reports_{fdate or 'all'}_{tdate or 'all'}.csv"
    return StreamingResponse(
        iter([output.getvalue().encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# ----- Schedule -----
@app.get("/schedule")
def schedule_list(
    request: Request,
    q: Optional[str] = None,
    fdate: Optional[str] = None,
    tdate: Optional[str] = None,
    manager: Optional[str] = None,
):
    db = SessionLocal()
    qry = db.query(Schedule)
    if fdate:
        qry = qry.filter(Schedule.date >= parse_date(fdate))
    if tdate:
        qry = qry.filter(Schedule.date <= parse_date(tdate))
    if manager:
        qry = qry.filter(Schedule.manager == manager)
    if q:
        like = f"%{q}%"
        from sqlalchemy import or_
        qry = qry.filter(
            or_(Schedule.title.like(like), Schedule.site.like(like), Schedule.memo.like(like))
        )
    data = qry.order_by(Schedule.date.desc(), Schedule.id.desc()).all()
    db.close()

    if not os.path.isfile(os.path.join("templates", "schedule_list.html")):
        rows = "".join(
            f"<tr><td>{s.id}</td><td>{s.date:%Y-%m-%d}</td><td>{s.title}</td>"
            f"<td>{s.site or ''}</td><td>{s.manager}</td>"
            f"<td>{(s.start_time or '')}~{(s.end_time or '')}</td>"
            f"<td>{s.memo or ''}</td></tr>"
            for s in data
        )
        return HTMLResponse(
            "<h2>일정관리</h2>"
            '<p><a href="/schedule/new">+ 새 일정</a></p>'
            f"<table border=1 cellpadding=6>"
            f"<tr><th>ID</th><th>날짜</th><th>일정명</th><th>현장</th>"
            f"<th>담당자</th><th>시간</th><th>메모</th></tr>{rows}</table>"
        )

    return render(
        "schedule_list.html",
        items=data,
        managers=MANAGERS,
        fdate=fdate or "",
        tdate=tdate or "",
        manager=manager or "",
        q=q or "",
    )

@app.get("/schedule/new", dependencies=[Depends(check_auth)])
def schedule_new():
    today = date.today().strftime("%Y-%m-%d")
    if not os.path.isfile(os.path.join("templates", "schedule_form.html")):
        options = "".join(f'<option value="{m}">{m}</option>' for m in MANAGERS)
        return HTMLResponse(
            "<h2>일정 등록</h2>"
            '<form method="post" action="/schedule/new">'
            f'<label>날짜 <input type="date" name="date_" value="{today}" required></label><br>'
            '<label>일정명 <input type="text" name="title" required></label><br>'
            '<label>현장 <input type="text" name="site"></label><br>'
            f'<label>담당자 <select name="manager" required>{options}</select></label><br>'
            '<label>시작시간 <input type="time" name="start_time"></label><br>'
            '<label>종료시간 <input type="time" name="end_time"></label><br>'
            '<label>메모 <input type="text" name="memo"></label><br>'
            '<button type="submit">등록</button>'
            "</form>"
        )
    return render("schedule_form.html", item=None, managers=MANAGERS, today=today, mode="new")

@app.post("/schedule/new", dependencies=[Depends(check_auth)])
def schedule_create(
    date_: str = Form(...),
    title: str = Form(...),
    site: str = Form(""),
    manager: str = Form(...),
    start_time: str = Form(""),
    end_time: str = Form(""),
    memo: str = Form(""),
):
    db = SessionLocal()
    obj = Schedule(
        date=parse_date(date_),
        title=title.strip(),
        site=site.strip(),
        manager=manager.strip(),
        start_time=start_time.strip(),
        end_time=end_time.strip(),
        memo=memo.strip(),
    )
    db.add(obj)
    db.commit()
    db.close()
    return RedirectResponse(url="/schedule", status_code=303)

@app.get("/schedule/edit/{sid}", dependencies=[Depends(check_auth)])
def schedule_edit(sid: int):
    db = SessionLocal()
    item = db.query(Schedule).get(sid)
    db.close()
    if not item:
        raise HTTPException(status_code=404, detail="Not found")

    if not os.path.isfile(os.path.join("templates", "schedule_form.html")):
        options = "".join(
            f'<option value="{m}" {"selected" if item.manager==m else ""}>{m}</option>'
            for m in MANAGERS
        )
        return HTMLResponse(
            f"<h2>일정 수정 #{item.id}</h2>"
            f'<form method="post" action="/schedule/edit/{item.id}">'
            f'<label>날짜 <input type="date" name="date_" value="{item.date:%Y-%m-%d}" required></label><br>'
            f'<label>일정명 <input type="text" name="title" value="{item.title}" required></label><br>'
            f'<label>현장 <input type="text" name="site" value="{item.site or ""}"></label><br>'
            f'<label>담당자 <select name="manager" required>{options}</select></label><br>'
            f'<label>시작시간 <input type="time" name="start_time" value="{item.start_time or ""}"></label><br>'
            f'<label>종료시간 <input type="time" name="end_time" value="{item.end_time or ""}"></label><br>'
            f'<label>메모 <input type="text" name="memo" value="{item.memo or ""}"></label><br>'
            '<button type="submit">저장</button>'
            "</form>"
        )

    return render(
        "schedule_form.html",
        item=item,
        managers=MANAGERS,
        today=item.date.strftime("%Y-%m-%d"),
        mode="edit",
    )

@app.post("/schedule/edit/{sid}", dependencies=[Depends(check_auth)])
def schedule_update(
    sid: int,
    date_: str = Form(...),
    title: str = Form(...),
    site: str = Form(""),
    manager: str = Form(...),
    start_time: str = Form(""),
    end_time: str = Form(""),
    memo: str = Form(""),
):
    db = SessionLocal()
    item = db.query(Schedule).get(sid)
    if not item:
        db.close()
        raise HTTPException(status_code=404, detail="Not found")
    item.date = parse_date(date_)
    item.title = title.strip()
    item.site = site.strip()
    item.manager = manager.strip()
    item.start_time = start_time.strip()
    item.end_time = end_time.strip()
    item.memo = memo.strip()
    db.commit()
    db.close()
    return RedirectResponse(url="/schedule", status_code=303)

@app.post("/schedule/delete/{sid}", dependencies=[Depends(check_auth)])
def schedule_delete(sid: int):
    db = SessionLocal()
    item = db.query(Schedule).get(sid)
    if item:
        db.delete(item)
        db.commit()
    db.close()
    return RedirectResponse(url="/schedule", status_code=303)

# --------------- run tip ---------------
# uvicorn app:app --host 0.0.0.0 --port 8000
