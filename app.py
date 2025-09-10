# app.py — NAIZ 전산프로그램 (정렬 기본값/최신 DDL 반영판)
import os
import json
from datetime import date
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND

from sqlalchemy import (
    create_engine, event, Column, Integer, String, Text, DateTime, ForeignKey,
    UniqueConstraint, or_, select, func
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session as OrmSession

from fastapi.templating import Jinja2Templates


# ------------------------------------------------------------------------------
# 설정
# ------------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///naiz.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="naiz_session",
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

def _comma(v):
    if v is None or v == "":
        return ""
    try:
        # 정수/문자 정수
        return f"{int(v):,}"
    except Exception:
        try:
            # 소수도 반올림해서 표시 (원단위라면 int로 캐스팅)
            return f"{float(v):,.0f}"
        except Exception:
            return str(v)
templates.env.filters["comma"] = _comma

# ------------------------------------------------------------------------------
# DB 초기화 (SQLite FK 강제)
# ------------------------------------------------------------------------------
Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    future=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_db() -> OrmSession:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _to_int_or_none(v):
    if v is None or v == "" or v == "None":
        return None
    try:
        return int(v)
    except Exception:
        return None
    
def default_color(status: str) -> str:
    s = (status or "").lower()
    return {
        "todo":        "#3b82f6",  # 파랑
        "in_progress": "#f59e0b",  # 주황
        "done":        "#10b981",  # 초록
        "lab_request": "#8b5cf6",  # 보라
    }.get(s, "#3b82f6")


# ------------------------------------------------------------------------------
# 모델 (최신 DDL 반영)
# ------------------------------------------------------------------------------
class Department(Base):
    __tablename__ = "departments"
    dept_id = Column(Integer, primary_key=True)
    dept_code = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    parent_id = Column(Integer, ForeignKey("departments.dept_id"), nullable=True)
    status = Column(String, nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    deleted_at = Column(DateTime, nullable=True)
    parent = relationship("Department", remote_side=[dept_id], backref="children")

class JobRank(Base):
    __tablename__ = "job_ranks"
    rank_id = Column(Integer, primary_key=True)
    rank_code = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))

class Role(Base):
    __tablename__ = "roles"
    role_id = Column(Integer, primary_key=True)
    role_code = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))

class Employee(Base):
    __tablename__ = "employees"
    emp_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    dept_id = Column(Integer, ForeignKey("departments.dept_id"), nullable=True)
    rank_id = Column(Integer, ForeignKey("job_ranks.rank_id"), nullable=True)
    status = Column(String, nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    deleted_at = Column(DateTime, nullable=True)
    dept = relationship("Department", backref="employees")
    rank = relationship("JobRank", backref="employees")

class EmployeeRole(Base):
    __tablename__ = "employee_roles"
    emp_id = Column(Integer, ForeignKey("employees.emp_id", ondelete="CASCADE"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    employee = relationship("Employee", backref="emp_roles")
    role = relationship("Role", backref="role_emps")

class EmployeeAuth(Base):
    __tablename__ = "employee_auth"
    auth_id = Column(Integer, primary_key=True)
    emp_id = Column(Integer, ForeignKey("employees.emp_id", ondelete="CASCADE"), unique=True, nullable=False)
    login_id = Column(String, unique=True, nullable=False)
    pw_hash = Column(String, nullable=False)  # bcrypt or argon2 hash
    pw_salt = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    employee = relationship("Employee", backref="auth", uselist=False)

class Vendor(Base):
    __tablename__ = "vendors"
    vendor_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    ceo_name = Column(String)
    phone = Column(String)
    email = Column(String)
    address = Column(String)
    note = Column(Text)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    deleted_at = Column(DateTime)

class Site(Base):
    __tablename__ = "sites"
    site_id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    camera_count = Column(Integer, nullable=False, default=0)
    nrs_count = Column(Integer, nullable=False, default=0)
    note = Column(Text)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    deleted_at = Column(DateTime)

class SiteLocation(Base):
    __tablename__ = "site_locations"
    location_id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.site_id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    address = Column(String)
    manager_name = Column(String)
    manager_phone = Column(String)
    note = Column(Text)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    site = relationship("Site", backref="locations")

class CSRequest(Base):
    __tablename__ = "cs_requests"
    request_id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.site_id", ondelete="SET NULL"))
    requester_name = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="requested")
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    site = relationship("Site")

class CSRequestLocation(Base):
    __tablename__ = "cs_request_locations"
    request_id = Column(Integer, ForeignKey("cs_requests.request_id", ondelete="CASCADE"), primary_key=True)
    location_id = Column(Integer, ForeignKey("site_locations.location_id", ondelete="CASCADE"), primary_key=True)
    request = relationship("CSRequest", backref="req_locations")
    location = relationship("SiteLocation")

class CSSchedule(Base):
    __tablename__ = "cs_schedules"
    schedule_id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey("cs_requests.request_id", ondelete="SET NULL"))
    start_date = Column(String, nullable=False)  # YYYY-MM-DD
    end_date = Column(String)                    # nullable
    site_id = Column(Integer, ForeignKey("sites.site_id", ondelete="SET NULL"))
    request_content = Column(Text)
    work_content = Column(Text)
    extra_content = Column(Text)
    status = Column(String, nullable=False, default="todo")
    note = Column(Text)
    color  = Column(String)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    site = relationship("Site")
    request = relationship("CSRequest")

class CSScheduleLocation(Base):
    __tablename__ = "cs_schedule_locations"
    schedule_id = Column(Integer, ForeignKey("cs_schedules.schedule_id", ondelete="CASCADE"), primary_key=True)
    location_id = Column(Integer, ForeignKey("site_locations.location_id", ondelete="CASCADE"), primary_key=True)
    schedule = relationship("CSSchedule", backref="sch_locations")
    location = relationship("SiteLocation")

class CSScheduleAssignee(Base):
    __tablename__ = "cs_schedule_assignees"
    schedule_id = Column(Integer, ForeignKey("cs_schedules.schedule_id", ondelete="CASCADE"), primary_key=True)
    emp_id = Column(Integer, ForeignKey("employees.emp_id", ondelete="CASCADE"), primary_key=True)
    schedule = relationship("CSSchedule", backref="sch_assignees")
    employee = relationship("Employee")

class CSHelp(Base):
    __tablename__ = "cs_helps"
    help_id = Column(Integer, primary_key=True)
    schedule_id = Column(Integer, ForeignKey("cs_schedules.schedule_id", ondelete="CASCADE"), unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    schedule = relationship("CSSchedule", backref="help")

class SWProduct(Base):
    __tablename__ = "sw_products"
    sw_id = Column(Integer, primary_key=True)
    sw_code = Column(String, unique=True, nullable=True)  # 선택적/유니크 코드
    sw_name = Column(String, nullable=False, unique=True)
    sw_func = Column(Text)
    unit = Column(String)  # 단가 단위(선택)
    price_wons = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))

class SWService(Base):
    __tablename__ = "sw_services"
    sv_id = Column(Integer, primary_key=True)
    sw_id = Column(Integer, ForeignKey("sw_products.sw_id", ondelete="CASCADE"), nullable=False)
    sv_code = Column(String, unique=True, nullable=False)
    sv_name = Column(String, nullable=False)
    sv_type = Column(String, nullable=False, default="A")  # CHECK는 DB가 수행
    price_wons = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    updated_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))
    product = relationship("SWProduct", backref="services")
    __table_args__ = (UniqueConstraint("sw_id", "sv_name", name="uq_sw_sv_name"),)


# ------------------------------------------------------------------------------
# DB 생성
# ------------------------------------------------------------------------------
def init_db():
    Base.metadata.create_all(bind=engine)

@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------------------------------------------------------------
# 인증
# ------------------------------------------------------------------------------
def verify_password_hash(pw: str, hash_str: str) -> bool:
    try:
        if hash_str.startswith(("$2a$", "$2b$", "$2y$")):
            from passlib.hash import bcrypt
            return bcrypt.verify(pw, hash_str)
        if hash_str.startswith("$argon2"):
            from passlib.hash import argon2
            return argon2.verify(pw, hash_str)
    except Exception:
        pass
    return False

def is_logged_in(request: Request) -> bool:
    return "user" in request.session

def require_login(request: Request):
    if not is_logged_in(request):
        raise HTTPException(status_code=401, detail="Login required")

@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    accept = (request.headers.get("accept") or "").lower()
    if exc.status_code == 401 and "text/html" in accept:
        return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, db: OrmSession = Depends(get_db),
                 login_id: str = Form(...), password: str = Form(...)):
    auth = db.execute(select(EmployeeAuth).where(EmployeeAuth.login_id == login_id)).scalar_one_or_none()
    if not auth or not verify_password_hash(password, auth.pw_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "로그인 실패"})
    request.session["user"] = {"login_id": login_id, "emp_id": auth.emp_id}
    return RedirectResponse(url="/calendar", status_code=HTTP_302_FOUND)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)


# ------------------------------------------------------------------------------
# 유틸: 셀렉트 옵션
# ------------------------------------------------------------------------------
def options_sites(db: OrmSession):
    return [(s.site_id, s.name) for s in db.query(Site).order_by(Site.name).all()]

def options_site_locations(db: OrmSession, site_id: Optional[int] = None):
    q = db.query(SiteLocation).join(Site)
    if site_id:
        q = q.filter(SiteLocation.site_id == site_id)
    return [(l.location_id, f"[{l.site.name}] {l.name}") for l in q.order_by(Site.name, SiteLocation.name).all()]

def options_employees(db: OrmSession):
    return [(e.emp_id, e.name) for e in db.query(Employee).order_by(Employee.name).all()]

def options_roles(db: OrmSession):
    return [(r.role_id, r.name) for r in db.query(Role).order_by(Role.name).all()]

def options_ranks(db: OrmSession):
    return [(r.rank_id, r.name) for r in db.query(JobRank).order_by(JobRank.rank_id).all()]

def options_departments(db: OrmSession):
    return [(d.dept_id, d.name) for d in db.query(Department).order_by(Department.name).all()]

def options_sw_products(db: OrmSession):
    return [(p.sw_id, p.sw_name) for p in db.query(SWProduct).order_by(SWProduct.sw_name).all()]


# ------------------------------------------------------------------------------
# 캘린더(FullCalendar용)
# ------------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/calendar", status_code=HTTP_302_FOUND)

@app.get("/calendar", response_class=HTMLResponse)
def calendar_page(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    statuses = ["todo", "in_progress", "done", "lab_request"]
    return templates.TemplateResponse("calendar.html", {
        "request": request,
        "employees": options_employees(db),
        "sites": options_sites(db),
        "statuses": statuses,
    })

@app.get("/events", response_class=PlainTextResponse)
@app.get("/api/events", response_class=PlainTextResponse)
def events_json(
    request: Request,
    db: OrmSession = Depends(get_db),
    start: Optional[str] = None,
    end: Optional[str] = None,
    site_id: Optional[int] = None,
    assignee: Optional[int] = None,  # emp_id
    status: Optional[str] = None,
    q: Optional[str] = None,
):
    require_login(request)

    qset = db.query(CSSchedule).outerjoin(Site)

    # '2025-09-05' 또는 '2025-09-05T...' 형태 모두 허용
    def _parse(d: Optional[str]) -> Optional[str]:
        if not d:
            return None
        try:
            return date.fromisoformat(d[:10]).isoformat()
        except Exception:
            return None

    s = _parse(start)
    e = _parse(end)
    if s:
        qset = qset.filter(CSSchedule.start_date >= s)
    if e:
        qset = qset.filter(CSSchedule.start_date <= e)
    if site_id:
        qset = qset.filter(CSSchedule.site_id == site_id)
    if status:
        qset = qset.filter(CSSchedule.status == status)
    if assignee:
        qset = (
            qset.join(
                CSScheduleAssignee,
                CSSchedule.schedule_id == CSScheduleAssignee.schedule_id,
            )
            .filter(CSScheduleAssignee.emp_id == assignee)
        )
    if q:
        like = f"%{q}%"
        qset = qset.filter(
            or_(
                CSSchedule.request_content.ilike(like),
                CSSchedule.work_content.ilike(like),
                CSSchedule.extra_content.ilike(like),
                Site.name.ilike(like),
            )
        )

    rows = qset.order_by(CSSchedule.start_date.asc()).all()

    # 글자색 자동 대비(밝은 배경이면 진한 글자, 어두우면 흰 글자)
    def _text_on(bg: Optional[str]) -> str:
        try:
            h = (bg or "").lstrip("#")
            if len(h) != 6:
                return "#111"
            r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
            yiq = (r * 299 + g * 587 + b * 114) / 1000
            return "#111" if yiq >= 160 else "#fff"
        except Exception:
            return "#111"

    payload = []
    for r in rows:
        assignees = [a.employee.name for a in r.sch_assignees]
        site_name = r.site.name if r.site else "-"
        # 셀에 보이는 텍스트는 "현장 + 담당자들"
        title = f"[{site_name}] " + (", ".join(assignees) if assignees else "")

        # 색상: 개별 지정 > 상태 기본색
        evt_color = (r.color or "").strip() or default_color(r.status)

        payload.append(
            {
                "id": r.schedule_id,
                "title": title,
                "start": r.start_date,
                "end": r.end_date or r.start_date,
                # FullCalendar 색상 속성들
                "color": evt_color,                 # 단일 지정
                "backgroundColor": evt_color,       # 보강
                "borderColor": evt_color,           # 보강
                "textColor": _text_on(evt_color),   # 가독성
                # 클릭/팝오버에서 사용할 추가 정보
                "extendedProps": {
                    "site_id": r.site_id,
                    "site_name": site_name,
                    "status": r.status,
                    "assignees": assignees,
                    "request_content": r.request_content or "",
                    "work_content": r.work_content or "",
                    "extra_content": r.extra_content or "",
                    "note": r.note or "",
                    "color": evt_color,
                },
            }
        )

    return PlainTextResponse(
        content=json.dumps(payload, ensure_ascii=False),
        media_type="application/json; charset=utf-8",
    )

# ------------------------------------------------------------------------------
# 제네릭 렌더
# ------------------------------------------------------------------------------
def render_list(request: Request, title, headers, rows, routes):
    # headers: str | (label, class) | {"label":..., "bold":bool, "align":"left|center|right", "class":"..."}
    norm_headers = []
    for h in headers:
        if isinstance(h, str):
            norm_headers.append({"label": h, "class": "th-center"})  # 기본: 가운데, 기본 굵기
        elif isinstance(h, tuple):
            label = h[0]
            cls = (h[1] if len(h) > 1 else "th-center")
            norm_headers.append({"label": label, "class": cls.strip()})
        elif isinstance(h, dict):
            label = h.get("label") or h.get("text") or ""
            align = {"left": "th-left", "right": "th-right", "center": "th-center"}.get(h.get("align", "center"), "th-center")
            extra = h.get("class", "")
            bold = "th-bold" if h.get("bold") else ""
            cls = " ".join(c for c in [align, bold, extra] if c)
            norm_headers.append({"label": label, "class": cls})
        else:
            norm_headers.append({"label": str(h), "class": "th-center"})

    return templates.TemplateResponse("generic_list.html", {
        "request": request,
        "title": title,
        "headers": norm_headers,  # ← 정규화된 헤더
        "rows": rows,
        "routes": routes
    })


def render_form(request: Request, title: str, fields: List[Dict[str, Any]], action: str, method: str = "post"):
    return templates.TemplateResponse("generic_form.html", {
        "request": request, "title": title, "fields": fields, "action": action, "method": method
    })


# ------------------------------------------------------------------------------
# 조직: 부서 / 직급 / 권한 / 직원(+권한)
#  - 기본 정렬: ID ASC
# ------------------------------------------------------------------------------
@app.get("/departments", response_class=HTMLResponse)
def departments_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows = []
    for d in db.query(Department).order_by(Department.dept_id.asc()).all():
        parent = db.get(Department, d.parent_id).name if d.parent_id else ""
        rows.append([d.dept_id, d.dept_code, d.name, parent, d.status, d.created_at])
    headers = ["ID", "코드", "부서명", "상위부서", "상태", "생성"]
    return render_list(request, "부서", headers, rows, {
        "new": "/departments/new", "edit": "/departments/edit/{id}", "delete": "/departments/delete/{id}"
    })

@app.get("/departments/new", response_class=HTMLResponse)
def departments_new(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    fields = [
        {"name": "dept_code", "label": "부서코드", "type": "text", "required": True},
        {"name": "name", "label": "부서명", "type": "text", "required": True},
        {"name": "parent_id", "label": "상위부서", "type": "select",
         "options": [(None, "")] + options_departments(db), "nullable": True},
        {"name": "status", "label": "상태", "type": "select",
         "options": [("active", "active"), ("inactive", "inactive"), ("archived", "archived")]}
    ]
    return render_form(request, "부서 추가", fields, "/departments/new")

@app.post("/departments/new")
def departments_new_submit(
    request: Request, db: OrmSession = Depends(get_db),
    dept_code: str = Form(...), name: str = Form(...),
    parent_id: Optional[int] = Form(None), status: str = Form("active")
):
    require_login(request)
    d = Department(dept_code=dept_code.strip().upper(), name=name.strip(),
                   parent_id=parent_id or None, status=status)
    db.add(d); db.commit()
    return RedirectResponse(url="/departments", status_code=HTTP_302_FOUND)

@app.get("/departments/edit/{dept_id}", response_class=HTMLResponse)
def departments_edit(request: Request, dept_id: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    d = db.get(Department, dept_id);  assert d
    fields = [
        {"name":"dept_code","label":"부서코드","type":"text","required":True,"value":d.dept_code},
        {"name":"name","label":"부서명","type":"text","required":True,"value":d.name},
        {"name":"parent_id","label":"상위부서","type":"select","options":[(None,"")] + options_departments(db),"value":d.parent_id or ""},
        {"name":"status","label":"상태","type":"select","options":[("active","active"),("inactive","inactive"),("archived","archived")],"value":d.status},
    ]
    return render_form(request, "부서 수정", fields, f"/departments/edit/{dept_id}")

@app.post("/departments/edit/{dept_id}")
def departments_edit_submit(
    request: Request, dept_id: int, db: OrmSession = Depends(get_db),
    dept_code: str = Form(...), name: str = Form(...),
    parent_id: Optional[int] = Form(None), status: str = Form("active")
):
    require_login(request)
    d = db.get(Department, dept_id);  assert d
    d.dept_code = dept_code.strip().upper(); d.name = name.strip()
    d.parent_id = parent_id or None; d.status = status
    db.commit()
    return RedirectResponse(url="/departments", status_code=HTTP_302_FOUND)

@app.post("/departments/delete/{dept_id}")
def departments_delete(request: Request, dept_id: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    d = db.get(Department, dept_id)
    if d: db.delete(d); db.commit()
    return RedirectResponse(url="/departments", status_code=HTTP_302_FOUND)


@app.get("/job_ranks", response_class=HTMLResponse)
def job_ranks_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows = [[r.rank_id, r.rank_code, r.name, r.created_at]
            for r in db.query(JobRank).order_by(JobRank.rank_id.asc()).all()]
    return render_list(request, "직급", ["ID","코드","이름","생성"], rows, {
        "new":"/job_ranks/new","edit":"/job_ranks/edit/{id}","delete":"/job_ranks/delete/{id}"
    })

@app.get("/job_ranks/new", response_class=HTMLResponse)
def job_ranks_new(request: Request):
    require_login(request)
    fields=[{"name":"rank_code","label":"코드","type":"text","required":True},
            {"name":"name","label":"이름","type":"text","required":True}]
    return render_form(request,"직급 추가",fields,"/job_ranks/new")

@app.post("/job_ranks/new")
def job_ranks_new_submit(request: Request, db: OrmSession = Depends(get_db),
                         rank_code: str = Form(...), name: str = Form(...)):
    require_login(request)
    db.add(JobRank(rank_code=rank_code.strip().upper(), name=name.strip())); db.commit()
    return RedirectResponse(url="/job_ranks", status_code=HTTP_302_FOUND)

@app.get("/job_ranks/edit/{rid}", response_class=HTMLResponse)
def job_ranks_edit(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(JobRank, rid); assert r
    fields=[{"name":"rank_code","label":"코드","type":"text","required":True,"value":r.rank_code},
            {"name":"name","label":"이름","type":"text","required":True,"value":r.name}]
    return render_form(request,"직급 수정",fields,f"/job_ranks/edit/{rid}")

@app.post("/job_ranks/edit/{rid}")
def job_ranks_edit_submit(request: Request, rid: int, db: OrmSession = Depends(get_db),
                          rank_code: str = Form(...), name: str = Form(...)):
    require_login(request)
    r = db.get(JobRank, rid); assert r
    r.rank_code = rank_code.strip().upper(); r.name = name.strip(); db.commit()
    return RedirectResponse(url="/job_ranks", status_code=HTTP_302_FOUND)

@app.post("/job_ranks/delete/{rid}")
def job_ranks_delete(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(JobRank, rid)
    if r: db.delete(r); db.commit()
    return RedirectResponse(url="/job_ranks", status_code=HTTP_302_FOUND)


@app.get("/roles", response_class=HTMLResponse)
def roles_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows = [[r.role_id, r.role_code, r.name, r.created_at]
            for r in db.query(Role).order_by(Role.role_id.asc()).all()]
    return render_list(request, "권한", ["ID","코드","이름","생성"], rows, {
        "new":"/roles/new","edit":"/roles/edit/{id}","delete":"/roles/delete/{id}"
    })

@app.get("/roles/new", response_class=HTMLResponse)
def roles_new(request: Request):
    require_login(request)
    fields=[{"name":"role_code","label":"코드","type":"text","required":True},
            {"name":"name","label":"이름","type":"text","required":True}]
    return render_form(request,"권한 추가",fields,"/roles/new")

@app.post("/roles/new")
def roles_new_submit(request: Request, db: OrmSession = Depends(get_db),
                     role_code: str = Form(...), name: str = Form(...)):
    require_login(request)
    db.add(Role(role_code=role_code.strip().upper(), name=name.strip())); db.commit()
    return RedirectResponse(url="/roles", status_code=HTTP_302_FOUND)

@app.get("/roles/edit/{rid}", response_class=HTMLResponse)
def roles_edit(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(Role, rid); assert r
    fields=[{"name":"role_code","label":"코드","type":"text","required":True,"value":r.role_code},
            {"name":"name","label":"이름","type":"text","required":True,"value":r.name}]
    return render_form(request,"권한 수정",fields,f"/roles/edit/{rid}")

@app.post("/roles/edit/{rid}")
def roles_edit_submit(request: Request, rid: int, db: OrmSession = Depends(get_db),
                      role_code: str = Form(...), name: str = Form(...)):
    require_login(request)
    r = db.get(Role, rid); assert r
    r.role_code = role_code.strip().upper(); r.name = name.strip(); db.commit()
    return RedirectResponse(url="/roles", status_code=HTTP_302_FOUND)

@app.post("/roles/delete/{rid}")
def roles_delete(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(Role, rid)
    if r: db.delete(r); db.commit()
    return RedirectResponse(url="/roles", status_code=HTTP_302_FOUND)


@app.get("/employees", response_class=HTMLResponse)
def employees_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows=[]
    for e in db.query(Employee).order_by(Employee.emp_id.asc()).all():
        dept = e.dept.name if e.dept else ""
        rank = e.rank.name if e.rank else ""
        roles = ", ".join(sorted([er.role.name for er in e.emp_roles]))
        rows.append([e.emp_id, e.name, dept, rank, e.status, roles, e.created_at])
    return render_list(request, "직원", ["ID","이름","부서","직급","상태","권한","생성"], rows, {
        "new":"/employees/new","edit":"/employees/edit/{id}","delete":"/employees/delete/{id}"
    })

@app.get("/employees/new", response_class=HTMLResponse)
def employees_new(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    fields = [
        {"name":"name","label":"이름","type":"text","required":True},
        {"name":"dept_id","label":"부서","type":"select","options":[(None,"")] + options_departments(db),"nullable":True},
        {"name":"rank_id","label":"직급","type":"select","options":[(None,"")] + options_ranks(db),"nullable":True},
        {"name":"status","label":"상태","type":"select","options":[("active","active"),("leave","leave"),("retired","retired")]},
        {"name":"roles","label":"권한","type":"multiselect","options":options_roles(db)}
    ]
    return render_form(request,"직원 추가",fields,"/employees/new")

@app.post("/employees/new")
def employees_new_submit(
    request: Request, db: OrmSession = Depends(get_db),
    name: str = Form(...), dept_id: Optional[int] = Form(None), rank_id: Optional[int] = Form(None),
    status: str = Form("active"), roles: Optional[List[int]] = Form(None)
):
    require_login(request)
    e = Employee(name=name.strip(), dept_id=dept_id or None, rank_id=rank_id or None, status=status)
    db.add(e); db.commit(); db.refresh(e)
    if roles:
        if isinstance(roles, str): roles = [roles]
        for rid in roles:
            db.add(EmployeeRole(emp_id=e.emp_id, role_id=int(rid)))
        db.commit()
    return RedirectResponse(url="/employees", status_code=HTTP_302_FOUND)

@app.get("/employees/edit/{eid}", response_class=HTMLResponse)
def employees_edit(request: Request, eid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    e = db.get(Employee, eid); assert e
    current_roles = [er.role_id for er in e.emp_roles]
    fields = [
        {"name":"name","label":"이름","type":"text","required":True,"value":e.name},
        {"name":"dept_id","label":"부서","type":"select","options":[(None,"")] + options_departments(db),"value":e.dept_id or ""},
        {"name":"rank_id","label":"직급","type":"select","options":[(None,"")] + options_ranks(db),"value":e.rank_id or ""},
        {"name":"status","label":"상태","type":"select","options":[("active","active"),("leave","leave"),("retired","retired")],"value":e.status},
        {"name":"roles","label":"권한","type":"multiselect","options":options_roles(db),"value":current_roles},
    ]
    return render_form(request,"직원 수정",fields,f"/employees/edit/{eid}")

@app.post("/employees/edit/{eid}")
def employees_edit_submit(
    request: Request, eid: int, db: OrmSession = Depends(get_db),
    name: str = Form(...), dept_id: Optional[int] = Form(None), rank_id: Optional[int] = Form(None),
    status: str = Form("active"), roles: Optional[List[int]] = Form(None)
):
    require_login(request)
    e = db.get(Employee, eid); assert e
    e.name=name.strip(); e.dept_id=dept_id or None; e.rank_id=rank_id or None; e.status=status
    db.query(EmployeeRole).filter(EmployeeRole.emp_id==eid).delete()
    if roles:
        if isinstance(roles, str): roles = [roles]
        for rid in roles:
            db.add(EmployeeRole(emp_id=eid, role_id=int(rid)))
    db.commit()
    return RedirectResponse(url="/employees", status_code=HTTP_302_FOUND)

@app.post("/employees/delete/{eid}")
def employees_delete(request: Request, eid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    e = db.get(Employee, eid)
    if e: db.delete(e); db.commit()
    return RedirectResponse(url="/employees", status_code=HTTP_302_FOUND)


# ------------------------------------------------------------------------------
# 협력사 / 현장 / 상세현장 (기본 정렬: ID ASC)
# ------------------------------------------------------------------------------
@app.get("/vendors", response_class=HTMLResponse)
def vendors_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows=[[v.vendor_id,v.name,v.ceo_name or "",v.phone or "",v.email or "",v.created_at]
          for v in db.query(Vendor).order_by(Vendor.vendor_id.asc()).all()]
    return render_list(request,"협력사",["ID","업체명","대표","연락처","이메일","생성"],rows,{
        "new":"/vendors/new","edit":"/vendors/edit/{id}","delete":"/vendors/delete/{id}"
    })

@app.get("/vendors/new", response_class=HTMLResponse)
def vendors_new(request: Request):
    require_login(request)
    fields=[{"name":"name","label":"업체명","type":"text","required":True},
            {"name":"ceo_name","label":"대표","type":"text"},
            {"name":"phone","label":"연락처","type":"text"},
            {"name":"email","label":"이메일","type":"text"},
            {"name":"address","label":"주소","type":"text"},
            {"name":"note","label":"비고","type":"textarea"}]
    return render_form(request,"협력사 추가",fields,"/vendors/new")

@app.post("/vendors/new")
def vendors_new_submit(request: Request, db: OrmSession = Depends(get_db),
                       name: str = Form(...), ceo_name: Optional[str] = Form(None), phone: Optional[str] = Form(None),
                       email: Optional[str] = Form(None), address: Optional[str] = Form(None), note: Optional[str] = Form(None)):
    require_login(request)
    db.add(Vendor(name=name.strip(),ceo_name=ceo_name,phone=phone,email=email,address=address,note=note)); db.commit()
    return RedirectResponse(url="/vendors", status_code=HTTP_302_FOUND)

@app.get("/vendors/edit/{vid}", response_class=HTMLResponse)
def vendors_edit(request: Request, vid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    v = db.get(Vendor, vid); assert v
    fields=[{"name":"name","label":"업체명","type":"text","required":True,"value":v.name},
            {"name":"ceo_name","label":"대표","type":"text","value":v.ceo_name or ""},
            {"name":"phone","label":"연락처","type":"text","value":v.phone or ""},
            {"name":"email","label":"이메일","type":"text","value":v.email or ""},
            {"name":"address","label":"주소","type":"text","value":v.address or ""},
            {"name":"note","label":"비고","type":"textarea","value":v.note or ""}]
    return render_form(request,"협력사 수정",fields,f"/vendors/edit/{vid}")

@app.post("/vendors/edit/{vid}")
def vendors_edit_submit(
    request: Request, vid: int, db: OrmSession = Depends(get_db),
    name: str = Form(...),
    ceo_name: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    note: Optional[str] = Form(None)
):
    require_login(request)
    v = db.get(Vendor, vid); assert v
    v.name = name.strip()
    v.ceo_name = ceo_name
    v.phone = phone
    v.email = email
    v.address = address
    v.note = note
    db.commit()
    return RedirectResponse(url="/vendors", status_code=HTTP_302_FOUND)


@app.post("/vendors/delete/{vid}")
def vendors_delete(request: Request, vid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    v = db.get(Vendor, vid)
    if v: db.delete(v); db.commit()
    return RedirectResponse(url="/vendors", status_code=HTTP_302_FOUND)


@app.get("/sites", response_class=HTMLResponse)
def sites_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows=[[s.site_id,s.name,s.camera_count,s.nrs_count,s.created_at]
          for s in db.query(Site).order_by(Site.site_id.asc()).all()]
    return render_list(request,"현장",["ID","현장명","카메라수","NRS수","생성"],rows,{
        "new":"/sites/new","edit":"/sites/edit/{id}","delete":"/sites/delete/{id}","child":"/site_locations?site_id={id}"
    })

@app.get("/sites/new", response_class=HTMLResponse)
def sites_new(request: Request):
    require_login(request)
    fields=[{"name":"name","label":"현장명","type":"text","required":True},
            {"name":"camera_count","label":"카메라수","type":"number","value":0},
            {"name":"nrs_count","label":"NRS수","type":"number","value":0},
            {"name":"note","label":"비고","type":"textarea"}]
    return render_form(request,"현장 추가",fields,"/sites/new")

@app.post("/sites/new")
def sites_new_submit(request: Request, db: OrmSession = Depends(get_db),
                     name: str = Form(...), camera_count: int = Form(0), nrs_count: int = Form(0), note: Optional[str] = Form(None)):
    require_login(request)
    db.add(Site(name=name.strip(),camera_count=camera_count,nrs_count=nrs_count,note=note)); db.commit()
    return RedirectResponse(url="/sites", status_code=HTTP_302_FOUND)

@app.get("/sites/edit/{sid}", response_class=HTMLResponse)
def sites_edit(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(Site, sid); assert s
    fields=[{"name":"name","label":"현장명","type":"text","required":True,"value":s.name},
            {"name":"camera_count","label":"카메라수","type":"number","value":s.camera_count},
            {"name":"nrs_count","label":"NRS수","type":"number","value":s.nrs_count},
            {"name":"note","label":"비고","type":"textarea","value":s.note or ""}]
    return render_form(request,"현장 수정",fields,f"/sites/edit/{sid}")

@app.post("/sites/edit/{sid}")
def sites_edit_submit(request: Request, sid: int, db: OrmSession = Depends(get_db),
                      name: str = Form(...), camera_count: int = Form(0), nrs_count: int = Form(0), note: Optional[str] = Form(None)):
    require_login(request)
    s = db.get(Site, sid); assert s
    s.name=name.strip(); s.camera_count=camera_count; s.nrs_count=nrs_count; s.note=note
    db.commit()
    return RedirectResponse(url="/sites", status_code=HTTP_302_FOUND)

@app.post("/sites/delete/{sid}")
def sites_delete(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(Site, sid)
    if s: db.delete(s); db.commit()
    return RedirectResponse(url="/sites", status_code=HTTP_302_FOUND)


@app.get("/site_locations", response_class=HTMLResponse)
def site_locations_list(request: Request, db: OrmSession = Depends(get_db), site_id: Optional[int] = None):
    require_login(request)
    q = db.query(SiteLocation).join(Site)
    if site_id: q = q.filter(SiteLocation.site_id == site_id)
    rows=[[l.location_id, f"[{l.site.name}] {l.name}", l.address or "", l.manager_name or "", l.manager_phone or "", l.created_at]
          for l in q.order_by(SiteLocation.location_id.asc()).all()]
    return render_list(request,"상세현장",["ID","이름","주소","담당자","연락처","생성"],rows,{
        "new":"/site_locations/new","edit":"/site_locations/edit/{id}","delete":"/site_locations/delete/{id}"
    })

@app.get("/site_locations/new", response_class=HTMLResponse)
def site_locations_new(request: Request, db: OrmSession = Depends(get_db), site_id: Optional[int] = None):
    require_login(request)
    fields=[{"name":"site_id","label":"현장","type":"select","options":[(None,"")] + options_sites(db),"value":site_id or ""},
            {"name":"name","label":"이름","type":"text","required":True},
            {"name":"address","label":"주소","type":"text"},
            {"name":"manager_name","label":"담당자","type":"text"},
            {"name":"manager_phone","label":"연락처","type":"text"},
            {"name":"note","label":"비고","type":"textarea"}]
    return render_form(request,"상세현장 추가",fields,"/site_locations/new")

@app.post("/site_locations/new")
def site_locations_new_submit(request: Request, db: OrmSession = Depends(get_db),
                              site_id: int = Form(...), name: str = Form(...),
                              address: Optional[str] = Form(None), manager_name: Optional[str] = Form(None),
                              manager_phone: Optional[str] = Form(None), note: Optional[str] = Form(None)):
    require_login(request)
    db.add(SiteLocation(site_id=site_id, name=name.strip(), address=address, manager_name=manager_name, manager_phone=manager_phone, note=note)); db.commit()
    return RedirectResponse(url="/site_locations", status_code=HTTP_302_FOUND)

@app.get("/site_locations/edit/{lid}", response_class=HTMLResponse)
def site_locations_edit(request: Request, lid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    l = db.get(SiteLocation, lid); assert l
    fields=[{"name":"site_id","label":"현장","type":"select","options":[(None,"")] + options_sites(db),"value":l.site_id},
            {"name":"name","label":"이름","type":"text","required":True,"value":l.name},
            {"name":"address","label":"주소","type":"text","value":l.address or ""},
            {"name":"manager_name","label":"담당자","type":"text","value":l.manager_name or ""},
            {"name":"manager_phone","label":"연락처","type":"text","value":l.manager_phone or ""},
            {"name":"note","label":"비고","type":"textarea","value":l.note or ""}]
    return render_form(request,"상세현장 수정",fields,f"/site_locations/edit/{lid}")

@app.post("/site_locations/edit/{lid}")
def site_locations_edit_submit(request: Request, lid: int, db: OrmSession = Depends(get_db),
                               site_id: int = Form(...), name: str = Form(...),
                               address: Optional[str] = Form(None), manager_name: Optional[str] = Form(None),
                               manager_phone: Optional[str] = Form(None), note: Optional[str] = Form(None)):
    require_login(request)
    l = db.get(SiteLocation, lid); assert l
    l.site_id=site_id; l.name=name.strip(); l.address=address; l.manager_name=manager_name; l.manager_phone=manager_phone; l.note=note
    db.commit()
    return RedirectResponse(url="/site_locations", status_code=HTTP_302_FOUND)

@app.post("/site_locations/delete/{lid}")
def site_locations_delete(request: Request, lid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    l = db.get(SiteLocation, lid)
    if l: db.delete(l); db.commit()
    return RedirectResponse(url="/site_locations", status_code=HTTP_302_FOUND)


# ------------------------------------------------------------------------------
# CS: 요청 / 일정 (기본 정렬: ID DESC)
# ------------------------------------------------------------------------------
@app.get("/cs_requests", response_class=HTMLResponse)
def cs_requests_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    q = db.query(CSRequest).outerjoin(Site)
    rows=[[r.request_id, r.requester_name, (r.site.name if r.site else ""), r.status, r.created_at]
          for r in q.order_by(CSRequest.request_id.desc()).all()]
    return render_list(request,"CS 요청",["ID","요청자","현장","상태","생성"],rows,{
        "new":"/cs_requests/new","edit":"/cs_requests/edit/{id}","delete":"/cs_requests/delete/{id}"
    })

@app.get("/cs_requests/new", response_class=HTMLResponse)
def cs_requests_new(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    fields=[{"name":"site_id","label":"현장","type":"select", "search_inline": True, "options":[(None,"")] + options_sites(db),"nullable":True},
            {"name":"requester_name","label":"요청자","type":"text","required":True},
            {"name":"content","label":"요청 내용","type":"textarea","required":True},
            {"name":"status","label":"상태","type":"select","options":[("requested","requested"),("accepted","accepted"),("rejected","rejected"),("scheduled","scheduled")]},
            {"name":"locations","label":"상세현장(복수)","type":"multiselect","options":options_site_locations(db)}]
    return render_form(request,"CS 요청 등록",fields,"/cs_requests/new")

@app.post("/cs_requests/new")
def cs_requests_new_submit(
    request: Request, db: OrmSession = Depends(get_db),
    site_id: Optional[int] = Form(None), requester_name: str = Form(...),
    content: str = Form(...), status: str = Form("requested"), locations: Optional[List[int]] = Form(None)
):
    require_login(request)
    r = CSRequest(site_id=site_id or None, requester_name=requester_name.strip(), content=content, status=status)
    db.add(r); db.commit(); db.refresh(r)
    if locations:
        if isinstance(locations, str): locations = [locations]
        for lid in locations:
            db.add(CSRequestLocation(request_id=r.request_id, location_id=int(lid)))
        db.commit()
    return RedirectResponse(url="/cs_requests", status_code=HTTP_302_FOUND)

@app.get("/cs_requests/edit/{rid}", response_class=HTMLResponse)
def cs_requests_edit(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(CSRequest, rid); assert r
    curr = [rl.location_id for rl in r.req_locations]
    fields=[{"name":"site_id","label":"현장","type":"select","search_inline": True,"options":[(None,"")] + options_sites(db),"value":r.site_id or ""},
            {"name":"requester_name","label":"요청자","type":"text","required":True,"value":r.requester_name},
            {"name":"content","label":"요청 내용","type":"textarea","required":True,"value":r.content},
            {"name":"status","label":"상태","type":"select","options":[("requested","requested"),("accepted","accepted"),("rejected","rejected"),("scheduled","scheduled")],"value":r.status},
            {"name":"locations","label":"상세현장(복수)","type":"multiselect","options":options_site_locations(db),"value":curr}]
    return render_form(request,"CS 요청 수정",fields,f"/cs_requests/edit/{rid}")

@app.post("/cs_requests/edit/{rid}")
def cs_requests_edit_submit(
    request: Request, rid: int, db: OrmSession = Depends(get_db),
    site_id: Optional[int] = Form(None), requester_name: str = Form(...),
    content: str = Form(...), status: str = Form("requested"), locations: Optional[List[int]] = Form(None)
):
    require_login(request)
    r = db.get(CSRequest, rid); assert r
    r.site_id=site_id or None; r.requester_name=requester_name.strip(); r.content=content; r.status=status
    db.query(CSRequestLocation).filter(CSRequestLocation.request_id==rid).delete()
    if locations:
        if isinstance(locations, str): locations = [locations]
        for lid in locations:
            db.add(CSRequestLocation(request_id=rid, location_id=int(lid)))
    db.commit()
    return RedirectResponse(url="/cs_requests", status_code=HTTP_302_FOUND)

@app.post("/cs_requests/delete/{rid}")
def cs_requests_delete(request: Request, rid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    r = db.get(CSRequest, rid)
    if r: db.delete(r); db.commit()
    return RedirectResponse(url="/cs_requests", status_code=HTTP_302_FOUND)


@app.get("/cs_schedules", response_class=HTMLResponse)
def cs_schedules_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    q = db.query(CSSchedule).outerjoin(Site)
    rows=[]
    for s in q.order_by(CSSchedule.schedule_id.desc()).all():
        assignees = ", ".join([a.employee.name for a in s.sch_assignees])
        rows.append([s.schedule_id, (s.site.name if s.site else ""), s.start_date, s.end_date or "", s.status, assignees])
    return render_list(request,"CS 일정",["ID","현장","시작","종료","상태","담당자"],rows,{
        "new":"/cs_schedules/new","edit":"/cs_schedules/edit/{id}","delete":"/cs_schedules/delete/{id}"
    })

@app.get("/cs_schedules/new", response_class=HTMLResponse)
def cs_schedules_new(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    fields=[{"name":"request_id","label":"요청ID","type":"select","search_inline": True,
             "options":[(None,"")] + [(r.request_id, f"{r.request_id}: {r.requester_name}") for r in db.query(CSRequest).order_by(CSRequest.request_id.desc()).all()],"nullable":True},
            {"name":"site_id","label":"현장","type":"select","search_inline": True,"options":[(None,"")] + options_sites(db),"nullable":True},
            {"name":"start_date","label":"시작일","type":"date","required":True,"value":date.today().isoformat()},
            {"name":"end_date","label":"종료일","type":"date"},
            {"name":"request_content","label":"요청 요약","type":"textarea"},
            {"name":"work_content","label":"작업 내용","type":"textarea"},
            {"name":"extra_content","label":"추가 내용","type":"textarea"},
            {"name":"status","label":"상태","type":"select","options":[("todo","todo"),("in_progress","in_progress"),("done","done"),("lab_request","lab_request")]},
            {"name":"note","label":"비고","type":"textarea"},
            {"name":"color","label":"표시 색상","type":"color","value":"#3b82f6"},
            {"name":"locations","label":"상세현장(복수)","type":"multiselect","options":options_site_locations(db)},
            {"name":"assignees","label":"담당자(복수)","type":"multiselect","options":options_employees(db)}]
    return render_form(request,"CS 일정 등록",fields,"/cs_schedules/new")

@app.post("/cs_schedules/new")
def cs_schedules_new_submit(
    request: Request, db: OrmSession = Depends(get_db),
    request_id: Optional[str] = Form(None),
    site_id:    Optional[str] = Form(None),
    start_date: str = Form(...),
    end_date:   Optional[str] = Form(None),
    request_content: Optional[str] = Form(None),
    work_content:    Optional[str] = Form(None),
    extra_content:   Optional[str] = Form(None),
    status: str = Form("todo"),
    note:   Optional[str] = Form(None),
    color: Optional[str] = Form(None),
    locations: Optional[List[int]] = Form(None),
    assignees: Optional[List[int]] = Form(None),
):
    require_login(request)

    # 빈 문자열을 None으로 변환
    request_id_i = _to_int_or_none(request_id)
    site_id_i    = _to_int_or_none(site_id)

    # color를 빈값을 받으면 기본색
    color_val = (color or "").strip() or default_color(status)

    s = CSSchedule(
        request_id=request_id_i,
        site_id=site_id_i,
        start_date=start_date,
        end_date=end_date or None,
        request_content=request_content,
        work_content=work_content,
        extra_content=extra_content,
        status=status,
        note=note,
        color=color_val
    )
    db.add(s); db.commit(); db.refresh(s)

    # 다중 선택들 처리
    if locations:
        if isinstance(locations, str):  # 단일값 케이스 방어
            locations = [locations]
        for lid in locations:
            db.add(CSScheduleLocation(schedule_id=s.schedule_id, location_id=int(lid)))

    if assignees:
        if isinstance(assignees, str):
            assignees = [assignees]
        for eid in assignees:
            db.add(CSScheduleAssignee(schedule_id=s.schedule_id, emp_id=int(eid)))

    db.commit()
    return RedirectResponse(url="/cs_schedules", status_code=HTTP_302_FOUND)


@app.get("/cs_schedules/edit/{sid}", response_class=HTMLResponse)
def cs_schedules_edit(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(CSSchedule, sid); assert s
    cur_locs = [sl.location_id for sl in s.sch_locations]
    cur_emps = [sa.emp_id for sa in s.sch_assignees]
    fields=[{"name":"request_id","label":"요청ID","type":"select","search_inline": True,"options":[(None,"")] + [(r.request_id, f"{r.request_id}: {r.requester_name}") for r in db.query(CSRequest).order_by(CSRequest.request_id.desc()).all()],"value":s.request_id or ""},
            {"name":"site_id","label":"현장","type":"select","search_inline": True,"options":[(None,"")] + options_sites(db),"value":s.site_id or ""},
            {"name":"start_date","label":"시작일","type":"date","required":True,"value":s.start_date},
            {"name":"end_date","label":"종료일","type":"date","value":s.end_date or ""},
            {"name":"request_content","label":"요청 요약","type":"textarea","value":s.request_content or ""},
            {"name":"work_content","label":"작업 내용","type":"textarea","value":s.work_content or ""},
            {"name":"extra_content","label":"추가 내용","type":"textarea","value":s.extra_content or ""},
            {"name":"status","label":"상태","type":"select","options":[("todo","todo"),("in_progress","in_progress"),("done","done"),("lab_request","lab_request")],"value":s.status},
            {"name":"note","label":"비고","type":"textarea","value":s.note or ""},
            {"name":"color","label":"표시 색상","type":"color","value": s.color or default_color(s.status)},
            {"name":"locations","label":"상세현장(복수)","type":"multiselect","options":options_site_locations(db),"value":cur_locs},
            {"name":"assignees","label":"담당자(복수)","type":"multiselect","options":options_employees(db),"value":cur_emps}]
    return render_form(request,"CS 일정 수정",fields,f"/cs_schedules/edit/{sid}")

@app.post("/cs_schedules/edit/{sid}")
def cs_schedules_edit_submit(
    request: Request, sid: int, db: OrmSession = Depends(get_db),
    request_id: Optional[str] = Form(None),
    site_id:    Optional[str] = Form(None),
    start_date: str = Form(...),
    end_date:   Optional[str] = Form(None),
    request_content: Optional[str] = Form(None),
    work_content:    Optional[str] = Form(None),
    extra_content:   Optional[str] = Form(None),
    status: str = Form("todo"),
    note:   Optional[str] = Form(None),
    color: Optional[str] = Form(None),
    locations: Optional[List[int]] = Form(None),
    assignees: Optional[List[int]] = Form(None),
):
    require_login(request)

    request_id_i = _to_int_or_none(request_id)
    site_id_i    = _to_int_or_none(site_id)

    s = db.get(CSSchedule, sid); assert s
    s.request_id = request_id_i
    s.site_id    = site_id_i
    s.start_date = start_date
    s.end_date   = end_date or None
    s.request_content = request_content
    s.work_content    = work_content
    s.extra_content   = extra_content
    s.status = status
    s.note   = note
    s.color  = (color or "").strip() or default_color(status)

    # 다대다 갱신
    db.query(CSScheduleLocation).filter(CSScheduleLocation.schedule_id == sid).delete()
    if locations:
        if isinstance(locations, str):
            locations = [locations]
        for lid in locations:
            db.add(CSScheduleLocation(schedule_id=sid, location_id=int(lid)))

    db.query(CSScheduleAssignee).filter(CSScheduleAssignee.schedule_id == sid).delete()
    if assignees:
        if isinstance(assignees, str):
            assignees = [assignees]
        for eid in assignees:
            db.add(CSScheduleAssignee(schedule_id=sid, emp_id=int(eid)))

    db.commit()
    return RedirectResponse(url="/cs_schedules", status_code=HTTP_302_FOUND)


@app.post("/cs_schedules/delete/{sid}")
def cs_schedules_delete(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(CSSchedule, sid)
    if s: db.delete(s); db.commit()
    return RedirectResponse(url="/cs_schedules", status_code=HTTP_302_FOUND)


# ------------------------------------------------------------------------------
# 제품: SW / 서비스 (기본 정렬: ID ASC)
# ------------------------------------------------------------------------------
@app.get("/sw_products", response_class=HTMLResponse)
def sw_products_list(request: Request, db: OrmSession = Depends(get_db)):
    require_login(request)
    rows=[[p.sw_id,p.sw_code or "",p.sw_name,p.unit or "",p.price_wons,p.status,p.created_at]
          for p in db.query(SWProduct).order_by(SWProduct.sw_id.asc()).all()]
    return render_list(request,"SW 제품",["ID","코드","제품명","단위","가격(원)","상태","생성"],rows,{
        "new":"/sw_products/new","edit":"/sw_products/edit/{id}","delete":"/sw_products/delete/{id}","child":"/sw_services?sw_id={id}"
    })

@app.get("/sw_products/new", response_class=HTMLResponse)
def sw_products_new(request: Request):
    require_login(request)
    fields=[{"name":"sw_code","label":"제품코드","type":"text"},
            {"name":"sw_name","label":"제품명","type":"text","required":True},
            {"name":"unit","label":"단위","type":"text"},
            {"name":"sw_func","label":"기능설명","type":"textarea"},
            {"name":"price_wons","label":"가격(원)","type":"number","value":0},
            {"name":"status","label":"상태","type":"select","options":[("active","active"),("inactive","inactive"),("archived","archived")]}]
    return render_form(request,"SW 제품 추가",fields,"/sw_products/new")

@app.post("/sw_products/new")
def sw_products_new_submit(request: Request, db: OrmSession = Depends(get_db),
                           sw_code: Optional[str] = Form(None),
                           sw_name: str = Form(...), unit: Optional[str] = Form(None),
                           sw_func: Optional[str] = Form(None), price_wons: int = Form(0),
                           status: str = Form("active")):
    require_login(request)
    db.add(SWProduct(sw_code=(sw_code.strip() if sw_code else None),
                     sw_name=sw_name.strip(), unit=(unit or None), sw_func=sw_func,
                     price_wons=price_wons, status=status)); db.commit()
    return RedirectResponse(url="/sw_products", status_code=HTTP_302_FOUND)

@app.get("/sw_products/edit/{pid}", response_class=HTMLResponse)
def sw_products_edit(request: Request, pid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    p = db.get(SWProduct, pid); assert p
    fields=[{"name":"sw_code","label":"제품코드","type":"text","value":p.sw_code or ""},
            {"name":"sw_name","label":"제품명","type":"text","required":True,"value":p.sw_name},
            {"name":"unit","label":"단위","type":"text","value":p.unit or ""},
            {"name":"sw_func","label":"기능설명","type":"textarea","value":p.sw_func or ""},
            {"name":"price_wons","label":"가격(원)","type":"number","value":p.price_wons},
            {"name":"status","label":"상태","type":"select","options":[("active","active"),("inactive","inactive"),("archived","archived")],"value":p.status}]
    return render_form(request,"SW 제품 수정",fields,f"/sw_products/edit/{pid}")

@app.post("/sw_products/edit/{pid}")
def sw_products_edit_submit(request: Request, pid: int, db: OrmSession = Depends(get_db),
                            sw_code: Optional[str] = Form(None),
                            sw_name: str = Form(...), unit: Optional[str] = Form(None),
                            sw_func: Optional[str] = Form(None), price_wons: int = Form(0),
                            status: str = Form("active")):
    require_login(request)
    p = db.get(SWProduct, pid); assert p
    p.sw_code=(sw_code.strip() if sw_code else None); p.sw_name=sw_name.strip()
    p.unit=(unit or None); p.sw_func=sw_func; p.price_wons=price_wons; p.status=status
    db.commit()
    return RedirectResponse(url="/sw_products", status_code=HTTP_302_FOUND)

@app.post("/sw_products/delete/{pid}")
def sw_products_delete(request: Request, pid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    p = db.get(SWProduct, pid)
    if p: db.delete(p); db.commit()
    return RedirectResponse(url="/sw_products", status_code=HTTP_302_FOUND)


@app.get("/sw_services", response_class=HTMLResponse)
def sw_services_list(request: Request, db: OrmSession = Depends(get_db), sw_id: Optional[int] = None):
    require_login(request)
    q = db.query(SWService).join(SWProduct)
    if sw_id: q = q.filter(SWService.sw_id == sw_id)
    rows=[[s.sv_id, s.product.sw_name, s.sv_code, s.sv_name, s.sv_type, s.price_wons, s.status]
          for s in q.order_by(SWService.sv_id.asc()).all()]
    headers = [
        "ID",
        {"label": "제품", "align": "center", "bold": True},
        {"label": "서비스코드", "align": "center"},
        {"label": "서비스명", "align": "center", "bold":True},
        {"label": "유형", "align": "center"},
        {"label": "가격(원)",   "align": "right",  "bold": True, "format": "money"},
        {"label": "상태", "align": "center"},
    ]
    return render_list(request,"서비스",["ID","제품","서비스코드","서비스명","유형","가격(원)","상태"],rows,{
        "new":"/sw_services/new","edit":"/sw_services/edit/{id}","delete":"/sw_services/delete/{id}"
    })

@app.get("/sw_services/new", response_class=HTMLResponse)
def sw_services_new(request: Request, db: OrmSession = Depends(get_db), sw_id: Optional[int] = None):
    require_login(request)
    fields=[{"name":"sw_id","label":"제품","type":"select","options":options_sw_products(db),"value":sw_id or ""},
            {"name":"sv_code","label":"서비스코드","type":"text","required":True},
            {"name":"sv_name","label":"서비스명","type":"text","required":True},
            {"name":"sv_type","label":"유형","type":"select","options":[("A","A"),("B","B"),("C","C")]},
            {"name":"price_wons","label":"가격(원)","type":"number","value":0},
            {"name":"status","label":"상태","type":"select","options":[("active","active"),("inactive","inactive"),("archived","archived")]}]
    return render_form(request,"서비스 추가",fields,"/sw_services/new")

@app.post("/sw_services/new")
def sw_services_new_submit(request: Request, db: OrmSession = Depends(get_db),
                           sw_id: int = Form(...), sv_code: str = Form(...),
                           sv_name: str = Form(...), sv_type: str = Form("A"),
                           price_wons: int = Form(0), status: str = Form("active")):
    require_login(request)
    db.add(SWService(sw_id=sw_id, sv_code=sv_code.strip(), sv_name=sv_name.strip(),
                     sv_type=sv_type, price_wons=price_wons, status=status)); db.commit()
    return RedirectResponse(url="/sw_services", status_code=HTTP_302_FOUND)

@app.get("/sw_services/edit/{sid}", response_class=HTMLResponse)
def sw_services_edit(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(SWService, sid); assert s
    fields=[{"name":"sw_id","label":"제품","type":"select","options":options_sw_products(db),"value":s.sw_id},
            {"name":"sv_code","label":"서비스코드","type":"text","required":True,"value":s.sv_code},
            {"name":"sv_name","label":"서비스명","type":"text","required":True,"value":s.sv_name},
            {"name":"sv_type","label":"유형","type":"select","options":[("A","A"),("B","B"),("C","C")],"value":s.sv_type},
            {"name":"price_wons","label":"가격(원)","type":"number","value":s.price_wons},
            {"name":"status","label":"상태","type":"select","options":[("active","active"),("inactive","inactive"),("archived","archived")],"value":s.status}]
    return render_form(request,"서비스 수정",fields,f"/sw_services/edit/{sid}")

@app.post("/sw_services/edit/{sid}")
def sw_services_edit_submit(request: Request, sid: int, db: OrmSession = Depends(get_db),
                            sw_id: int = Form(...), sv_code: str = Form(...),
                            sv_name: str = Form(...), sv_type: str = Form("A"),
                            price_wons: int = Form(0), status: str = Form("active")):
    require_login(request)
    s = db.get(SWService, sid); assert s
    s.sw_id=sw_id; s.sv_code=sv_code.strip(); s.sv_name=sv_name.strip()
    s.sv_type=sv_type; s.price_wons=price_wons; s.status=status
    db.commit()
    return RedirectResponse(url="/sw_services", status_code=HTTP_302_FOUND)

@app.post("/sw_services/delete/{sid}")
def sw_services_delete(request: Request, sid: int, db: OrmSession = Depends(get_db)):
    require_login(request)
    s = db.get(SWService, sid)
    if s: db.delete(s); db.commit()
    return RedirectResponse(url="/sw_services", status_code=HTTP_302_FOUND)


# ------------------------------------------------------------------------------
# 헬스체크
# ------------------------------------------------------------------------------
@app.get("/healthz")
def healthz(db: OrmSession = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ------------------------------------------------------------------------------
# 실행
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
