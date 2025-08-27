# app.py
from __future__ import annotations
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route as StarletteRoute
import sqlite3, os, hashlib, secrets, datetime as dt
from typing import Optional, List, Dict, Any

# -----------------------------------------------------------------------------
# 기본 설정
# -----------------------------------------------------------------------------
app = FastAPI(title="TechSupport (New DB)")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "app.db")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

# -----------------------------------------------------------------------------
# 유틸
# -----------------------------------------------------------------------------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # 모든 연결에서 FK 강제
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now_local() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def has_table(cur: sqlite3.Cursor, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None

def get_session_dict(request: Request) -> Dict[str, Any]:
    # request.session을 직접 건드리면 SessionMiddleware 없을 때 assert가 터짐
    s = request.scope.get("session")
    return s if isinstance(s, dict) else {}

def verify_password(plain: str, pw_hash: str, pw_salt: Optional[str]) -> bool:
    """
    pw_hash가 bcrypt 형태($2...)면 bcrypt로 검증(설치 시),
    그 외에는 sha256(salt+password) 또는 sha256(password)로 검증
    """
    if not pw_hash:
        return False
    try:
        if pw_hash.startswith("$2"):  # bcrypt
            import bcrypt  # optional
            return bcrypt.checkpw(plain.encode(), pw_hash.encode())
    except Exception:
        # bcrypt 미설치/에러 → 아래 sha256로 폴백
        pass

    if pw_salt:
        return sha256_hex(pw_salt + plain) == pw_hash
    else:
        return sha256_hex(plain) == pw_hash

# -----------------------------------------------------------------------------
# 초기 시드 (DB 스키마는 이미 제공된 SQL로 만들었다고 가정)
# 직원/권한/로그인 정보가 전혀 없으면 최소 관리자 계정 생성
# -----------------------------------------------------------------------------
def seed_minimum():
    conn = db()
    cur = conn.cursor()

    # 필요한 핵심 테이블 존재 확인
    needed = ["departments", "job_ranks", "roles", "employees", "employee_roles", "employee_auth"]
    if not all(has_table(cur, t) for t in needed):
        conn.close()
        return  # 스키마 미구성 상태 → 아무것도 하지 않음

    # 직원/계정이 하나도 없으면 시드
    cur.execute("SELECT COUNT(*) FROM employees")
    emp_count = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM employee_auth")
    auth_count = cur.fetchone()[0] or 0

    if emp_count == 0 and auth_count == 0:
        # 1) 부서 HQ
        cur.execute("INSERT INTO departments(dept_code, name, status) VALUES (?,?,?)",
                    ("HQ", "본사", "active"))
        cur.execute("SELECT dept_id FROM departments WHERE dept_code='HQ'")
        dept_id = cur.fetchone()[0]

        # 2) 직급/권한
        cur.execute("INSERT INTO job_ranks(rank_code, name) VALUES (?,?)", ("ADMIN", "관리자"))
        cur.execute("SELECT rank_id FROM job_ranks WHERE rank_code='ADMIN'")
        rank_id = cur.fetchone()[0]

        # roles: ADMIN / MANAGER / STAFF
        for code, nm in [("ADMIN", "관리자"), ("MANAGER", "매니저"), ("STAFF", "직원")]:
            cur.execute("INSERT OR IGNORE INTO roles(role_code, name) VALUES (?,?)", (code, nm))

        # 3) 직원 / 로그인
        cur.execute("""
            INSERT INTO employees(name, dept_id, rank_id, status)
            VALUES (?,?,?, 'active')
        """, ("관리자", dept_id, rank_id))
        cur.execute("SELECT emp_id FROM employees WHERE name='관리자' ORDER BY emp_id DESC LIMIT 1")
        emp_id = cur.fetchone()[0]

        # 직원 권한: ADMIN 부여
        cur.execute("SELECT role_id FROM roles WHERE role_code='ADMIN'")
        role_id = cur.fetchone()[0]
        cur.execute("INSERT INTO employee_roles(emp_id, role_id) VALUES (?,?)", (emp_id, role_id))

        # 로그인 생성 (sha256(salt+password))
        salt = secrets.token_hex(8)
        password = "admin123!"
        pw_hash = sha256_hex(salt + password)
        cur.execute("""
            INSERT INTO employee_auth(emp_id, login_id, pw_hash, pw_salt)
            VALUES (?,?,?,?)
        """, (emp_id, "admin", pw_hash, salt))

        conn.commit()

    conn.close()

seed_minimum()

# -----------------------------------------------------------------------------
# 세션 미들웨어
# -----------------------------------------------------------------------------
app.add_middleware(
    SessionMiddleware,
    secret_key="CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_please-2025",
    same_site="lax",
    https_only=False,
    max_age=60 * 60 * 8,  # 8h
)

# -----------------------------------------------------------------------------
# 인증 가드 미들웨어 (템플릿/정적/로그인 등 허용 경로 제외)
#  - request.scope['session']만 사용해 SessionMiddleware 유무에도 안전
# -----------------------------------------------------------------------------
class AuthGuardMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, open_exact: tuple[str, ...], open_prefix: tuple[str, ...]):
        super().__init__(app)
        self.open_exact = open_exact
        self.open_prefix = open_prefix

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 화이트리스트
        if path in self.open_exact or any(path.startswith(p) for p in self.open_prefix):
            return await call_next(request)

        s = get_session_dict(request)
        if s.get("emp_id"):
            return await call_next(request)

        return RedirectResponse("/login", status_code=303)

app.add_middleware(
    AuthGuardMiddleware,
    open_exact=("/login", "/logout", "/favicon.ico", "/_routes", "/_whoami"),
    open_prefix=("/static", "/uploads", "/docs", "/redoc", "/openapi.json"),
)

# -----------------------------------------------------------------------------
# 작은 헬퍼: 현재 사용자
# -----------------------------------------------------------------------------
def current_user(request: Request) -> Optional[Dict[str, Any]]:
    s = get_session_dict(request)
    if s.get("emp_id"):
        return {
            "emp_id": s.get("emp_id"),
            "name": s.get("emp_name"),
            "dept_id": s.get("dept_id"),
            "roles": s.get("roles", []),
            "login_id": s.get("login_id"),
        }
    return None

def require_role(request: Request, allowed: List[str]) -> Optional[Response]:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    user_roles = set(user.get("roles", []))
    if not user_roles.intersection(set(allowed)):
        return HTMLResponse("<h3>권한이 없습니다.</h3>", status_code=403)
    return None

# -----------------------------------------------------------------------------
# 뷰: 로그인/로그아웃
# -----------------------------------------------------------------------------
def render_login(request: Request, error: str = "") -> HTMLResponse:
    # templates/login.html 있으면 그걸 사용
    try:
        return templates.TemplateResponse("login.html", {"request": request, "error": error})
    except Exception:
        # 폴백 간단 페이지
        html = f"""
        <html><head><meta charset="utf-8"><title>로그인</title>
        <style>
        body{{font-family:ui-sans-serif,system-ui,Apple SD Gothic Neo,Malgun Gothic}}
        .card{{max-width:420px;margin:64px auto;padding:16px;border:1px solid #e5e7eb;border-radius:12px}}
        label{{display:block;margin:.25rem 0 .25rem}}
        input{{width:100%;padding:.5rem;border:1px solid #e5e7eb;border-radius:8px}}
        .err{{margin:.5rem 0;color:#dc2626}}
        button{{padding:.5rem .8rem;border-radius:8px;border:1px solid #e5e7eb;background:#111827;color:#fff}}
        </style></head><body>
        <div class="card">
          <h2 style="margin:0 0 .75rem">로그인</h2>
          {"<div class='err'>"+error+"</div>" if error else ""}
          <form method="post" action="/login">
            <label>아이디</label>
            <input type="text" name="login_id" required>
            <label style="margin-top:.5rem">비밀번호</label>
            <input type="password" name="password" required>
            <div style="margin-top:.75rem"><button type="submit">로그인</button></div>
          </form>
        </div>
        </body></html>
        """
        return HTMLResponse(html)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render_login(request)

@app.post("/login")
def login_submit(
    request: Request,
    login_id: str = Form(...),
    password: str = Form(...),
):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT a.auth_id, a.emp_id, a.login_id, a.pw_hash, a.pw_salt,
               e.name AS emp_name, e.dept_id
          FROM employee_auth a
          JOIN employees e ON e.emp_id = a.emp_id
         WHERE a.login_id = ?
    """, (login_id.strip(),))
    row = cur.fetchone()

    if not row:
        conn.close()
        return render_login(request, "아이디 또는 비밀번호가 올바르지 않습니다.")

    if not verify_password(password, row["pw_hash"], row["pw_salt"]):
        conn.close()
        return render_login(request, "아이디 또는 비밀번호가 올바르지 않습니다.")

    # 역할 목록
    cur.execute("""
        SELECT r.role_code
          FROM employee_roles er
          JOIN roles r ON r.role_id = er.role_id
         WHERE er.emp_id = ?
    """, (row["emp_id"],))
    roles = [r[0] for r in cur.fetchall()]
    conn.close()

    # 세션 세팅
    request.session.clear()
    request.session["emp_id"]   = row["emp_id"]
    request.session["emp_name"] = row["emp_name"]
    request.session["dept_id"]  = row["dept_id"]
    request.session["login_id"] = row["login_id"]
    request.session["roles"]    = roles

    return RedirectResponse("/schedules", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

# -----------------------------------------------------------------------------
# 디버그
# -----------------------------------------------------------------------------
@app.get("/_routes")
def show_routes():
    out = []
    for r in app.router.routes:
        if isinstance(r, StarletteRoute):
            methods = sorted((r.methods or set()) - {'HEAD', 'OPTIONS'})
            out.append({"path": r.path, "methods": methods})
    return JSONResponse(out)

@app.get("/_whoami")
def whoami(request: Request):
    return JSONResponse(get_session_dict(request))

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

# -----------------------------------------------------------------------------
# 홈 → 일정
# -----------------------------------------------------------------------------
@app.get("/")
def home():
    return RedirectResponse("/schedules", status_code=303)

# -----------------------------------------------------------------------------
# 부서 목록 (읽기 전용)
# -----------------------------------------------------------------------------
@app.get("/departments", response_class=HTMLResponse)
def departments_page(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT d.dept_id, d.dept_code, d.name,
               p.name AS parent_name, d.status, d.created_at, d.updated_at
          FROM departments d
          LEFT JOIN departments p ON p.dept_id = d.parent_id
         WHERE d.deleted_at IS NULL
         ORDER BY COALESCE(p.name, d.name), d.name
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # 템플릿 있으면 사용
    try:
        return templates.TemplateResponse("departments_list.html", {"request": request, "items": rows})
    except Exception:
        # 폴백
        body = "<h2>부서</h2><table border=1 cellpadding=6><tr><th>ID</th><th>CODE</th><th>이름</th><th>상위</th><th>상태</th></tr>"
        for r in rows:
            body += f"<tr><td>{r['dept_id']}</td><td>{r['dept_code']}</td><td>{r['name']}</td><td>{r.get('parent_name') or ''}</td><td>{r['status']}</td></tr>"
        body += "</table>"
        return HTMLResponse(f"<html><body style='font-family:sans-serif'>{body}</body></html>")

# -----------------------------------------------------------------------------
# 현장 목록 (새 스키마: sites)
# -----------------------------------------------------------------------------
@app.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request):
    conn = db(); cur = conn.cursor()
    cur.execute("""
        SELECT site_id, name, camera_count, nrs_count, note, created_at, updated_at
          FROM sites
         WHERE deleted_at IS NULL
         ORDER BY name
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    try:
        return templates.TemplateResponse("sites_list.html", {"request": request, "items": rows})
    except Exception:
        body = "<h2>현장</h2><table border=1 cellpadding=6><tr><th>ID</th><th>이름</th><th>카메라</th><th>NRS</th><th>비고</th></tr>"
        for r in rows:
            body += f"<tr><td>{r['site_id']}</td><td>{r['name']}</td><td>{r['camera_count']}</td><td>{r['nrs_count']}</td><td>{r.get('note','') or ''}</td></tr>"
        body += "</table>"
        return HTMLResponse(f"<html><body style='font-family:sans-serif'>{body}</body></html>")

# -----------------------------------------------------------------------------
# 일정(= cs_schedules) 리스트 + API
# -----------------------------------------------------------------------------
@app.get("/schedules", response_class=HTMLResponse)
def schedules_page(request: Request,
                   fdate: Optional[str] = None,
                   tdate: Optional[str] = None,
                   status: Optional[str] = None,
                   site_id: Optional[int] = None,
                   assignee_emp_id: Optional[int] = None):
    # 단순 목록 화면 (템플릿 없으면 폴백)
    try:
        return templates.TemplateResponse("schedules.html", {"request": request})
    except Exception:
        # 폴백 화면은 API 링크와 간단 설명만
        html = """
        <html><head><meta charset="utf-8"><title>CS 일정</title></head>
        <body style="font-family:sans-serif">
          <h2>CS 일정</h2>
          <p>프런트 템플릿이 없어서 간단 화면만 보여줍니다.</p>
          <p><a href="/api/schedules">/api/schedules</a> 에서 JSON을 확인하세요.</p>
        </body></html>
        """
        return HTMLResponse(html)

@app.get("/api/schedules")
def api_schedules(
    fdate: Optional[str] = None,   # YYYY-MM-DD
    tdate: Optional[str] = None,   # YYYY-MM-DD
    status: Optional[str] = None,  # todo|in_progress|done|lab_request
    site_id: Optional[int] = None,
    assignee_emp_id: Optional[int] = None,
):
    conn = db(); cur = conn.cursor()

    where = []
    args: List[Any] = []

    if fdate:
        where.append("date(s.start_date) >= date(?)")
        args.append(fdate)
    if tdate:
        where.append("(s.end_date IS NULL OR date(s.end_date) <= date(?))")
        args.append(tdate)
    if status:
        where.append("s.status = ?")
        args.append(status)
    if site_id:
        where.append("s.site_id = ?")
        args.append(site_id)
    if assignee_emp_id:
        where.append("""
            s.schedule_id IN (
              SELECT schedule_id FROM cs_schedule_assignees WHERE emp_id = ?
            )
        """)
        args.append(assignee_emp_id)

    sql = """
        SELECT s.schedule_id, s.request_id, s.start_date, s.end_date,
               s.site_id, si.name AS site_name,
               s.request_content, s.work_content, s.extra_content,
               s.status, s.note, s.created_at, s.updated_at,
               (SELECT COUNT(*) FROM cs_schedule_assignees a
                 WHERE a.schedule_id = s.schedule_id) AS assignee_count
          FROM cs_schedules s
          LEFT JOIN sites si ON si.site_id = s.site_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY date(s.start_date) DESC, s.schedule_id DESC"

    cur.execute(sql, args)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return JSONResponse(rows)

# -----------------------------------------------------------------------------
# 간단한 '권한 필요' 예시 엔드포인트 (ADMIN만)
# -----------------------------------------------------------------------------
@app.get("/admin/ping")
def admin_ping(request: Request):
    deny = require_role(request, ["ADMIN"])
    if deny:
        return deny
    return PlainTextResponse("pong (admin)")

# -----------------------------------------------------------------------------
# 앱 시작 안내
# -----------------------------------------------------------------------------
@app.on_event("startup")
def _startup_banner():
    print("✅ App started. Try:")
    print("  - http://localhost:8000/login  (admin / admin123!)")
    print("  - http://localhost:8000/_routes")
    print("  - http://localhost:8000/_whoami")
