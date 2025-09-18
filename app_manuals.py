# app_manuals.py — 매뉴얼 업로드/목록/다운로드/삭제/ZIP 내보내기
import os
import io
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Request, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_302_FOUND

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, func, select, or_
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session as OrmSession

# (중요) 로그인/권한 가드: 기존 프로젝트 헬퍼 재사용
from auth_utils import require_login, require_tech, require_master

# ------------------------------------------------------------------------------
# 기본 경로/엔진 설정 (app.py와 같은 DATABASE_URL 환경설정 재사용)
# ------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"     # 기존 템플릿 폴더
UPLOADS_ROOT = BASE_DIR / "uploads"        # app.py 가 app.mount("/uploads", StaticFiles(directory="uploads"))로 마운트함
MANUALS_DIR  = UPLOADS_ROOT / "manuals"    # 매뉴얼은 /uploads/manuals/에 보관

MANUALS_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/naiz.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    future=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_db() -> OrmSession:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
router = APIRouter()

# ------------------------------------------------------------------------------
# 모델
# ------------------------------------------------------------------------------
Base = declarative_base()

class ManualDoc(Base):
    __tablename__ = "manual_docs"
    id          = Column(Integer, primary_key=True)
    section     = Column(String, nullable=False)   # 예) "1.1 소개"
    title       = Column(String, nullable=False)   # 예) "도입부 이미지"
    orig_name   = Column(String, nullable=True)    # 업로드 당시 원본 파일명
    stored_rel  = Column(String, nullable=False)   # 웹 상대경로 (예: /uploads/manuals/20250918_153000_img.png)
    mime_type   = Column(String, nullable=True)
    size_bytes  = Column(Integer, nullable=True)
    note        = Column(Text, nullable=True)
    uploaded_at = Column(DateTime, nullable=False, default=func.datetime("now", "localtime"))

# 최초 로드시 테이블 생성
Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------------------
# 유틸
# ------------------------------------------------------------------------------
_filename_pat = re.compile(r'[^A-Za-z0-9._-]+')

def secure_filename(name: str) -> str:
    name = (name or "").strip().replace(" ", "_")
    name = _filename_pat.sub("", name)
    if not name:
        name = "file"
    # 확장자 보존
    if "." in name:
        base, ext = name.rsplit(".", 1)
        return f"{base}.{ext}"
    return name

def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ------------------------------------------------------------------------------
# 뷰: 목록
# ------------------------------------------------------------------------------
@router.get("/manuals", response_class=HTMLResponse)
def manuals_list(request: Request,
                 db: OrmSession = Depends(get_db),
                 section: Optional[str] = None,
                 q: Optional[str] = None):
    """매뉴얼 파일 목록 + 필터 + CSV/ZIP 내보내기 안내"""
    require_login(request)

    qset = db.query(ManualDoc)
    if section:
        qset = qset.filter(ManualDoc.section == section)
    if q:
        like = f"%{q}%"
        qset = qset.filter(or_(
            ManualDoc.section.ilike(like),
            ManualDoc.title.ilike(like),
            ManualDoc.orig_name.ilike(like),
            ManualDoc.note.ilike(like),
        ))
    items = qset.order_by(ManualDoc.id.desc()).all()

    # 간단한 테이블 템플릿(기존 generic_list를 써도 되지만, 여기선 자체 HTML로 가볍게 구성)
    html = """
    {% extends "base.html" %}
    {% block title %}매뉴얼 - NAIZ{% endblock %}
    {% block content %}
    <h1 class="mb-2">매뉴얼</h1>

    <form method="get" class="filter" style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end;">
      <div>
        <label>섹션</label>
        <input type="text" name="section" value="{{ section or '' }}" placeholder='예: 1.1 소개'>
      </div>
      <div>
        <label>검색</label>
        <input type="text" name="q" value="{{ q or '' }}" placeholder="제목/원본명/메모 검색">
      </div>
      <div>
        <button class="btn btn-outline" type="submit">적용</button>
        <a class="btn" href="/manuals">초기화</a>
        <a class="btn primary" href="/manuals/new">+ 업로드</a>
        <a class="btn" href="/manuals/export.zip{% if section or q %}?{{ 'section=' ~ section if section }}{% if section and q %}&{% endif %}{{ 'q=' ~ q if q }}{% endif %}">ZIP로 내보내기</a>
      </div>
    </form>

    <div class="card" style="margin-top:12px;">
      <div class="card-body" style="overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th style="width:70px;text-align:center;">ID</th>
              <th>섹션</th>
              <th>제목</th>
              <th>원본파일</th>
              <th>미리보기/다운로드</th>
              <th style="width:100px;text-align:center;">크기</th>
              <th style="width:180px;">업로드</th>
              <th style="width:120px;text-align:center;">작업</th>
            </tr>
          </thead>
          <tbody>
          {% for m in items %}
            <tr>
              <td style="text-align:center;">{{ m.id }}</td>
              <td>{{ m.section }}</td>
              <td>{{ m.title }}</td>
              <td>{{ m.orig_name or '' }}</td>
              <td>
                {% if m.stored_rel %}
                  <a href="{{ m.stored_rel }}" target="_blank">열기</a>
                  &nbsp;|&nbsp;
                  <a href="/manuals/file/{{ m.id }}">다운로드</a>
                {% else %}
                  -
                {% endif %}
              </td>
              <td style="text-align:right;">{{ (m.size_bytes or 0) | comma }}</td>
              <td>{{ (m.uploaded_at or '') }}</td>
              <td style="text-align:center;">
                <form method="post" action="/manuals/delete/{{ m.id }}" onsubmit="return confirm('삭제하시겠습니까?');" style="display:inline;">
                  <button class="btn" type="submit">삭제</button>
                </form>
              </td>
            </tr>
          {% endfor %}
          {% if items|length == 0 %}
            <tr><td colspan="8" style="text-align:center;color:#777;">등록된 매뉴얼이 없습니다.</td></tr>
          {% endif %}
          </tbody>
        </table>
      </div>
    </div>
    {% endblock %}
    """
    return templates.TemplateResponse(
        template_name=templates.from_string(html).template.name,
        context={"request": request, "items": items, "section": section, "q": q}
    )

# ------------------------------------------------------------------------------
# 뷰: 업로드 폼
# ------------------------------------------------------------------------------
@router.get("/manuals/new", response_class=HTMLResponse)
def manuals_new(request: Request):
    require_login(request)
    html = """
    {% extends "base.html" %}
    {% block title %}매뉴얼 업로드 - NAIZ{% endblock %}
    {% block content %}
    <h1 class="mb-2">매뉴얼 업로드</h1>
    <div class="card">
      <div class="card-body">
        <form method="post" action="/manuals/new" enctype="multipart/form-data" class="form">
          <div class="mb-2">
            <label>섹션<span style="color:#e11;">*</span></label>
            <input class="form-control" type="text" name="section" placeholder="예: 1.1 소개" required>
          </div>
          <div class="mb-2">
            <label>제목<span style="color:#e11;">*</span></label>
            <input class="form-control" type="text" name="title" placeholder="예: 도입부 이미지" required>
          </div>
          <div class="mb-2">
            <label>메모</label>
            <textarea class="form-control" name="note" rows="3" placeholder="추가 설명 (선택)"></textarea>
          </div>
          <div class="mb-2">
            <label>파일<span style="color:#e11;">*</span></label>
            <input class="form-control" type="file" name="file" accept=".png,.jpg,.jpeg,.gif,.webp,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx" required>
          </div>
          <div class="mt-2" style="display:flex;gap:8px;">
            <button class="btn btn-primary" type="submit">업로드</button>
            <a class="btn btn-outline" href="/manuals">목록</a>
          </div>
        </form>
      </div>
    </div>
    {% endblock %}
    """
    return templates.TemplateResponse(
        template_name=templates.from_string(html).template.name,
        context={"request": request}
    )

# ------------------------------------------------------------------------------
# 액션: 업로드 저장
# ------------------------------------------------------------------------------
@router.post("/manuals/new")
async def manuals_new_submit(
    request: Request,
    db: OrmSession = Depends(get_db),
    section: str = Form(...),
    title: str = Form(...),
    note: Optional[str] = Form(None),
    file: UploadFile = File(...)
):
    require_login(request)

    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="파일이 필요합니다.")

    safe = secure_filename(file.filename)
    ts   = _now_stamp()
    saved_name = f"{ts}_{safe}"
    dest = MANUALS_DIR / saved_name

    raw = await file.read()
    with open(dest, "wb") as f:
        f.write(raw)

    rel_web = f"/uploads/manuals/{saved_name}"
    m = ManualDoc(
        section=section.strip(),
        title=title.strip(),
        orig_name=file.filename,
        stored_rel=rel_web,
        mime_type=(file.content_type or None),
        size_bytes=len(raw),
        note=(note or None),
    )
    db.add(m)
    db.commit()

    return RedirectResponse(url="/manuals", status_code=HTTP_302_FOUND)

# ------------------------------------------------------------------------------
# 파일 다운로드 (원본명으로 내려주기)
# ------------------------------------------------------------------------------
@router.get("/manuals/file/{mid}", response_class=FileResponse)
def manuals_file(mid: int, db: OrmSession = Depends(get_db)):
    require_login  # 가드로 사용하려면 위에 데코레이터/미들웨어에서 처리되므로 명시적 호출은 생략

    m = db.get(ManualDoc, mid)
    if not m:
        raise HTTPException(status_code=404, detail="파일 정보를 찾을 수 없습니다.")
    if not m.stored_rel or not m.stored_rel.startswith("/uploads/manuals/"):
        raise HTTPException(status_code=400, detail="파일 경로가 올바르지 않습니다.")

    disk = BASE_DIR / m.stored_rel.lstrip("/")
    if not disk.exists():
        raise HTTPException(status_code=404, detail="디스크에 파일이 없습니다.")

    return FileResponse(
        path=str(disk),
        media_type=(m.mime_type or "application/octet-stream"),
        filename=(m.orig_name or disk.name)
    )

# ------------------------------------------------------------------------------
# 삭제 (레코드+디스크)
# ------------------------------------------------------------------------------
@router.post("/manuals/delete/{mid}")
def manuals_delete(request: Request, mid: int, db: OrmSession = Depends(get_db)):
    require_login(request)

    m = db.get(ManualDoc, mid)
    if not m:
        return RedirectResponse(url="/manuals", status_code=HTTP_302_FOUND)

    # 디스크 파일 삭제 (있을 때만)
    if m.stored_rel and m.stored_rel.startswith("/uploads/manuals/"):
        disk = BASE_DIR / m.stored_rel.lstrip("/")
        try:
            if disk.exists():
                disk.unlink()
        except Exception:
            # 파일 삭제 실패해도 DB는 진행
            pass

    db.delete(m)
    db.commit()
    return RedirectResponse(url="/manuals", status_code=HTTP_302_FOUND)

# ------------------------------------------------------------------------------
# ZIP 내보내기 (필터 적용)
# ------------------------------------------------------------------------------
@router.get("/manuals/export.zip")
def manuals_export_zip(
    request: Request,
    db: OrmSession = Depends(get_db),
    section: Optional[str] = None,
    q: Optional[str] = None
):
    require_login(request)

    qset = db.query(ManualDoc)
    if section:
        qset = qset.filter(ManualDoc.section == section)
    if q:
        like = f"%{q}%"
        qset = qset.filter(or_(
            ManualDoc.section.ilike(like),
            ManualDoc.title.ilike(like),
            ManualDoc.orig_name.ilike(like),
            ManualDoc.note.ilike(like),
        ))
    rows: List[ManualDoc] = qset.order_by(ManualDoc.id.asc()).all()
    if not rows:
        return PlainTextResponse("내보낼 파일이 없습니다.", status_code=404)

    # 메모리 ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # 인덱스 CSV 포함
        index_lines = ["id,section,title,orig_name,stored_rel,uploaded_at,size_bytes"]
        for m in rows:
            index_lines.append(
                f'{m.id},"{(m.section or "").replace("\"","\"\"")}","{(m.title or "").replace("\"","\"\"")}",'
                f'"{(m.orig_name or "").replace("\"","\"\"")}",{m.stored_rel},{m.uploaded_at},{m.size_bytes or 0}'
            )

            if m.stored_rel and m.stored_rel.startswith("/uploads/manuals/"):
                disk = BASE_DIR / m.stored_rel.lstrip("/")
                if disk.exists():
                    # ZIP 내부 경로: section/원본명(없으면 저장명)
                    inner_name = (m.orig_name or disk.name)
                    # 섹션 폴더로 정리
                    inner_path = f"{m.section or 'misc'}/{inner_name}"
                    # 동일 파일명 충돌 시 id 프리픽스
                    if inner_path in z.namelist():
                        inner_path = f"{m.section or 'misc'}/{m.id}_{inner_name}"
                    z.write(str(disk), arcname=inner_path)

        z.writestr("index.csv", "\ufeff" + "\n".join(index_lines))  # BOM 추가(엑셀 호환)

    buf.seek(0)
    fname = f"manuals_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )
