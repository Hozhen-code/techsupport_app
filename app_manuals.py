# app_manuals.py — 매뉴얼(트리/체크/첨부) + RMD→HTML 뷰어 + HTML→PDF 내보내기
from __future__ import annotations

import io
import os
import shutil
import logging
import mimetypes
import secrets
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace
from typing import List, Optional, Dict, Any

from fastapi import (
    APIRouter, Depends, Request, UploadFile, File, Form, HTTPException, Query
)
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey,
    DateTime, Boolean, func, UniqueConstraint, create_engine
)
from sqlalchemy.orm import relationship, Session, declarative_base, sessionmaker

# 권한 헬퍼
from auth_utils import require_master, require_tech, require_login

# ─────────────────────────────────────────────
# 로깅/기본 설정
# ─────────────────────────────────────────────
logger = logging.getLogger("uvicorn.error")

# ▶ DB URL을 app.py와 동일 정책으로 통일
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/naiz.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

TEMPLATES_DIR = Path("templates")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/manuals", tags=["manuals"])

# 매뉴얼 정적 자산 위치 (Rmd 렌더 결과 html, site_libs 등)
UPLOAD_ROOT = Path(os.getenv("MANUALS_DIR", "uploads/manuals")).resolve()
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

# 업로드 정책
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "150"))
ALLOWED_EXTS = set(
    x.lower() for x in os.getenv(
        "ALLOWED_MANUALS_EXTS",
        ".pdf,.png,.jpg,.jpeg,.gif,.webp,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.md"
    ).split(",")
)

# ─────────────────────────────────────────────
# DB 모델
# ─────────────────────────────────────────────
class Version(Base):
    __tablename__ = "versions"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=func.now())

class Software(Base):
    __tablename__ = "software"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=func.now())

class ManualNode(Base):
    __tablename__ = "manual_nodes"
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    parent_id = Column(Integer, ForeignKey("manual_nodes.id"), nullable=True)
    sort_order = Column(Integer, default=0)
    is_section = Column(Boolean, default=True)
    parent = relationship("ManualNode", remote_side=[id], backref="children", lazy="joined")

class ManualNodeRevision(Base):
    __tablename__ = "manual_node_revisions"
    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, ForeignKey("manual_nodes.id"), nullable=False, index=True)
    software_id = Column(Integer, ForeignKey("software.id"), nullable=False, index=True)
    version_id = Column(Integer, ForeignKey("versions.id"), nullable=False, index=True)
    checked = Column(Boolean, default=False)
    summary = Column(Text, nullable=True)
    updated_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    node = relationship("ManualNode", lazy="joined")
    software = relationship("Software", lazy="joined")
    version = relationship("Version", lazy="joined")

    __table_args__ = (UniqueConstraint("node_id", "software_id", "version_id", name="uniq_node_sw_ver"),)

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True)
    revision_id = Column(Integer, ForeignKey("manual_node_revisions.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    stored_path = Column(String, nullable=False)
    mime = Column(String)
    size = Column(Integer)
    uploaded_at = Column(DateTime, default=func.now())
    revision = relationship("ManualNodeRevision", backref="attachments", lazy="joined")

class ChangeLog(Base):
    __tablename__ = "manual_changelog"
    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, index=True)
    software_id = Column(Integer, index=True)
    version_id = Column(Integer, index=True)
    changed_by = Column(Integer, nullable=True)
    change_note = Column(Text)
    changed_at = Column(DateTime, default=func.now())

class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        # 강력 무캐시
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────
# 권한 dependency
# ─────────────────────────────────────────────
def current_user_dep(request: Request):
    require_login(request)
    u = request.session.get("user") or {}
    return SimpleNamespace(
        id=u.get("emp_id") or u.get("id") or 0,
        login_id=u.get("login_id"),
        roles=u.get("roles", []),
        name=u.get("name"),
    )

def dep_master(request: Request, user=Depends(current_user_dep)):
    require_master(request)
    return user

def dep_tech(request: Request, user=Depends(current_user_dep)):
    require_tech(request)
    return user

# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────
def _secure_under_root(p: Path) -> Path:
    p = p.resolve()
    if not str(p).startswith(str(UPLOAD_ROOT)):
        raise HTTPException(400, detail="invalid path")
    return p

def _ext_ok(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return (ext in ALLOWED_EXTS) if ALLOWED_EXTS else True

def _guess_mime(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"

def _tri_state(flags: List[bool]) -> str:
    if not flags:
        return "unchecked"
    if all(flags):
        return "checked"
    if any(flags):
        return "partial"
    return "unchecked"

# ─────────────────────────────────────────────
# 정적 마운트 + 페이지/뷰어
# ─────────────────────────────────────────────
def mount_manuals_static(app):
    app.mount(
        "/manuals_static",
        NoCacheStaticFiles(directory=str(UPLOAD_ROOT)),
        name="manuals_static",
    )

@router.get("/", response_class=HTMLResponse)
def manuals_page(request: Request, db: Session = Depends(get_db)):
    require_login(request)
    versions = db.query(Version).order_by(Version.created_at.desc()).all()
    sw = db.query(Software).order_by(Software.name).all()
    return templates.TemplateResponse(
        "manuals.html", {"request": request, "versions": versions, "software": sw}
    )

@router.get("/viewer", response_class=HTMLResponse)
def viewer_page(request: Request,
                sw: str = Query(..., description="소프트웨어명"),
                version: str = Query(..., description="버전")):
    # /uploads/manuals/<SW>/<VERSION>/index.html 확인
    html_path = UPLOAD_ROOT / sw / version / "index.html"   # ← MANUALS_DIR 오타 수정
    if not html_path.exists():
        raise HTTPException(404, f"HTML not found: {html_path}")

    iframe_src = f"/manuals_static/{sw}/{version}/index.html"
    html = """
    {% extends "base.html" %}
    {% block content %}
    <div class="container mx-auto px-4 py-4">
      <div class="flex items-center mb-3 gap-2">
        <h2 class="text-xl font-semibold">{{ sw }} ({{ version }})</h2>
        <a class="btn btn-sm" href="/manuals/export/pdf?sw={{ sw }}&version={{ version }}">PDF 내보내기</a>
      </div>
      <div class="border rounded shadow bg-white" style="height: calc(100vh - 180px);">
        <iframe src="{{ iframe_src }}" style="width:100%;height:100%;border:0;" referrerpolicy="no-referrer"></iframe>
      </div>
    </div>
    {% endblock %}
    """
    template = templates.env.from_string(html)
    return HTMLResponse(template.render({"request": request, "sw": sw, "version": version, "iframe_src": iframe_src}))


# ─────────────────────────────────────────────
# 버전/소프트웨어 API
# ─────────────────────────────────────────────
@router.get("/api/versions")
def api_versions(db: Session = Depends(get_db)):
    rows = db.query(Version).all()
    return [{"id": r.id, "name": r.name} for r in rows]

@router.get("/api/software")
def api_software(db: Session = Depends(get_db)):
    rows = db.query(Software).all()
    return [{"id": r.id, "name": r.name} for r in rows]

@router.get("/api/html_meta")
def html_meta(sw: str = Query(...), version: str = Query(...)):
    p = (UPLOAD_ROOT / sw / version / "index.html")
    if not p.exists():
        raise HTTPException(404, "index.html not found")
    return {"mtime": int(p.stat().st_mtime)}

# ─────────────────────────────────────────────
# 트리 조회/체크 저장
# ─────────────────────────────────────────────
@router.api_route("/api/tree", methods=["GET", "POST"])
async def api_tree(
    request: Request,
    db: Session = Depends(get_db),
    version_id: Optional[int] = Query(None),
    sw_ids: Optional[List[int]] = Query(None),
    q: Optional[str] = Query(None),
):
    require_login(request)

    if request.method == "POST":
        form = await request.form()
        if version_id is None and "version_id" in form:
            version_id = int(form.get("version_id"))
        if (not sw_ids) and ("sw_ids" in form):
            raw_list = form.getlist("sw_ids")
            if len(raw_list) == 1 and ("," in raw_list[0]):
                sw_ids = [int(x) for x in raw_list[0].split(",") if x]
            else:
                sw_ids = [int(x) for x in raw_list if x]
        if q is None:
            q = form.get("q")

    if not version_id or not sw_ids:
        return {"tree": []}

    revs = db.query(ManualNodeRevision).filter(
        ManualNodeRevision.version_id == version_id,
        ManualNodeRevision.software_id.in_(sw_ids),
    ).all()

    allowed_ids = {r.node_id for r in revs}

    def add_parents(nid: int):
        node = db.get(ManualNode, nid)   # ← 최신 API 사용
        while node and node.parent_id:
            allowed_ids.add(node.parent_id)
            node = node.parent

    for nid in list(allowed_ids):
        add_parents(nid)

    all_nodes = db.query(ManualNode).filter(ManualNode.id.in_(allowed_ids)).all()
    checked_map = {r.node_id: bool(r.checked) for r in revs}

    match_ids = set()
    if q:
        ql = q.lower()
        for n in all_nodes:
            if ql in (n.title or "").lower():
                match_ids.add(n.id)
                p = n.parent
                while p:
                    match_ids.add(p.id)
                    p = p.parent

    def serialize(n: ManualNode) -> Dict[str, Any]:
        kids = [
            serialize(c)
            for c in sorted(n.children, key=lambda x: (x.sort_order, x.id))
            if c.id in allowed_ids
        ]
        states = [k["state"] for k in kids]
        child_checked_flags = [s == "checked" for s in states]
        node_checked = checked_map.get(n.id, False)

        if not kids:
            state = "checked" if node_checked else "unchecked"
        else:
            if node_checked and all(child_checked_flags):
                state = "checked"
            else:
                ts = _tri_state(child_checked_flags or [node_checked])
                state = "partial" if (node_checked and ts == "unchecked") else ts

        return {
            "id": n.id,
            "title": n.title,
            "is_section": n.is_section,
            "state": state,
            "children": kids,
            "highlight": (n.id in match_ids) if q else False,
        }

    roots = [n for n in all_nodes if n.parent_id is None or n.parent_id not in allowed_ids]
    roots.sort(key=lambda x: (x.sort_order, x.id))
    tree = [serialize(r) for r in roots]
    return {"tree": tree}

@router.post("/api/check")
def api_check(
    request: Request,
    version_id: int = Form(...),
    sw_ids: str = Form(...),
    node_id: int = Form(...),
    checked: bool = Form(...),
    db: Session = Depends(get_db),
    actor: Any = Depends(dep_tech),
):
    require_login(request)
    sw_list = [int(x) for x in sw_ids.split(",") if x]

    def collect(nid: int, acc: List[int]):
        acc.append(nid)
        for c in db.query(ManualNode).filter(ManualNode.parent_id == nid).all():
            collect(c.id, acc)

    queue: List[int] = []
    collect(node_id, queue)

    for nid in queue:
        for sw in sw_list:
            rev = db.query(ManualNodeRevision).filter_by(
                node_id=nid, software_id=sw, version_id=version_id
            ).first()
            if not rev:
                rev = ManualNodeRevision(
                    node_id=nid,
                    software_id=sw,
                    version_id=version_id,
                    checked=checked,
                    updated_by=getattr(actor, "id", None),
                )
                db.add(rev)
            else:
                rev.checked = checked
                rev.updated_by = getattr(actor, "id", None)

        db.add(
            ChangeLog(
                node_id=nid,
                software_id=sw_list[0],
                version_id=version_id,
                changed_by=getattr(actor, "id", None),
                change_note=f"check={checked}",
            )
        )

    db.commit()
    return {"ok": True}

# ─────────────────────────────────────────────
# 첨부 업로드/목록/삭제/다운로드 (ID 기반만 제공)
# ─────────────────────────────────────────────
@router.post("/api/upload")
def api_upload(
    request: Request,
    version_id: int = Form(...),
    software_id: int = Form(...),
    node_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: Any = Depends(dep_tech),
):
    require_login(request)

    if not file.filename:
        raise HTTPException(400, "filename missing")
    if not _ext_ok(file.filename):
        raise HTTPException(400, f"file extension not allowed: {file.filename}")

    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"file too large (>{MAX_UPLOAD_MB}MB)")

    logger.info(f"[UPLOAD] v={version_id} sw={software_id} node={node_id} name={file.filename}")

    rev = (
        db.query(ManualNodeRevision)
        .filter_by(node_id=node_id, software_id=software_id, version_id=version_id)
        .first()
    )
    if not rev:
        rev = ManualNodeRevision(
            node_id=node_id, software_id=software_id, version_id=version_id,
            updated_by=getattr(actor, "id", None),
        )
        db.add(rev)
        db.flush()

    node_dir = UPLOAD_ROOT / f"v{version_id}_sw{software_id}" / str(node_id)
    node_dir.mkdir(parents=True, exist_ok=True)

    dest_name = file.filename
    dest_path = node_dir / dest_name
    if dest_path.exists():
        stem, ext = os.path.splitext(dest_name)
        dest_name = f"{stem}_{secrets.token_hex(4)}{ext}"
        dest_path = node_dir / dest_name

    try:
        with dest_path.open("wb") as f:
            shutil.copyfileobj(file.file, f)
        size = dest_path.stat().st_size
    except Exception as e:
        logger.exception("upload save failed")
        raise HTTPException(500, f"save failed: {e}")

    mime = file.content_type or _guess_mime(dest_name)

    att = Attachment(
        revision_id=rev.id,
        filename=dest_name,
        stored_path=str(dest_path),
        mime=mime,
        size=size,
    )
    db.add(att)
    db.commit()

    return {"ok": True, "attachment_id": att.id, "path": att.stored_path, "size": att.size}

@router.get("/api/attachments")
def list_attachments(
    version_id: int = Query(...),
    software_id: int = Query(...),
    node_id: int = Query(...),
    db: Session = Depends(get_db),
    _: Any = Depends(dep_tech),
):
    rev = (
        db.query(ManualNodeRevision)
        .filter_by(node_id=node_id, software_id=software_id, version_id=version_id)
        .first()
    )
    if not rev:
        return []
    rows = (
        db.query(Attachment)
        .filter(Attachment.revision_id == rev.id)
        .order_by(Attachment.uploaded_at.desc())
        .all()
    )
    return [
        {
            "id": a.id,
            "filename": a.filename,
            "mime": a.mime,
            "size": a.size,
            "uploaded_at": a.uploaded_at.isoformat(),
            "download_url": f"/manuals/file_by_id?att_id={a.id}",
        }
        for a in rows
    ]

@router.delete("/api/attachments/{att_id}")
def delete_attachment(att_id: int, db: Session = Depends(get_db), _: Any = Depends(dep_tech)):
    att = db.get(Attachment, att_id)
    if not att:
        raise HTTPException(404, "attachment not found")
    try:
        p = _secure_under_root(Path(att.stored_path))
        if p.exists():
            p.unlink()
    except Exception:
        logger.warning("failed to remove file from disk (continuing)")
    db.delete(att)
    db.commit()
    return {"ok": True}

@router.get("/file_by_id")
def get_file_by_id(
    att_id: int = Query(...),
    inline: bool = Query(True),
    db: Session = Depends(get_db),
):
    att = db.get(Attachment, att_id)
    if not att:
        raise HTTPException(404, "attachment not found")
    p = _secure_under_root(Path(att.stored_path))
    if not p.exists():
        raise HTTPException(404, "file missing on disk")

    mime = att.mime or _guess_mime(att.filename)
    disp = "inline" if inline else "attachment"
    # filename 파라미터를 사용하지 않고, 명시적으로 헤더만 설정해 중복 방지
    headers = {"Content-Disposition": f"{disp}; filename*=UTF-8''{att.filename}"}
    return FileResponse(str(p), media_type=mime, headers=headers)

# ─────────────────────────────────────────────
# HTML → PDF 내보내기 (RMD 렌더 결과 활용)
# ─────────────────────────────────────────────
@router.get("/export/pdf")
def export_pdf_from_html(
    sw: str = Query(..., description="소프트웨어명"),
    version: str = Query(..., description="버전 문자열"),
):
    """
    /uploads/manuals/{SW}/{VERSION}/index.html 를 통째로 PDF 변환해서 다운로드.
    WeasyPrint는 JS 실행이 제한적이므로, 필요 시 wkhtmltopdf/Chromium으로 교체 가능.
    """
    try:
        from weasyprint import HTML
    except Exception as e:
        raise HTTPException(500, detail=f"WeasyPrint not available: {e}")

    html_path = UPLOAD_ROOT / sw / version / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail=f"HTML not found: {html_path}")

    # 파일 경로를 URL로 넘겨 리소스 상대경로를 그대로 사용
    src_url = f"file://{html_path}"
    pdf_bytes = HTML(src_url).write_pdf()

    fname = f"{sw}_{version}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{fname}"'}
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers=headers)
