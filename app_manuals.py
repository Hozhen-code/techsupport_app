from fastapi import (
    APIRouter, Depends, Request, UploadFile, File, Form,
    HTTPException, Query
)
from fastapi.responses import (
    HTMLResponse, StreamingResponse, FileResponse, JSONResponse
)
from fastapi.templating import Jinja2Templates
from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey,
    DateTime, Boolean, func, UniqueConstraint, create_engine
)
from sqlalchemy.orm import relationship, Session, declarative_base, sessionmaker
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime
from auth_utils import require_master, require_tech, require_login
from types import SimpleNamespace
import shutil, io, os, logging, mimetypes, secrets

# ─────────────────────────────────────────────
# 로깅 설정
# ─────────────────────────────────────────────
logger = logging.getLogger("uvicorn.error")

# ─────────────────────────────────────────────
# DB 설정
# ─────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./naiz.db")
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

# ─────────────────────────────────────────────
# 템플릿 & 라우터
# ─────────────────────────────────────────────
templates = Jinja2Templates(directory="templates")
router = APIRouter(prefix="/manuals", tags=["manuals"])

# 컨테이너 기준 /app/uploads/manuals 로 생성됨 (상대경로)
UPLOAD_ROOT = Path(os.getenv("MANUALS_DIR", "uploads/manuals")).resolve()
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

# 업로드 제약
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "150"))  # 기본 150MB
ALLOWED_EXTS = set(
    x.lower() for x in os.getenv(
        "ALLOWED_MANUALS_EXTS",
        ".pdf,.png,.jpg,.jpeg,.gif,.webp,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.md"
    ).split(",")
)

# ─────────────────────────────────────────────
# 모델 정의
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

    __table_args__ = (
        UniqueConstraint("node_id", "software_id", "version_id", name="uniq_node_sw_ver"),
    )


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


Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────
# 권한 헬퍼
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
# 페이지
# ─────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
def manuals_page(request: Request, db: Session = Depends(get_db)):
    require_login(request)
    versions = db.query(Version).order_by(Version.created_at.desc()).all()
    sw = db.query(Software).order_by(Software.name).all()
    return templates.TemplateResponse(
        "manuals.html", {"request": request, "versions": versions, "software": sw}
    )


@router.get("/api/versions")
def api_versions(db: Session = Depends(get_db)):
    rows = db.query(Version).all()
    return [{"id": r.id, "name": r.name} for r in rows]


@router.get("/api/software")
def api_software(db: Session = Depends(get_db)):
    rows = db.query(Software).all()
    return [{"id": r.id, "name": r.name} for r in rows]

# ─────────────────────────────────────────────
# 트리 조회
# ─────────────────────────────────────────────

def _tri_state(flags: List[bool]) -> str:
    if not flags:
        return "unchecked"
    if all(flags):
        return "checked"
    if any(flags):
        return "partial"
    return "unchecked"


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

    def add_parents(nid):
        node = db.query(ManualNode).get(nid)
        while node and node.parent_id:
            allowed_ids.add(node.parent_id)
            node = node.parent

    for rid in list(allowed_ids):
        add_parents(rid)

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


# ─────────────────────────────────────────────
# 체크 저장
# ─────────────────────────────────────────────

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
# 파일 업로드/목록/삭제/다운로드
# ─────────────────────────────────────────────

def _secure_under_root(p: Path) -> Path:
    """UPLOAD_ROOT 하위 경로만 허용 (경로 탈출 차단)."""
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

    # 업로드 크기 제한 검사 (가능한 경우, content-length 사용)
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"file too large (>{MAX_UPLOAD_MB}MB)")

    logger.info(
        f"[UPLOAD] start v={version_id} sw={software_id} node={node_id} name={file.filename}"
    )

    # 리비전 확보
    rev = (
        db.query(ManualNodeRevision)
        .filter_by(node_id=node_id, software_id=software_id, version_id=version_id)
        .first()
    )
    if not rev:
        rev = ManualNodeRevision(
            node_id=node_id,
            software_id=software_id,
            version_id=version_id,
            updated_by=getattr(actor, "id", None),
        )
        db.add(rev)
        db.flush()

    # 경로 생성 (버전/소프트웨어/노드)
    node_dir = UPLOAD_ROOT / f"v{version_id}_sw{software_id}" / str(node_id)
    node_dir.mkdir(parents=True, exist_ok=True)

    # 동일 파일명 충돌 방지: 기존 유지/덮어쓰기/버전링 중 택1
    # 여기서는 같은 이름이 있으면 _{shortid} 추가
    dest_name = file.filename
    dest_path = node_dir / dest_name
    if dest_path.exists():
        stem, ext = os.path.splitext(dest_name)
        dest_name = f"{stem}_{secrets.token_hex(4)}{ext}"
        dest_path = node_dir / dest_name

    # 저장
    size = 0
    try:
        with dest_path.open("wb") as f:
            # shutil.copyfileobj 반환값은 None 일 수 있음 → 실제 파일 크기로 보정
            shutil.copyfileobj(file.file, f)
        size = dest_path.stat().st_size
    except Exception as e:
        logger.exception("upload save failed")
        raise HTTPException(500, f"save failed: {e}")

    mime = file.content_type or _guess_mime(dest_name)
    logger.info(f"[UPLOAD] saved -> {dest_path} ({size} bytes)")

    att = Attachment(
        revision_id=rev.id,
        filename=dest_name,
        stored_path=str(dest_path),
        mime=mime,
        size=size,
    )
    db.add(att)
    db.commit()

    return {"ok": True, "attachment_id": att.id, "path": att.stored_path, "size": size}


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
    att = db.query(Attachment).get(att_id)
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
    att = db.query(Attachment).get(att_id)
    if not att:
        raise HTTPException(404, "attachment not found")
    p = _secure_under_root(Path(att.stored_path))
    if not p.exists():
        raise HTTPException(404, "file missing on disk")

    mime = att.mime or _guess_mime(att.filename)
    disp = "inline" if inline else "attachment"
    headers = {
        "Content-Disposition": f"{disp}; filename*=UTF-8''{att.filename}"
    }
    return FileResponse(str(p), media_type=mime, filename=att.filename, headers=headers)


@router.get("/file")
def get_uploaded_file(path: str = Query(...), inline: bool = Query(True)):
    """레거시 호환: 절대경로/상대경로 모두 허용하되, UPLOAD_ROOT 하위만 서비스."""
    try:
        p = Path(path)
        if not p.is_absolute():
            p = UPLOAD_ROOT / p
        p = _secure_under_root(p)
    except Exception:
        raise HTTPException(400, "invalid path")

    if not p.exists():
        raise HTTPException(404, "파일 없음")

    mime = _guess_mime(p.name)
    disp = "inline" if inline else "attachment"
    headers = {"Content-Disposition": f"{disp}; filename*=UTF-8''{p.name}"}
    return FileResponse(str(p), media_type=mime, filename=p.name, headers=headers)


# ─────────────────────────────────────────────
# PDF 내보내기 (간단 목차 버전)
# ─────────────────────────────────────────────

@router.post("/export/pdf")
def export_pdf(
    request: Request,
    version_id: int = Form(...),
    sw_ids: str = Form(...),
    cover_title: str = Form("메뉴얼"),
    db: Session = Depends(get_db),
):
    require_login(request)
    try:
        from weasyprint import HTML
    except Exception as e:
        raise HTTPException(500, detail=f"WeasyPrint 미설치/환경오류: {e}")

    sw_list = [int(x) for x in sw_ids.split(",") if x]
    version = db.query(Version).get(version_id)
    # 체크된 노드 수집
    revs = (
        db.query(ManualNodeRevision)
        .filter(
            ManualNodeRevision.version_id == version_id,
            ManualNodeRevision.software_id.in_(sw_list),
            ManualNodeRevision.checked.is_(True),
        )
        .all()
    )
    include_ids = {r.node_id for r in revs}

    def flatten(n, acc):
        acc.append(n)
        for c in n.children:
            flatten(c, acc)

    ordered = []
    roots = db.query(ManualNode).filter(ManualNode.parent_id.is_(None)).order_by(ManualNode.sort_order, ManualNode.id)
    for r in roots:
        flatten(r, ordered)
    selected = [n for n in ordered if n.id in include_ids]

    cover = f"<h1>{cover_title}</h1><h2>{version.name if version else ''}</h2>"
    body = "".join(f"<h3>{i+1}. {n.title}</h3>" for i, n in enumerate(selected))
    html = f"<html><meta charset='utf-8'><body>{cover}{body}</body></html>"
    pdf = HTML(string=html).write_pdf()

    fname = f"manual_{(version.name if version else 'v')}.pdf"
    headers = {"Content-Disposition": f"attachment; filename=\"{fname}\""}
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf", headers=headers)
