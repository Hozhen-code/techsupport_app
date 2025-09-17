# app_manuals.py
from fastapi import (
    APIRouter, Depends, Request, UploadFile, File, Form, HTTPException, Query
)
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, DateTime, Boolean,
    func, UniqueConstraint, create_engine
)
from sqlalchemy.orm import relationship, Session, declarative_base, sessionmaker
from typing import List, Optional, Dict, Any
from pathlib import Path
import io, os, shutil, enum
from datetime import datetime
from auth_utils import require_master, require_tech, require_login
from types import SimpleNamespace

# ── DB/세션 생성 ───────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./naiz.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

templates = Jinja2Templates(directory="templates")
Base = declarative_base()
router = APIRouter(prefix="/manuals", tags=["manuals"])

# 업로드 루트
UPLOAD_ROOT = Path("uploads/manuals")
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

# 역할 상수
class Role(str, enum.Enum):
    master = "MASTER"
    tech = "TECH"
    lab = "LAB"

# 권한 의존성
def current_user_dep(request: Request):
    require_login(request)
    u = request.session.get("user") or {}
    return SimpleNamespace(
        id=u.get("id") or u.get("emp_id") or 0,
        login_id=u.get("login_id"),
        roles=u.get("roles", []),
        name=u.get("name"),
    )

def dep_master(request: Request, user=Depends(current_user_dep)):
    require_master(request); return user

def dep_tech(request: Request, user=Depends(current_user_dep)):
    require_tech(request); return user

# ── 스키마 ───────────────────────────────────────────────
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
    node_id = Column(Integer, ForeignKey("manual_nodes.id"), index=True, nullable=False)
    software_id = Column(Integer, ForeignKey("software.id"), index=True, nullable=False)
    version_id = Column(Integer, ForeignKey("versions.id"), index=True, nullable=False)
    checked = Column(Boolean, default=False)
    summary = Column(Text, nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
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
    revision_id = Column(Integer, ForeignKey("manual_node_revisions.id"), index=True, nullable=False)
    filename = Column(String, nullable=False)
    stored_path = Column(String, nullable=False)
    mime = Column(String, nullable=True)
    size = Column(Integer, nullable=True)
    uploaded_at = Column(DateTime, default=func.now())

    revision = relationship("ManualNodeRevision", backref="attachments", lazy="joined")

class ChangeLog(Base):
    __tablename__ = "manual_changelog"
    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, ForeignKey("manual_nodes.id"), index=True)
    software_id = Column(Integer, ForeignKey("software.id"), index=True)
    version_id = Column(Integer, ForeignKey("versions.id"), index=True)
    changed_by = Column(Integer, ForeignKey("users.id"))
    change_note = Column(Text)
    changed_at = Column(DateTime, default=func.now())

Base.metadata.create_all(bind=engine)

# ── 유틸 ───────────────────────────────────────────────
def tri_state(checked_children: List[bool]) -> str:
    if not checked_children:
        return "unchecked"
    if all(checked_children):
        return "checked"
    if any(checked_children):
        return "partial"
    return "unchecked"

# ── 페이지 ─────────────────────────────────────────────
@router.get("/", response_class=HTMLResponse, name="manuals_page")
def manuals_page(request: Request, db: Session = Depends(get_db)):
    versions = db.query(Version).order_by(Version.created_at.desc()).all()
    sw = db.query(Software).order_by(Software.name).all()
    return templates.TemplateResponse(
        "manuals.html",
        {"request": request, "versions": versions, "software": sw},
    )

# ── 드롭다운 API ───────────────────────────────────────
@router.get("/api/versions")
def api_versions(db: Session = Depends(get_db)):
    rows = db.query(Version).order_by(Version.created_at.desc()).all()
    return [{"id": r.id, "name": r.name} for r in rows]

@router.get("/api/software")
def api_software(db: Session = Depends(get_db)):
    rows = db.query(Software).order_by(Software.name).all()
    return [{"id": r.id, "name": r.name} for r in rows]

# ── 트리 조회 ──────────────────────────────────────────
@router.get("/api/tree")
def api_tree(
    version_id: int,
    sw_ids: List[int] = Query(..., description="SW ID 리스트"),
    q: Optional[str] = None,
    db: Session = Depends(get_db),
):
    all_nodes = db.query(ManualNode).all()

    revs = db.query(ManualNodeRevision).filter(
        ManualNodeRevision.version_id == version_id,
        ManualNodeRevision.software_id.in_(sw_ids),
    ).all()

    checked_map: Dict[int, bool] = {}
    for r in revs:
        checked_map[r.node_id] = checked_map.get(r.node_id, False) or bool(r.checked)

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
        kids = [serialize(c) for c in sorted(n.children, key=lambda x: (c.sort_order, c.id))]
        states = [k["state"] for k in kids]
        child_checked_flags = [s == "checked" for s in states]
        node_checked = checked_map.get(n.id, False)
        if not kids:
            state = "checked" if node_checked else "unchecked"
        else:
            if node_checked and all(child_checked_flags):
                state = "checked"
            else:
                _ts = tri_state(child_checked_flags or [node_checked])
                state = "partial" if (node_checked and _ts == "unchecked") else _ts
        return {
            "id": n.id,
            "title": n.title,
            "is_section": n.is_section,
            "state": state,
            "children": kids,
            "highlight": (n.id in match_ids) if q else False,
        }

    roots = [n for n in all_nodes if n.parent_id is None]
    roots.sort(key=lambda x: (x.sort_order, x.id))
    tree = [serialize(r) for r in roots]
    return {"tree": tree}

# ── 체크 저장 ─────────────────────────────────────────
@router.post("/api/check")
def api_check(
    request: Request,
    version_id: int = Form(...),
    sw_ids: str = Form(...),  # "1,2,3"
    node_id: int = Form(...),
    checked: bool = Form(...),
    db: Session = Depends(get_db),
    actor: Any = Depends(dep_tech),
):
    sw_list = [int(x) for x in sw_ids.split(",") if x]

    queue: List[int] = []
    def collect(nid: int):
        queue.append(nid)
        for c in db.query(ManualNode).filter(ManualNode.parent_id == nid).all():
            collect(c.id)
    collect(node_id)

    changer_id = getattr(actor, "id", None)

    for nid in queue:
        for sw in sw_list:
            rev = db.query(ManualNodeRevision).filter_by(
                node_id=nid, software_id=sw, version_id=version_id
            ).first()
            if not rev:
                rev = ManualNodeRevision(
                    node_id=nid, software_id=sw, version_id=version_id,
                    checked=checked, updated_by=changer_id
                )
                db.add(rev)
            else:
                rev.checked = checked
                rev.updated_by = changer_id

        db.add(ChangeLog(
            node_id=nid, software_id=sw_list[0], version_id=version_id,
            changed_by=changer_id, change_note=f"check={checked}"
        ))

    db.commit()
    return {"ok": True}

# ── 첨부 업로드 ───────────────────────────────────────
@router.post("/api/upload")
def api_upload(
    version_id: int = Form(...),
    software_id: int = Form(...),
    node_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: Any = Depends(dep_tech),
):
    changer_id = getattr(user, "id", None)

    rev = db.query(ManualNodeRevision).filter_by(
        node_id=node_id, software_id=software_id, version_id=version_id
    ).first()
    if not rev:
        rev = ManualNodeRevision(
            node_id=node_id, software_id=software_id, version_id=version_id,
            checked=False, updated_by=changer_id
        )
        db.add(rev); db.flush()

    node_dir = UPLOAD_ROOT / f"v{version_id}_sw{software_id}" / str(node_id)
    node_dir.mkdir(parents=True, exist_ok=True)
    stored_path = node_dir / file.filename

    with open(stored_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    att = Attachment(
        revision_id=rev.id,
        filename=file.filename,
        stored_path=str(stored_path),
        mime=file.content_type,
        size=stored_path.stat().st_size,
    )
    db.add(att)

    db.add(ChangeLog(
        node_id=node_id, software_id=software_id, version_id=version_id,
        changed_by=changer_id, change_note=f"upload:{file.filename}"
    ))

    db.commit()
    return {"ok": True, "attachment_id": att.id}

# ── PDF 내보내기 ───────────────────────────────────────
@router.post("/export/pdf")
def export_pdf(
    request: Request,
    version_id: int = Form(...),
    sw_ids: str = Form(...),
    cover_title: str = Form("메뉴얼"),
    db: Session = Depends(get_db),
):
    try:
        from weasyprint import HTML, CSS
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=("WeasyPrint 실행 환경 필요. " f"원인: {e}")
        )

    sw_list = [int(x) for x in sw_ids.split(",") if x]
    version = db.query(Version).get(version_id)
    sw_names = [s.name for s in db.query(Software).filter(Software.id.in_(sw_list)).all()]

    revs = db.query(ManualNodeRevision).filter(
        ManualNodeRevision.version_id == version_id,
        ManualNodeRevision.software_id.in_(sw_list),
        ManualNodeRevision.checked.is_(True)
    ).all()
    include_ids = sorted({r.node_id for r in revs})

    def flatten(node: ManualNode, out: list):
        out.append(node)
        for c in sorted(node.children, key=lambda x: (x.sort_order, x.id)):
            flatten(c, out)

    roots = db.query(ManualNode).filter(ManualNode.parent_id.is_(None)).all()
    ordered = []
    for r in sorted(roots, key=lambda x: (x.sort_order, x.id)):
        flatten(r, ordered)

    selected_nodes = [n for n in ordered if n.id in include_ids]

    toc_items = []
    body_parts = []

    cover_html = f"""
    <section class="cover">
        <h1>{cover_title}</h1>
        <h2>버전: {version.name if version else ''}</h2>
        <p>SW: {", ".join(sw_names)}</p>
        <p>생성일: {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
    </section>
    <div class="pagebreak"></div>
    """

    for idx, n in enumerate(selected_nodes, start=1):
        toc_items.append(f"<li>{idx}. {n.title}</li>")
    toc_html = f"""
    <section class="toc">
        <h2>목차</h2>
        <ol>{''.join(toc_items)}</ol>
    </section>
    <div class="pagebreak"></div>
    """

    for idx, n in enumerate(selected_nodes, start=1):
        rev = db.query(ManualNodeRevision).filter(
            ManualNodeRevision.node_id == n.id,
            ManualNodeRevision.version_id == version_id,
            ManualNodeRevision.software_id.in_(sw_list)
        ).first()
        atts = rev.attachments if rev else []
        files_html = "".join(f"<li>{a.filename}</li>" for a in atts)
        body_parts.append(f"""
        <section class="section">
            <h3>{idx}. {n.title}</h3>
            {'<p>'+ (rev.summary or '') + '</p>' if (rev and rev.summary) else ''}
            {'<ul>'+files_html+'</ul>' if files_html else '<p>(첨부 없음)</p>'}
        </section>
        <div class="pagebreak"></div>
        """)

    html = f"""
    <html>
    <head>
    <meta charset="utf-8" />
    <style>
    @page {{ size: A4; margin: 20mm; }}
    body {{ font-family: "Noto Sans CJK KR", sans-serif; }}
    h1,h2,h3 {{ margin: 0 0 12px 0; }}
    .cover {{ text-align:center; padding-top: 120px; }}
    .toc ol {{ padding-left: 20px; }}
    .section {{ page-break-inside: avoid; }}
    .pagebreak {{ page-break-after: always; }}
    footer {{ position: fixed; bottom: 5mm; right: 10mm; font-size: 10px; }}
    </style>
    </head>
    <body>
    {cover_html}
    {toc_html}
    {''.join(body_parts)}
    <footer>Generated at {datetime.now().strftime("%Y-%m-%d %H:%M")}</footer>
    </body>
    </html>
    """
    pdf = HTML(string=html, base_url=str(Path(".").absolute())).write_pdf()
    filename = f'manual_{version.name if version else "unknown"}.pdf'
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ── 대량 업로드 ───────────────────────────────────────
@router.post("/api/bulk-import")
def bulk_import(
    version_id: int = Form(...),
    software_id: int = Form(...),
    node_id: int = Form(...),
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: Any = Depends(dep_tech),
):
    changer_id = getattr(user, "id", None)

    rev = db.query(ManualNodeRevision).filter_by(
        node_id=node_id, software_id=software_id, version_id=version_id
    ).first()
    if not rev:
        rev = ManualNodeRevision(
            node_id=node_id, software_id=software_id, version_id=version_id,
            checked=False, updated_by=changer_id
        )
        db.add(rev); db.flush()

    node_dir = UPLOAD_ROOT / f"v{version_id}_sw{software_id}" / str(node_id)
    node_dir.mkdir(parents=True, exist_ok=True)

    for f in files:
        stored_path = node_dir / f.filename
        with open(stored_path, "wb") as out:
            shutil.copyfileobj(f.file, out)

        att = Attachment(
            revision_id=rev.id,
            filename=f.filename,
            stored_path=str(stored_path),
            mime=f.content_type,
            size=stored_path.stat().st_size,
        )
        db.add(att)

        db.add(ChangeLog(
            node_id=node_id, software_id=software_id, version_id=version_id,
            changed_by=changer_id, change_note=f"upload:{f.filename}"
        ))

    db.commit()
    return {"ok": True}
