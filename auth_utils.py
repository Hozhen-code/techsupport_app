import io, csv
from fastapi import HTTPException, Request, Response

def current_roles(request: Request):
    return (request.session.get("user") or {}).get("roles", []) or []

def has_role(request: Request, *codes: str) -> bool:
    roles = set(r.upper() for r in current_roles(request))
    return any((c or "").upper() in roles for c in codes)

def require_login(request: Request):
    if "user" not in request.session:
        raise HTTPException(status_code=401, detail="Login required")

def require_role_any(request: Request, *codes: str):
    require_login(request)
    if not has_role(request, *codes):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

def require_master(request: Request):
    require_role_any(request, "MASTER")

def require_tech(request: Request):
    # MASTER도 허용
    require_role_any(request, "TECH", "MASTER")

def csv_response(filename: str, headers, rows):
    def hlabel(h):
        if isinstance(h, dict):  return h.get("label", "")
        if isinstance(h, tuple): return h[0]
        return str(h)
    labels = [hlabel(h) for h in headers]

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(labels)
    for r in rows:
        w.writerow([("" if v is None else v) for v in r])

    data = buf.getvalue().encode("utf-8-sig")  # 엑셀 호환 BOM
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
