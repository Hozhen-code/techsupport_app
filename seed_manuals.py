# seed_manuals.py
from app_manuals import SessionLocal, Version, Software, ManualNode

db = SessionLocal()

# 버전
for v in ["v2.1.27", "v2.1.28"]:
    if not db.query(Version).filter_by(name=v).first():
        db.add(Version(name=v))

# SW
for s in ["Client","NRS","LMS","영상분석","VAS","NVR","SW","서비스"]:
    if not db.query(Software).filter_by(name=s).first():
        db.add(Software(name=s))
db.commit()

# 트리(최상위 8개 단락)
roots = ["개요","설치하기","화면구성 및 기능","운영","장애/점검","보안","FAQ","부록"]
for idx, title in enumerate(roots):
    if not db.query(ManualNode).filter_by(title=title, parent_id=None).first():
        db.add(ManualNode(title=title, sort_order=idx, is_section=True))
db.commit()
print("seed done")
