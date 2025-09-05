PRAGMA foreign_keys = ON;

CREATE TABLE sw_services(
  sv_id        INTEGER PRIMARY KEY,
  sw_id        INTEGER NOT NULL REFERENCES sw_products(sw_id) ON DELETE CASCADE,
  sv_code      TEXT NOT NULL UNIQUE,
  sv_name      TEXT NOT NULL,
  sv_type      TEXT NOT NULL CHECK (sv_type IN ('A','B','C')),
  price_wons   INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','archived')),
  created_at   DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at   DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
  CONSTRAINT uq_sw_sv_name_type UNIQUE (sw_id, sv_name, sv_type)
);

CREATE INDEX IF NOT EXISTS ix_sw_services_sw_id ON sw_services(sw_id);

CREATE TRIGGER IF NOT EXISTS trg_sw_services_touch_updated
AFTER UPDATE ON sw_services
FOR EACH ROW
BEGIN
  UPDATE sw_services
     SET updated_at = datetime('now','localtime')
   WHERE sv_id = NEW.sv_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_sw_services_touch_updated
AFTER UPDATE ON sw_services
FOR EACH ROW
BEGIN
  UPDATE sw_services
     SET updated_at = datetime('now','localtime')
   WHERE sv_id = NEW.sv_id;
END;


