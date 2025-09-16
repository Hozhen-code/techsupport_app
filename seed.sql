ALTER TABLE cs_requests  ADD COLUMN deleted_at TEXT;
ALTER TABLE cs_requests  ADD COLUMN deleted_by INTEGER;

ALTER TABLE cs_schedules ADD COLUMN deleted_at TEXT;
ALTER TABLE cs_schedules ADD COLUMN deleted_by INTEGER;