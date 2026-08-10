PRAGMA foreign_keys = ON;

CREATE TABLE source_civil_events (
    event_reference TEXT PRIMARY KEY NOT NULL,
    record_revision TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    registration_status TEXT NOT NULL,
    registration_date TEXT NOT NULL,
    registration_area_code TEXT NOT NULL,
    certificate_available INTEGER NOT NULL CHECK (certificate_available IN (0, 1)),
    jurisdiction_code TEXT NOT NULL,
    registration_number TEXT NOT NULL
) STRICT;

INSERT INTO source_civil_events VALUES
('EVENT-SYNTH-0001', '5', 'ACTIVE', '2026-05-01T10:00:00Z', 'BIRTH', 'REGISTERED', '2026-04-30', 'AREA-A', 1, 'EX-A', 'REG-SYNTH-000001'),
('EVENT-SYNTH-0002', '2', 'ACTIVE', '2026-05-02T10:00:00Z', 'DEATH', 'REGISTERED', '2026-05-01', 'AREA-B', 1, 'EX-B', 'REG-SYNTH-000002'),
('EVENT-SYNTH-0101', '1', 'ACTIVE', '2026-05-03T10:00:00Z', 'BIRTH', 'REGISTERED', '2026-05-02', 'AREA-A', 1, 'EX-A', 'REG-SYNTH-AMBIG01'),
('EVENT-SYNTH-0102', '1', 'ACTIVE', '2026-05-03T10:05:00Z', 'BIRTH', 'REGISTERED', '2026-05-02', 'AREA-A', 0, 'EX-A', 'REG-SYNTH-AMBIG01'),
('EVENT-SYNTH-BAD1', '1', 'NOT-A-LIFECYCLE', '2026-05-04T10:00:00Z', 'BIRTH', 'REGISTERED', '2026-05-03', 'AREA-A', 1, 'EX-A', 'REG-SYNTH-INVALID1'),
('EVENT-SYNTH-XFORM', '1', 'ACTIVE', '2026-05-05T10:00:00Z', 'BIRTH', 'REGISTERED', 'not-a-date', 'AREA-A', 1, 'EX-A', 'REG-SYNTH-XFORM1');

CREATE VIEW relay_civil_events AS
SELECT event_reference,
       record_revision,
       lifecycle_state,
       recorded_at,
       event_type,
       registration_status,
       registration_date,
       registration_area_code,
       certificate_available,
       jurisdiction_code,
       registration_number
FROM source_civil_events;
