PRAGMA foreign_keys = ON;

CREATE TABLE source_registered_businesses (
    registration_number TEXT PRIMARY KEY NOT NULL,
    record_revision TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    legal_name TEXT NOT NULL,
    registration_status TEXT NOT NULL,
    legal_form TEXT NOT NULL,
    jurisdiction_code TEXT NOT NULL
) STRICT;

INSERT INTO source_registered_businesses VALUES
('BIZ-SYNTH-0001', '7', 'ACTIVE', '2026-06-01T08:00:00Z', 'Example Orchard Cooperative', 'ACTIVE', 'COOPERATIVE', 'EX-A'),
('BIZ-SYNTH-0002', '4', 'ACTIVE', '2026-06-02T08:00:00Z', 'Synthetic River Trading Ltd', 'ACTIVE', 'LIMITED_COMPANY', 'EX-B'),
('BIZ-SYNTH-0003', '9', 'SUSPENDED', '2026-06-03T08:00:00Z', 'Demonstration Workshop Association', 'SUSPENDED', 'ASSOCIATION', 'EX-A'),
('BIZ-SYNTH-0004', '2', 'RETIRED', '2026-06-04T08:00:00Z', 'Fixture Market Cooperative', 'CLOSED', 'COOPERATIVE', 'EX-B'),
('BIZ-SYNTH-BAD1', '1', 'ACTIVE', 'not-a-date-time', 'Invalid Fixture Enterprise', 'ACTIVE', 'LIMITED_COMPANY', 'EX-B');

CREATE VIEW relay_registered_businesses AS
SELECT registration_number,
       record_revision,
       lifecycle_state,
       recorded_at,
       legal_name,
       registration_status,
       legal_form,
       jurisdiction_code
FROM source_registered_businesses;
