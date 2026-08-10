PRAGMA foreign_keys = ON;

CREATE TABLE source_registered_businesses (
    registration_number TEXT PRIMARY KEY NOT NULL,
    record_revision TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    legal_name TEXT NOT NULL,
    public_legal_name TEXT NOT NULL,
    registrar_note TEXT NOT NULL,
    registration_status TEXT NOT NULL,
    legal_form TEXT NOT NULL,
    jurisdiction_code TEXT NOT NULL
) STRICT;

INSERT INTO source_registered_businesses VALUES
('BIZ-SYNTH-0001', '7', 'ACTIVE', '2026-06-01T08:00:00Z', 'Example Orchard Cooperative', 'Example Orchard Cooperative', 'Registrar note A', 'ACTIVE', 'COOPERATIVE', 'EX-A'),
('BIZ-SYNTH-0002', '4', 'ACTIVE', '2026-06-02T08:00:00Z', 'Synthetic River Trading Ltd', 'Synthetic River Trading Ltd', 'Registrar note B', 'ACTIVE', 'LIMITED_COMPANY', 'EX-B'),
('BIZ-SYNTH-0003', '9', 'SUSPENDED', '2026-06-03T08:00:00Z', 'Demonstration Workshop Association', 'Demonstration Workshop Association', 'Registrar note C', 'SUSPENDED', 'ASSOCIATION', 'EX-A'),
('BIZ-SYNTH-0004', '2', 'RETIRED', '2026-06-04T08:00:00Z', 'Fixture Market Cooperative', 'Fixture Market Cooperative', 'Registrar note D', 'CLOSED', 'COOPERATIVE', 'EX-B'),
('BIZ-SYNTH-BAD1', '1', 'ACTIVE', 'not-a-date-time', 'Invalid Fixture Enterprise', 'Invalid Fixture Enterprise', 'Registrar note invalid', 'ACTIVE', 'LIMITED_COMPANY', 'EX-B');

CREATE VIEW relay_registered_businesses AS
SELECT registration_number,
       record_revision,
       lifecycle_state,
       recorded_at,
       public_legal_name,
       legal_name AS registrar_legal_name,
       registrar_note,
       registration_status,
       legal_form,
       jurisdiction_code
FROM source_registered_businesses;

CREATE TABLE source_registered_premises (
    premises_identifier TEXT PRIMARY KEY NOT NULL,
    record_revision TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    business_registration_number TEXT NOT NULL,
    premises_name TEXT NOT NULL,
    longitude REAL NOT NULL,
    latitude REAL NOT NULL
) STRICT;

INSERT INTO source_registered_premises VALUES
('PREM-SYNTH-0001', '3', 'ACTIVE', '2026-06-01T08:00:00Z', 'BIZ-SYNTH-0001', 'Orchard cooperative market', 100.0, 13.0),
('PREM-SYNTH-0002', '2', 'ACTIVE', '2026-06-02T08:00:00Z', 'BIZ-SYNTH-0002', 'River trading warehouse', 100.5, 13.5),
('PREM-SYNTH-0003', '5', 'ACTIVE', '2026-06-03T08:00:00Z', 'BIZ-SYNTH-0003', 'Workshop meeting hall', 101.0, 14.0),
('PREM-SYNTH-0004', '1', 'RETIRED', '2026-06-04T08:00:00Z', 'BIZ-SYNTH-0004', 'Fixture market store', 102.0, 15.0),
('PREM-SYNTH-BAD1', '1', 'ACTIVE', '2026-06-05T08:00:00Z', 'BIZ-SYNTH-0002', 'Unsafe coordinate fixture', 100.25, 95.0);

CREATE VIEW relay_registered_premises AS
SELECT premises_identifier,
       record_revision,
       lifecycle_state,
       recorded_at,
       business_registration_number,
       premises_name,
       longitude,
       latitude
FROM source_registered_premises;
