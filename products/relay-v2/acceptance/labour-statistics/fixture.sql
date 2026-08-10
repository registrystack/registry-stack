PRAGMA foreign_keys = ON;

CREATE TABLE source_labour_force_rates (
    ref_area TEXT NOT NULL,
    sex TEXT NOT NULL,
    time_period TEXT NOT NULL,
    obs_value REAL NOT NULL,
    unit_measure TEXT NOT NULL,
    authority_scope TEXT NOT NULL,
    PRIMARY KEY (ref_area, sex, time_period)
) STRICT;

INSERT INTO source_labour_force_rates VALUES
('EX-A', 'F', '2024-Q1', 61.2, 'PERCENT', 'zone-a'),
('EX-A', 'M', '2024-Q1', 72.8, 'PERCENT', 'zone-a'),
('EX-A', 'F', '2024-Q2', 62.1, 'PERCENT', 'zone-a'),
('EX-A', 'M', '2024-Q2', 73.0, 'PERCENT', 'zone-a'),
('EX-B', 'F', '2024-Q1', 58.4, 'PERCENT', 'zone-b'),
('EX-B', 'M', '2024-Q1', 69.7, 'PERCENT', 'zone-b'),
('EX-B', 'X', '2024-Q2', 70.0, 'PERCENT', 'zone-b');

CREATE VIEW relay_labour_force_rates AS
SELECT ref_area, sex, time_period, obs_value, unit_measure
FROM source_labour_force_rates;

CREATE VIEW relay_authority_labour_force_rates AS
SELECT ref_area, sex, time_period, obs_value, unit_measure, authority_scope
FROM source_labour_force_rates;
