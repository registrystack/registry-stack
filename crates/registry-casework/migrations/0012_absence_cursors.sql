CREATE TABLE IF NOT EXISTS casework_absence_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    context_hash text NOT NULL,
    directory_revision bigint NOT NULL CHECK (directory_revision >= 0),
    last_starts_at timestamptz NOT NULL,
    last_absence_id uuid NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_absence_cursors_expiry_idx
    ON casework_absence_cursors(expires_at, cursor_id);
CREATE INDEX IF NOT EXISTS casework_absences_page_idx
    ON casework_absences(starts_at, absence_id);
