CREATE TABLE IF NOT EXISTS casework_directory_target_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    context_hash text NOT NULL,
    last_issuer text NOT NULL,
    last_subject text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_directory_target_cursors_expiry_idx
    ON casework_directory_target_cursors(expires_at, cursor_id);
