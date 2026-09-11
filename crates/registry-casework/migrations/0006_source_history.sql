CREATE TABLE IF NOT EXISTS casework_history_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    casework_profile_id text NOT NULL,
    source_profile_id text NOT NULL,
    item_id uuid NOT NULL REFERENCES casework_items(item_id) ON DELETE CASCADE,
    last_occurred_at timestamptz NOT NULL,
    last_event_id uuid NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_history_cursors_expiry_idx
    ON casework_history_cursors(expires_at, cursor_id);
CREATE INDEX IF NOT EXISTS casework_history_cursors_item_idx
    ON casework_history_cursors(item_id);
