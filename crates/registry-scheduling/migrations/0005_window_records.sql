-- Published arrival windows are deployment facts applied by the operator,
-- beside locations, pools, members, and dated exceptions. The strict Rust
-- record model validates this JSON before the atomic replacement writes it;
-- the identifier remains a typed column for deterministic replacement and
-- lookup.
CREATE TABLE IF NOT EXISTS scheduling_windows (
    window_id text PRIMARY KEY,
    window_record jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The public revision is the caller's agreement with a window's terms. Keep
-- its last accepted record even while the active window is absent, so a later
-- replacement cannot reuse an observed revision for different terms.
CREATE TABLE IF NOT EXISTS scheduling_window_revision_heads (
    window_id text PRIMARY KEY,
    window_record jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
