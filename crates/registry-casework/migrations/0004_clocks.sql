CREATE TABLE IF NOT EXISTS casework_holiday_sets (
    holiday_set text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL,
    digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
    created_at timestamptz NOT NULL,
    created_by_issuer text NOT NULL,
    created_by_subject text NOT NULL,
    created_by_profile text NOT NULL,
    PRIMARY KEY (holiday_set, revision)
);

CREATE TABLE IF NOT EXISTS casework_clock_occurrences (
    clock_occurrence_id uuid PRIMARY KEY,
    source_id text NOT NULL,
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    clock_id text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('subject','activity')),
    scope_key text NOT NULL,
    item_id uuid REFERENCES casework_items(item_id),
    state text NOT NULL CHECK (state IN ('running','paused','completed','cancelled','verification_pending','source_facts_missing')),
    policy_digest text NOT NULL CHECK (policy_digest LIKE 'sha256:%'),
    current_calculation_generation bigint NOT NULL CHECK (current_calculation_generation >= 0),
    recompute_generation bigint NOT NULL DEFAULT 0 CHECK (recompute_generation >= 0),
    source_binding_generation text NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_etag text NOT NULL,
    next_action_at timestamptz,
    lease_token uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (source_id, subject_kind, subject_id, clock_id, scope, scope_key)
);
CREATE INDEX IF NOT EXISTS casework_clock_occurrences_due_idx
    ON casework_clock_occurrences(next_action_at, clock_occurrence_id)
    WHERE state IN ('running','verification_pending') AND next_action_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS casework_clock_calculations (
    clock_occurrence_id uuid NOT NULL REFERENCES casework_clock_occurrences(clock_occurrence_id),
    generation bigint NOT NULL CHECK (generation > 0),
    recompute_generation bigint NOT NULL CHECK (recompute_generation >= 0),
    policy_digest text NOT NULL CHECK (policy_digest LIKE 'sha256:%'),
    policy jsonb NOT NULL,
    calendar jsonb,
    holiday_document jsonb,
    source_timing jsonb,
    anchor_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    due_at timestamptz,
    at_risk_at timestamptz,
    reminders jsonb NOT NULL,
    steps jsonb NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (clock_occurrence_id, generation)
);

CREATE TABLE IF NOT EXISTS casework_clock_effects (
    clock_occurrence_id uuid NOT NULL REFERENCES casework_clock_occurrences(clock_occurrence_id),
    effect_kind text NOT NULL CHECK (effect_kind IN ('reminder','step')),
    effect_id text NOT NULL,
    calculation_generation bigint NOT NULL,
    event_id uuid NOT NULL,
    applied_at timestamptz NOT NULL,
    PRIMARY KEY (clock_occurrence_id, effect_kind, effect_id),
    UNIQUE (event_id)
);

CREATE TABLE IF NOT EXISTS casework_clock_recompute_previews (
    preview_id uuid NOT NULL,
    clock_occurrence_id uuid NOT NULL REFERENCES casework_clock_occurrences(clock_occurrence_id),
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    profile_id text NOT NULL,
    expected_calculation_generation bigint NOT NULL,
    expected_source_revision bigint NOT NULL,
    expected_source_etag text NOT NULL,
    proposed_policy_digest text NOT NULL,
    proposed_policy jsonb NOT NULL,
    proposed_calendar jsonb NOT NULL,
    proposed_holiday_document jsonb NOT NULL,
    proposed_due_at timestamptz NOT NULL,
    proposed_at_risk_at timestamptz,
    proposed_reminders jsonb NOT NULL,
    proposed_steps jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    applied_at timestamptz,
    PRIMARY KEY (preview_id, clock_occurrence_id)
);
CREATE INDEX IF NOT EXISTS casework_clock_recompute_previews_expiry_idx
    ON casework_clock_recompute_previews(expires_at, preview_id);
