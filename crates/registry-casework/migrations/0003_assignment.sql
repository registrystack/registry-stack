CREATE TABLE IF NOT EXISTS casework_absences (
    absence_id uuid PRIMARY KEY,
    person_issuer text NOT NULL,
    person_subject text NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    cover_issuer text NOT NULL,
    cover_subject text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    CHECK (starts_at < ends_at),
    CHECK ((person_issuer, person_subject) <> (cover_issuer, cover_subject))
);
CREATE INDEX IF NOT EXISTS casework_absences_person_period_idx
    ON casework_absences(person_issuer, person_subject, starts_at, ends_at, absence_id);
CREATE INDEX IF NOT EXISTS casework_memberships_principal_team_idx
    ON casework_memberships(issuer, subject, membership_kind, team_id);

ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS assignment_owner_issuer text;
ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS assignment_owner_subject text;
ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS assigned_by_issuer text;
ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS assigned_by_subject text;
ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS assignment_absence_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE casework_items ADD COLUMN IF NOT EXISTS staffing_diagnostic text
    CHECK (staffing_diagnostic IS NULL OR staffing_diagnostic = 'no_cover_available');
CREATE INDEX IF NOT EXISTS casework_items_holder_caseload_idx
    ON casework_items(holder_issuer, holder_subject, queue_id, item_id)
    WHERE state NOT IN ('completed','superseded','cancelled');
CREATE INDEX IF NOT EXISTS casework_items_holder_caseload_all_idx
    ON casework_items(holder_issuer, holder_subject, item_id, queue_id)
    WHERE state NOT IN ('completed','superseded','cancelled');

ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS assignment_owner_issuer text;
ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS assignment_owner_subject text;
ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS assigned_by_issuer text;
ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS assigned_by_subject text;
ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS assignment_absence_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE casework_hosted_items ADD COLUMN IF NOT EXISTS staffing_diagnostic text
    CHECK (staffing_diagnostic IS NULL OR staffing_diagnostic = 'no_cover_available');
CREATE INDEX IF NOT EXISTS casework_hosted_items_holder_caseload_idx
    ON casework_hosted_items(holder_issuer, holder_subject, queue_id, item_id)
    WHERE state IN ('open','claimed');
CREATE INDEX IF NOT EXISTS casework_hosted_items_holder_caseload_all_idx
    ON casework_hosted_items(holder_issuer, holder_subject, item_id, queue_id)
    WHERE state IN ('open','claimed');

CREATE TABLE IF NOT EXISTS casework_assignment_cursors (
    cursor_id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    profile_id text NOT NULL,
    context_hash text NOT NULL,
    last_item_id uuid NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS casework_assignment_cursors_expiry_idx
    ON casework_assignment_cursors(expires_at, cursor_id);

CREATE INDEX IF NOT EXISTS casework_items_assignment_reconciliation_idx
    ON casework_items(item_id, queue_id, holder_issuer, holder_subject)
    WHERE state = 'claimed' AND holder_issuer IS NOT NULL;
CREATE INDEX IF NOT EXISTS casework_hosted_items_assignment_reconciliation_idx
    ON casework_hosted_items(item_id, queue_id, holder_issuer, holder_subject)
    WHERE state = 'claimed' AND holder_issuer IS NOT NULL;
