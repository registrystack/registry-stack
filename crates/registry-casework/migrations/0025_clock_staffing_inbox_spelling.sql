-- The multi-word clock, staffing, assignment, and inbox words are spelled in
-- kebab-case, as every other closed value Casework reads and writes:
-- `verification-pending` and `source-facts-missing` as clock states,
-- `no-cover-available` as a staffing diagnostic, `absence-cover` as a review
-- task assignment kind, and `my-teams`, `team-holdings`, and
-- `completed-by-me` as inbox views. Rows written with the snake_case spelling
-- are respelled here. No row is removed, no revision moves, and no digest
-- covers a respelled word.

ALTER TABLE casework_items DROP CONSTRAINT casework_items_staffing_diagnostic_check;
UPDATE casework_items SET staffing_diagnostic = 'no-cover-available'
WHERE staffing_diagnostic = 'no_cover_available';
ALTER TABLE casework_items ADD CONSTRAINT casework_items_staffing_diagnostic_check
    CHECK (staffing_diagnostic IS NULL OR staffing_diagnostic = 'no-cover-available');

-- The due index selects on the state, so it is rebuilt over the respelled rows.
DROP INDEX casework_clock_occurrences_due_idx;
ALTER TABLE casework_clock_occurrences DROP CONSTRAINT casework_clock_occurrences_state_check;
UPDATE casework_clock_occurrences SET state = 'verification-pending'
WHERE state = 'verification_pending';
UPDATE casework_clock_occurrences SET state = 'source-facts-missing'
WHERE state = 'source_facts_missing';
ALTER TABLE casework_clock_occurrences ADD CONSTRAINT casework_clock_occurrences_state_check
    CHECK (state IN ('running','paused','completed','cancelled','verification-pending','source-facts-missing'));
CREATE INDEX casework_clock_occurrences_due_idx
    ON casework_clock_occurrences(next_action_at, clock_occurrence_id)
    WHERE state IN ('running','verification-pending') AND next_action_at IS NOT NULL;

ALTER TABLE casework_review_tasks DROP CONSTRAINT casework_review_tasks_assignment_kind_check;
ALTER TABLE casework_review_tasks DROP CONSTRAINT casework_review_tasks_staffing_diagnostic_check;
UPDATE casework_review_tasks SET assignment_kind = 'absence-cover'
WHERE assignment_kind = 'absence_cover';
UPDATE casework_review_tasks SET staffing_diagnostic = 'no-cover-available'
WHERE staffing_diagnostic = 'no_cover_available';
ALTER TABLE casework_review_tasks ADD CONSTRAINT casework_review_tasks_assignment_kind_check
    CHECK (assignment_kind IS NULL OR assignment_kind IN ('claim','nomination','delegation','absence-cover'));
ALTER TABLE casework_review_tasks ADD CONSTRAINT casework_review_tasks_staffing_diagnostic_check
    CHECK (staffing_diagnostic IS NULL OR staffing_diagnostic = 'no-cover-available');

-- The missing-facts index selects on the state, so it is rebuilt too.
DROP INDEX casework_review_clock_missing_facts_idx;
ALTER TABLE casework_review_clock_occurrences
    DROP CONSTRAINT casework_review_clock_occurrences_state_check;
UPDATE casework_review_clock_occurrences SET state = 'source-facts-missing'
WHERE state = 'source_facts_missing';
ALTER TABLE casework_review_clock_occurrences
    ADD CONSTRAINT casework_review_clock_occurrences_state_check
    CHECK (state IN ('running','paused','completed','cancelled','source-facts-missing'));
CREATE INDEX casework_review_clock_missing_facts_idx
    ON casework_review_clock_occurrences(updated_at,clock_occurrence_id)
    WHERE scope='activity' AND state='source-facts-missing';

-- Review history details are read back as they were written. The assignment
-- kind of an assignment entry is Casework's word; its reason is the caller's
-- text and stays as it was sent.
UPDATE casework_review_history
SET detail = jsonb_set(detail, '{assignmentKind}', to_jsonb('absence-cover'::text))
WHERE kind IN ('task-absence-reconciled','task-assigned','task-delegated')
  AND detail->>'assignmentKind' = 'absence_cover';

-- A retained item response is deserialized into the type that wrote it, so
-- it is respelled with the type. Its request digest was computed over the
-- request as it was sent and stays as it is.
UPDATE casework_idempotency
SET response = jsonb_set(response, '{assignment,staffingDiagnostic}', to_jsonb('no-cover-available'::text))
WHERE operation IN ('item.claim','item.release','item.assigned','item.delegated','item.caseload-moved')
  AND response #>> '{assignment,staffingDiagnostic}' = 'no_cover_available';

-- An inbox cursor holds the listing it continues as compact JSON text, which
-- the runtime compares whole. Only the view member is respelled: inside a
-- queue or subject value the quotation marks of this pattern are escaped, so
-- the pattern matches the member alone.
UPDATE casework_cursors SET context = replace(context, '"view":"my_teams"', '"view":"my-teams"')
WHERE position('"view":"my_teams"' in context) > 0;
UPDATE casework_cursors SET context = replace(context, '"view":"team_holdings"', '"view":"team-holdings"')
WHERE position('"view":"team_holdings"' in context) > 0;
UPDATE casework_cursors SET context = replace(context, '"view":"completed_by_me"', '"view":"completed-by-me"')
WHERE position('"view":"completed_by_me"' in context) > 0;
