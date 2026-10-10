-- The multi-word review outcome words are spelled in kebab-case, as every
-- other closed value Casework reads and writes: `changes-requested` as a
-- request lifecycle, a result status, a reviewer decision, and a settlement;
-- `stage-advanced` as a decision transition; `already-terminal` as a
-- cancellation outcome. Rows written with the snake_case spelling are
-- respelled here. No row is removed, and no digest covers a respelled word.

ALTER TABLE casework_review_requests DROP CONSTRAINT casework_review_requests_lifecycle_check;
UPDATE casework_review_requests SET lifecycle = 'changes-requested' WHERE lifecycle = 'changes_requested';
ALTER TABLE casework_review_requests ADD CONSTRAINT casework_review_requests_lifecycle_check
    CHECK (lifecycle IN ('reviewing','approved','rejected','changes-requested','answered','cancelled','superseded'));

ALTER TABLE casework_review_decisions DROP CONSTRAINT casework_review_decisions_decision_check;
ALTER TABLE casework_review_decisions DROP CONSTRAINT casework_review_decisions_check;
UPDATE casework_review_decisions SET decision = 'changes-requested' WHERE decision = 'changes_requested';
ALTER TABLE casework_review_decisions ADD CONSTRAINT casework_review_decisions_decision_check
    CHECK (decision IN ('approve','reject','changes-requested','answer'));
ALTER TABLE casework_review_decisions ADD CONSTRAINT casework_review_decisions_check
    CHECK (
        (decision = 'approve' AND outcome IS NULL AND result IS NULL)
        OR (decision IN ('reject','changes-requested','answer') AND outcome IS NOT NULL)
    );

ALTER TABLE casework_review_results DROP CONSTRAINT casework_review_results_status_check;
ALTER TABLE casework_review_results DROP CONSTRAINT casework_review_results_check2;
UPDATE casework_review_results SET status = 'changes-requested' WHERE status = 'changes_requested';
ALTER TABLE casework_review_results ADD CONSTRAINT casework_review_results_status_check
    CHECK (status IN ('approved','rejected','changes-requested','answered','cancelled','superseded'));
ALTER TABLE casework_review_results ADD CONSTRAINT casework_review_results_check2
    CHECK (status NOT IN ('rejected','changes-requested','answered') OR outcome IS NOT NULL);

-- The accountability row keeps the decision word under a length bound only.
UPDATE casework_review_accountability SET decision = 'changes-requested' WHERE decision = 'changes_requested';

-- Review history details are read back as they were written.
UPDATE casework_review_history
SET detail = jsonb_set(detail, '{decision}', to_jsonb('changes-requested'::text))
WHERE detail->>'decision' = 'changes_requested';
UPDATE casework_review_history
SET detail = jsonb_set(detail, '{transition}', to_jsonb(replace(detail->>'transition', '_', '-')))
WHERE detail->>'transition' IN ('changes_requested','stage_advanced');
UPDATE casework_review_history
SET detail = jsonb_set(detail, '{status}', to_jsonb('changes-requested'::text))
WHERE kind = 'review_settled' AND detail->>'status' = 'changes_requested';

-- A retained replay response is deserialized into the type that wrote it, so
-- it is respelled with the type. Its request digest was computed over the
-- request as it was sent and stays as it is.
UPDATE casework_idempotency
SET response = jsonb_set(response, '{type}', to_jsonb('stage-advanced'::text))
WHERE operation = 'review.task.decide' AND response->>'type' = 'stage_advanced';
UPDATE casework_idempotency
SET response = jsonb_set(response, '{settlement,status}', to_jsonb('changes-requested'::text))
WHERE operation = 'review.task.decide' AND response #>> '{settlement,status}' = 'changes_requested';
UPDATE casework_idempotency
SET response = jsonb_set(response, '{outcome}', to_jsonb('already-terminal'::text))
WHERE operation = 'review.cancel' AND response->>'outcome' = 'already_terminal';
UPDATE casework_idempotency
SET response = jsonb_set(response, '{result,status}', to_jsonb('changes-requested'::text))
WHERE operation = 'review.cancel' AND response #>> '{result,status}' = 'changes_requested';
