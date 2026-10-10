-- The multi-word history and event words are spelled in kebab-case, as every
-- other closed value Casework reads and writes: the kind of an item history
-- entry and of its item event, the kind of a review history entry, the kind
-- of a directory event, the settlement outcome and the two release reasons
-- Casework itself writes into an item history detail, and the operation name
-- of a retained caseload move. Rows written with the snake_case spelling are
-- respelled here. No row is removed, and no digest covers a respelled word:
-- the request hash of a retained operation is left as it was written.

UPDATE casework_history
SET kind = replace(kind, '_', '-')
WHERE kind IN (
    'caseload_moved','draft_saved','task_approved','task_revoked','task_invalidated',
    'attempt_reserved','attempt_uncertain','action_completed','attempt_settled',
    'clock_reminder','clock_step_applied','clock_recomputed');
UPDATE casework_events
SET event_kind = replace(event_kind, '_', '-')
WHERE event_kind IN (
    'caseload_moved','draft_saved','task_approved','task_revoked','task_invalidated',
    'attempt_reserved','attempt_uncertain','action_completed','attempt_settled',
    'clock_reminder','clock_step_applied','clock_recomputed');

-- A settlement records what the operator established. Its reason is the
-- operator's own text and is left alone.
UPDATE casework_history
SET detail = jsonb_set(detail, '{outcome}', to_jsonb('not-applied'::text))
WHERE kind = 'attempt-settled' AND detail->>'outcome' = 'not_applied';
UPDATE casework_events
SET detail = jsonb_set(detail, '{outcome}', to_jsonb('not-applied'::text))
WHERE event_kind = 'attempt-settled' AND detail->>'outcome' = 'not_applied';

-- A release Casework itself decides names its reason with a closed word. A
-- reason a caller gave is free text and is left alone, so the rewrite is held
-- to the two system profiles that write the closed words.
UPDATE casework_events e
SET detail = jsonb_set(e.detail, '{reason}', to_jsonb('source-observation'::text))
FROM casework_history h
WHERE h.event_id = e.event_id
  AND h.kind = 'released' AND h.profile_id = 'system:reconciliation'
  AND e.detail->>'reason' = 'source_observation';
UPDATE casework_history
SET detail = jsonb_set(detail, '{reason}', to_jsonb('source-observation'::text))
WHERE kind = 'released' AND profile_id = 'system:reconciliation'
  AND detail->>'reason' = 'source_observation';
UPDATE casework_events e
SET detail = jsonb_set(e.detail, '{reason}', to_jsonb('directory-membership-changed'::text))
FROM casework_history h
WHERE h.event_id = e.event_id
  AND h.kind = 'released' AND h.profile_id = 'system:directory-reconciliation'
  AND e.detail->>'reason' = 'directory_membership_changed';
UPDATE casework_history
SET detail = jsonb_set(detail, '{reason}', to_jsonb('directory-membership-changed'::text))
WHERE kind = 'released' AND profile_id = 'system:directory-reconciliation'
  AND detail->>'reason' = 'directory_membership_changed';

UPDATE casework_review_history
SET kind = replace(kind, '_', '-')
WHERE kind IN (
    'clock_reminder','clock_step_applied','request_created','review_cancelled',
    'review_created','review_decided','review_settled','review_superseded',
    'stage_advanced','task_absence_reconciled','task_assigned','task_claimed',
    'task_delegated','task_draft_saved','task_grant_approved','task_grant_invalidated',
    'task_grant_revoked','task_released');

UPDATE casework_directory_events
SET event_kind = replace(event_kind, '_', '-')
WHERE event_kind IN (
    'directory_bootstrapped','team_updated','absence_created','absence_updated',
    'absence_deleted');

-- A retained caseload move is found again under its operation name. Its
-- request hash does not cover the name.
UPDATE casework_idempotency
SET operation = 'item.caseload-moved'
WHERE operation = 'item.caseload_moved';

-- The task-grant invalidation function writes the history kind, and the
-- index that finds the invalidations of one transaction selects on it.
CREATE OR REPLACE FUNCTION casework_invalidate_ineligible_tasks(target_item uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    lost record;
BEGIN
    FOR lost IN
        UPDATE casework_task_grants g
        SET invalidated_at=now(), invalidation_reason='eligibility'
        FROM casework_items i
        WHERE i.item_id=g.item_id
          AND (target_item IS NULL OR i.item_id=target_item)
          AND g.invalidated_at IS NULL
          AND g.expires_at>now()
          AND (
              i.erased_at IS NOT NULL
              OR i.holder_issuer IS DISTINCT FROM g.approver_issuer
              OR i.holder_subject IS DISTINCT FROM g.approver_subject
              OR NOT (g.record->'template'->'itemStates' ? i.state)
              OR i.source_id IS DISTINCT FROM g.record->'template'->>'source'
              OR NOT (g.record->'template'->'itemKinds' ? i.subject_kind)
              OR i.binding->>'version' IS DISTINCT FROM g.record->'proposal'->>'version'
              OR i.binding->>'integrity' IS DISTINCT FROM g.record->'proposal'->>'integrity'
              OR i.binding->>'generation' IS DISTINCT FROM g.record->'proposal'->>'generation'
              OR NOT EXISTS (
                  SELECT 1 FROM casework_memberships m
                  JOIN casework_queue_service q ON q.team_id=m.team_id
                  WHERE m.issuer=g.approver_issuer AND m.subject=g.approver_subject
                    AND m.membership_kind=g.approver_role
                    AND g.record->'template'->'eligibleTeams' ? m.team_id
                    AND q.queue_id=i.queue_id
              )
          )
        RETURNING g.grant_id, i.item_id, i.revision
    LOOP
        INSERT INTO casework_history(event_id,item_id,item_revision,kind,occurred_at,profile_id,detail)
        VALUES(gen_random_uuid(),lost.item_id,lost.revision,'task-invalidated',now(),'system:task-grants',jsonb_build_object('grantId',lost.grant_id));
    END LOOP;
END;
$$;

DROP INDEX casework_history_task_invalidated_idx;
CREATE INDEX casework_history_task_invalidated_idx
    ON casework_history(occurred_at)
    WHERE kind='task-invalidated' AND profile_id='system:task-grants';
