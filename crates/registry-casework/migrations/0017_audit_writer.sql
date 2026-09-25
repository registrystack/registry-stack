-- Casework writes its audit entries through the process audit writer, so the
-- database holds no audit state. The task-grant invalidation function records
-- only the history event; the transaction that caused the invalidation reads
-- those events back before it commits and writes their audit entries after.
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
        VALUES(gen_random_uuid(),lost.item_id,lost.revision,'task_invalidated',now(),'system:task-grants',jsonb_build_object('grantId',lost.grant_id));
    END LOOP;
END;
$$;

-- The invalidations one transaction recorded are found by their start time.
CREATE INDEX IF NOT EXISTS casework_history_task_invalidated_idx
    ON casework_history(occurred_at)
    WHERE kind='task_invalidated' AND profile_id='system:task-grants';

DROP TABLE casework_audit_outbox;
