-- A version is immutable even after it is retired. Reactivation can select
-- an existing identical version, but cannot replace its policy in place.
CREATE TABLE casework_task_templates (
    template_id text NOT NULL,
    template_version text NOT NULL,
    document jsonb NOT NULL CHECK (octet_length(document::text) <= 65536),
    active boolean NOT NULL DEFAULT false,
    PRIMARY KEY(template_id,template_version)
);
CREATE UNIQUE INDEX casework_task_templates_active_idx
ON casework_task_templates(template_id) WHERE active;

-- Immutable task bounds live with their source item and its erasure lifecycle.
CREATE TABLE casework_task_grants (
    grant_id uuid PRIMARY KEY,
    item_id uuid NOT NULL REFERENCES casework_items(item_id) ON DELETE CASCADE,
    approver_issuer text NOT NULL,
    approver_subject text NOT NULL,
    approver_profile text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    record jsonb NOT NULL CHECK (octet_length(record::text) <= 65536),
    approved_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > approved_at AND expires_at <= approved_at + interval '900 seconds'),
    invalidated_at timestamptz,
    invalidation_reason text CHECK (invalidation_reason IN ('revoked','eligibility','template','source')),
    UNIQUE(item_id, approver_issuer, approver_subject, approver_profile, idempotency_key)
);
CREATE INDEX casework_task_grants_active_idx ON casework_task_grants(expires_at,item_id) WHERE invalidated_at IS NULL;
CREATE INDEX casework_task_grants_item_idx ON casework_task_grants(item_id, approved_at, grant_id);

-- Directory writers replace membership rows inside a transaction. Evaluate
-- eligibility only after they advance the serialized directory revision, so an
-- unchanged replacement does not revoke grants during its temporary delete.
CREATE FUNCTION casework_invalidate_ineligible_tasks(target_item uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    lost record;
    event uuid;
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
                    AND m.membership_kind IN ('staff','supervisor')
                    AND g.record->'template'->'eligibleTeams' ? m.team_id
                    AND q.queue_id=i.queue_id
              )
          )
        RETURNING g.grant_id, i.item_id, i.revision
    LOOP
        event := gen_random_uuid();
        INSERT INTO casework_history(event_id,item_id,item_revision,kind,occurred_at,profile_id,detail)
        VALUES(event,lost.item_id,lost.revision,'task_invalidated',now(),'system:task-grants',jsonb_build_object('grantId',lost.grant_id));
        INSERT INTO casework_audit_outbox(event_id,audit_record)
        VALUES(event,jsonb_build_object('event','casework.task_invalidated','eventId',event,'itemId',lost.item_id,'grantId',lost.grant_id,'profileId','system:task-grants'));
    END LOOP;
END;
$$;

CREATE FUNCTION casework_task_directory_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM casework_invalidate_ineligible_tasks(NULL);
    RETURN NEW;
END;
$$;
CREATE TRIGGER casework_task_directory_changed
AFTER UPDATE OF directory_revision ON casework_meta FOR EACH ROW
EXECUTE FUNCTION casework_task_directory_changed();

CREATE FUNCTION casework_task_item_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.erased_at IS NOT NULL THEN
        -- Grant records contain the disclosed subject selectors. They belong to
        -- the same erasure boundary as the source item, not its tombstone.
        DELETE FROM casework_task_grants WHERE item_id=NEW.item_id;
    ELSE
        PERFORM casework_invalidate_ineligible_tasks(NEW.item_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER casework_task_item_changed
AFTER UPDATE OF holder_issuer,holder_subject,state,queue_id,binding,erased_at
ON casework_items FOR EACH ROW EXECUTE FUNCTION casework_task_item_changed();
