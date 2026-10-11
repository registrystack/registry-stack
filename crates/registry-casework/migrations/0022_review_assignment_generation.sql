-- Keep immediate grants bounded to fifteen minutes. Longer stored authority
-- requires the explicit governed deferred mode; credentials stay short-lived.
ALTER TABLE casework_task_grants DROP CONSTRAINT casework_task_grants_check;
ALTER TABLE casework_task_grants ADD CONSTRAINT casework_task_grants_authorization_window CHECK (
    expires_at > approved_at
    AND COALESCE(record->'template'->>'authorizationMode', 'immediate') IN ('immediate', 'deferred')
    AND expires_at <= approved_at + CASE record->'template'->>'authorizationMode'
        WHEN 'deferred' THEN interval '604800 seconds' ELSE interval '900 seconds' END
);
ALTER TABLE casework_review_task_grants DROP CONSTRAINT casework_review_task_grants_check;
ALTER TABLE casework_review_task_grants ADD CONSTRAINT casework_review_task_grants_authorization_window CHECK (
    expires_at > approved_at
    AND COALESCE(record->'template'->>'authorizationMode', 'immediate') IN ('immediate', 'deferred')
    AND expires_at <= approved_at + CASE record->'template'->>'authorizationMode'
        WHEN 'deferred' THEN interval '604800 seconds' ELSE interval '900 seconds' END
);

-- Separate responsibility changes from ordinary draft revisions. A released,
-- reassigned, completed, or queue-moved task cannot revive an old authorization
-- by returning to its former holder before a status check observes the change.
ALTER TABLE casework_review_tasks
    ADD COLUMN assignment_generation bigint NOT NULL DEFAULT 1
    CHECK (assignment_generation > 0);

CREATE FUNCTION casework_review_assignment_generation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.state, NEW.queue_id, NEW.holder_issuer, NEW.holder_subject,
           NEW.assignment_owner_issuer, NEW.assignment_owner_subject,
           NEW.assignment_kind, NEW.assignment_absence_ids)
       IS DISTINCT FROM
       ROW(OLD.state, OLD.queue_id, OLD.holder_issuer, OLD.holder_subject,
           OLD.assignment_owner_issuer, OLD.assignment_owner_subject,
           OLD.assignment_kind, OLD.assignment_absence_ids) THEN
        NEW.assignment_generation := OLD.assignment_generation + 1;
    ELSE
        NEW.assignment_generation := OLD.assignment_generation;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER casework_review_assignment_generation
BEFORE UPDATE ON casework_review_tasks
FOR EACH ROW EXECUTE FUNCTION casework_review_assignment_generation();
