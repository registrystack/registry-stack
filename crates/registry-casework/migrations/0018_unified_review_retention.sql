-- Keep PostgreSQL's expanded jsonb rendering from rejecting context and draft
-- values that passed their respective canonical JSON admission bounds. One
-- MiB safely covers numeric exponent expansion while retaining a hard limit.
ALTER TABLE casework_review_requests
    DROP CONSTRAINT casework_review_requests_context_check;
ALTER TABLE casework_review_requests
    ADD CONSTRAINT casework_review_requests_context_check
    CHECK (octet_length(context::text) <= 1048576);

ALTER TABLE casework_review_task_drafts
    DROP CONSTRAINT casework_review_task_drafts_body_check;
ALTER TABLE casework_review_task_drafts
    ADD CONSTRAINT casework_review_task_drafts_body_check
    CHECK (octet_length(body::text) <= 1048576);

-- Drafts are private to their authors. A later holder gets a separate draft
-- rather than replacing the prior holder's retained private work.
ALTER TABLE casework_review_task_drafts
    DROP CONSTRAINT casework_review_task_drafts_pkey;
ALTER TABLE casework_review_task_drafts
    ADD CONSTRAINT casework_review_task_drafts_pkey
    PRIMARY KEY (task_id, actor_issuer, actor_subject);

-- Result erasure precedes accountability erasure. Record completion so a
-- bounded cleanup pass does not continually relock already-scrubbed requests
-- while their minimized accountability rows remain retained.
ALTER TABLE casework_review_requests
    ADD COLUMN result_erased_at timestamptz;
ALTER TABLE casework_review_requests
    ADD CONSTRAINT casework_review_requests_result_erased_check
    CHECK (
        result_erased_at IS NULL
        OR (terminal_at IS NOT NULL AND result_available_until IS NOT NULL)
    );
CREATE INDEX casework_review_requests_pending_result_erasure_idx
    ON casework_review_requests(result_available_until,request_id)
    WHERE terminal_at IS NOT NULL AND result_erased_at IS NULL;

-- Earlier-stage decisions may predate terminal settlement by longer than the
-- accountability period. Align every surviving minimized record to the
-- request's terminal-settlement deadline before cleanup can observe it.
UPDATE casework_review_accountability a
   SET retained_until=r.accountability_retained_until
  FROM casework_review_requests r
 WHERE a.request_id=r.request_id
   AND r.terminal_at IS NOT NULL
   AND r.accountability_retained_until IS NOT NULL
   AND a.retained_until IS DISTINCT FROM r.accountability_retained_until;

-- Review idempotency rows share the product-wide table, so retain explicit
-- request ownership. This makes accountability-expiry deletion exact even
-- after response payloads have already been scrubbed.
ALTER TABLE casework_idempotency
    ADD COLUMN review_request_id uuid;

UPDATE casework_idempotency i
   SET review_request_id=r.request_id
  FROM casework_review_requests r
 WHERE i.operation LIKE 'review.%'
   AND i.resource='review-request:'||r.request_id::text;

UPDATE casework_idempotency i
   SET review_request_id=t.request_id
  FROM casework_review_tasks t
 WHERE i.operation LIKE 'review.%'
   AND i.review_request_id IS NULL
   AND i.resource='review-task:'||t.task_id::text;

UPDATE casework_idempotency i
   SET review_request_id=r.request_id
  FROM casework_review_requests r
 WHERE i.operation='review.create'
   AND i.review_request_id IS NULL
   AND i.resource='review-producer:'||r.producer_id
   AND i.request_hash=r.submission_digest;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM casework_idempotency
         WHERE operation LIKE 'review.%' AND review_request_id IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unowned unified-review idempotency state cannot be migrated',
            HINT = 'restore the matching review request and task state or remove only confirmed disposable review idempotency rows before retrying';
    END IF;
END
$$;

ALTER TABLE casework_idempotency
    ADD CONSTRAINT casework_idempotency_review_request_fkey
    FOREIGN KEY (review_request_id)
    REFERENCES casework_review_requests(request_id) ON DELETE CASCADE;
ALTER TABLE casework_idempotency
    ADD CONSTRAINT casework_idempotency_review_owner_check
    CHECK ((operation LIKE 'review.%') = (review_request_id IS NOT NULL));
CREATE INDEX casework_idempotency_review_request_idx
    ON casework_idempotency(review_request_id)
    WHERE review_request_id IS NOT NULL;
