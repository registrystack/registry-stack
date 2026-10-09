-- Exact selection belongs to the existing minimized accountability record.
-- Its label is resolved against the request's retained immutable policy.
ALTER TABLE casework_review_accountability
    ADD COLUMN outcome text CHECK (outcome IS NULL OR octet_length(outcome) BETWEEN 1 AND 128);

-- Recover legacy selections only while their original result window permits
-- reading them. Expired/erased selections stay unavailable, never guessed.
UPDATE casework_review_accountability a SET outcome=d.outcome
FROM casework_review_decisions d,casework_review_requests r
WHERE d.task_id=a.task_id AND d.request_id=a.request_id AND r.request_id=a.request_id
  AND d.actor_issuer=a.actor_issuer AND d.actor_subject=a.actor_subject
  AND r.result_erased_at IS NULL
  AND (r.lifecycle='reviewing' OR r.result_available_until>now());

-- Neither task nor request indexes can seek one author's newest decisions.
CREATE INDEX casework_review_decision_author_position_idx
    ON casework_review_decisions(actor_issuer,actor_subject,decided_at DESC,task_id DESC);
