-- Exact selection belongs to the existing minimized accountability record.
-- Its label is resolved against the request's retained immutable policy.
ALTER TABLE casework_review_accountability
    ADD COLUMN outcome text CHECK (outcome IS NULL OR octet_length(outcome) BETWEEN 1 AND 128);

-- Neither task nor request indexes can seek one author's newest decisions.
CREATE INDEX casework_review_decision_author_position_idx
    ON casework_review_decisions(actor_issuer,actor_subject,decided_at DESC,task_id DESC);
