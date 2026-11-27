-- SPDX-License-Identifier: Apache-2.0
--
-- A reviewer who holds a task can ask the subject's owner for more. The ask
-- belongs to the request and names the task that asked. The producer reads the
-- ask through its own feed and reports the answer without carrying its text.

CREATE TABLE casework_review_asks (
    ask_id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    task_id uuid NOT NULL,
    stage_index integer NOT NULL CHECK (stage_index >= 0),
    text text NOT NULL CHECK (octet_length(text) BETWEEN 1 AND 2000),
    wants jsonb NOT NULL CHECK (jsonb_typeof(wants) = 'array' AND jsonb_array_length(wants) <= 8),
    state text NOT NULL CHECK (state IN ('open','answered','expired','closed')),
    asked_at timestamptz NOT NULL,
    asked_by_ref text NOT NULL CHECK (octet_length(asked_by_ref) BETWEEN 1 AND 256),
    answered_at timestamptz,
    closed_at timestamptz,
    due_at timestamptz,
    CHECK (due_at IS NULL OR due_at > asked_at),
    UNIQUE (ask_id, request_id),
    FOREIGN KEY (task_id, request_id, stage_index)
        REFERENCES casework_review_tasks(task_id, request_id, stage_index) ON DELETE CASCADE,
    CHECK ((state = 'answered') = (answered_at IS NOT NULL)),
    CHECK ((state IN ('expired','closed')) = (closed_at IS NOT NULL)),
    CHECK (answered_at IS NULL OR answered_at >= asked_at)
);
-- One ask is open on a request at a time.
CREATE UNIQUE INDEX casework_review_ask_open_idx
    ON casework_review_asks(request_id)
    WHERE state = 'open';
CREATE INDEX casework_review_ask_request_idx
    ON casework_review_asks(request_id, asked_at, ask_id);

-- The producer's ask feed. An event announces that an ask opened, was answered,
-- expired or closed. The producer reads the ask next.
CREATE TABLE casework_review_ask_events (
    event_id uuid PRIMARY KEY,
    feed_position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    request_id uuid NOT NULL,
    ask_id uuid NOT NULL,
    producer_id text NOT NULL,
    change text NOT NULL CHECK (change IN ('opened','answered','expired','closed')),
    changed_at timestamptz NOT NULL,
    FOREIGN KEY (ask_id, request_id)
        REFERENCES casework_review_asks(ask_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (request_id, producer_id)
        REFERENCES casework_review_requests(request_id, producer_id) ON DELETE CASCADE
);
CREATE INDEX casework_review_ask_feed_idx
    ON casework_review_ask_events(producer_id, feed_position);
CREATE INDEX casework_review_ask_events_request_idx
    ON casework_review_ask_events(request_id);

-- A task marker tells reviewers that an ask waits for the applicant, was
-- answered or expired. It stays with the task through release and
-- reassignment and clears when the task is decided or closed.
ALTER TABLE casework_review_tasks
    ADD COLUMN ask_marker text CHECK (ask_marker IN ('waiting','answered','expired'));
ALTER TABLE casework_review_tasks
    ADD CONSTRAINT casework_review_task_ask_marker_check
    CHECK (ask_marker IS NULL OR state IN ('open','claimed'));

CREATE INDEX casework_review_ask_due_idx
    ON casework_review_asks(due_at, request_id) WHERE state='open' AND due_at IS NOT NULL;

ALTER TABLE casework_review_clock_occurrences
    DROP CONSTRAINT casework_review_clock_occurrences_state_check,
    ADD CONSTRAINT casework_review_clock_occurrences_state_check
        CHECK (state IN ('running','paused','completed','cancelled','source-facts-missing')),
    ADD COLUMN paused_at timestamptz,
    ADD COLUMN paused_duration_micros bigint NOT NULL DEFAULT 0 CHECK (paused_duration_micros >= 0),
    ADD COLUMN paused_ask_id uuid,
    ADD COLUMN paused_state text CHECK (paused_state IN ('running','source-facts-missing')),
    ADD CONSTRAINT casework_review_clock_pause_check
        CHECK ((state='paused') = (paused_at IS NOT NULL)
            AND (state='paused') = (paused_state IS NOT NULL)
            AND (state='paused') = (paused_ask_id IS NOT NULL));

-- A request that resumes an earlier round at its returning stage keeps the
-- staff who decided the earlier round's stages before that stage. They count
-- as previous-stage reviewers of every stage of the resumed request, so
-- separation of duties holds across rounds and outlives the erasure of the
-- earlier round. The rows hold staff identifiers only and are erased with the
-- resumed request's own decisions.
CREATE TABLE casework_review_prior_stage_reviewers (
    request_id uuid NOT NULL REFERENCES casework_review_requests(request_id) ON DELETE CASCADE,
    actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 2048),
    PRIMARY KEY (request_id, actor_issuer, actor_subject)
);
