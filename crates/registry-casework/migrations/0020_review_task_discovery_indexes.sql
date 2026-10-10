-- Live task walks use an immutable creation position within served queues.
CREATE INDEX casework_review_task_queue_position_idx
    ON casework_review_tasks(queue_id, created_at, task_id);

-- Ownership selection happens before paging, including delegated holdings.
CREATE INDEX casework_review_task_assigned_position_idx
    ON casework_review_tasks(holder_issuer, holder_subject, created_at, task_id)
    WHERE state = 'claimed';

-- Supervisor discovery exposes only a reference to the separate audited read.
CREATE INDEX casework_review_accountability_task_idx
    ON casework_review_accountability(task_id);
