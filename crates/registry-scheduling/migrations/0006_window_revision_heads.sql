-- Keep the last accepted record for every published-window identifier, even
-- while that window is absent from the active environment records. A later
-- records replacement can therefore distinguish an exact re-publication from
-- changed terms attempting to reuse an observed public revision.
CREATE TABLE IF NOT EXISTS scheduling_window_revision_heads (
    window_id text PRIMARY KEY,
    window_record jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Schema version 5 was never released, but a developer may have exercised it
-- from the review branch. Refuse its formerly accepted overlapping staffing
-- shape during upgrade rather than carrying double-bookable records forward.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM scheduling_windows AS earlier
        JOIN scheduling_windows AS later ON earlier.window_id < later.window_id
        WHERE earlier.window_record #>> '{staffing,pool}' =
              later.window_record #>> '{staffing,pool}'
          AND (earlier.window_record ->> 'start')::timestamptz <
              (later.window_record ->> 'end')::timestamptz
          AND (later.window_record ->> 'start')::timestamptz <
              (earlier.window_record ->> 'end')::timestamptz
    ) THEN
        RAISE EXCEPTION 'overlapping published windows share one staffing pool';
    END IF;
END
$$;

INSERT INTO scheduling_window_revision_heads(window_id, window_record)
SELECT window_id, window_record
FROM scheduling_windows
ON CONFLICT(window_id) DO NOTHING;
