-- A superseded occurrence is terminal and never matched again, so its identity
-- stays reserved only while the occurrence is not superseded. Returning a source
-- to an earlier package or binding generation derives the same occurrence key as
-- the item that generation left behind; that observation opens a fresh item
-- beside the superseded one. The drop and the create share one transaction, so
-- the constraint is never observably absent.
DROP INDEX IF EXISTS casework_items_occurrence_idx;
CREATE UNIQUE INDEX casework_items_occurrence_idx
    ON casework_items(source_id, subject_kind, subject_id, occurrence_key)
    WHERE state <> 'superseded';
