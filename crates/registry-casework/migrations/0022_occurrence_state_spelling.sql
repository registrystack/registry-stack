-- The two waiting item states are spelled in kebab-case, as every other
-- closed value Casework reads and writes. Rows written with the snake_case
-- spelling are respelled here, in an order that keeps live task grants valid:
-- the item trigger compares an item's state with the states its grant's
-- template lists, so templates and grant records are respelled before items.

-- A stored template document is compared with the packaged template by JSON
-- equality and carries no digest, so it is rewritten in place.
UPDATE casework_task_templates
SET document = jsonb_set(document, '{itemStates}', (
    SELECT jsonb_agg(
        CASE listed.state #>> '{}'
            WHEN 'waiting_applicant' THEN to_jsonb('waiting-applicant'::text)
            WHEN 'waiting_application' THEN to_jsonb('waiting-application'::text)
            ELSE listed.state
        END ORDER BY listed.position)
    FROM jsonb_array_elements(document->'itemStates') WITH ORDINALITY AS listed(state, position)))
WHERE jsonb_typeof(document->'itemStates') = 'array'
  AND document->'itemStates' ?| ARRAY['waiting_applicant','waiting_application'];

-- A grant record embeds the template it was approved under.
UPDATE casework_task_grants
SET record = jsonb_set(record, '{template,itemStates}', (
    SELECT jsonb_agg(
        CASE listed.state #>> '{}'
            WHEN 'waiting_applicant' THEN to_jsonb('waiting-applicant'::text)
            WHEN 'waiting_application' THEN to_jsonb('waiting-application'::text)
            ELSE listed.state
        END ORDER BY listed.position)
    FROM jsonb_array_elements(record->'template'->'itemStates') WITH ORDINALITY AS listed(state, position)))
WHERE jsonb_typeof(record->'template'->'itemStates') = 'array'
  AND record->'template'->'itemStates' ?| ARRAY['waiting_applicant','waiting_application'];

ALTER TABLE casework_items DROP CONSTRAINT casework_items_state_check;
UPDATE casework_items SET state = 'waiting-applicant' WHERE state = 'waiting_applicant';
UPDATE casework_items SET state = 'waiting-application' WHERE state = 'waiting_application';
ALTER TABLE casework_items ADD CONSTRAINT casework_items_state_check
    CHECK (state IN ('open','claimed','waiting-applicant','waiting-application','synchronizing','completed','superseded','cancelled'));
