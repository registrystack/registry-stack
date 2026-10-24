-- Counted resources describe physical stock. Zero is a valid current fact:
-- confirmed commitments remain historical truth while new allocations stop.
ALTER TABLE scheduling_pool_members
    ADD COLUMN capacity_units integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT scheduling_pool_members_capacity_units_check
        CHECK (capacity_units BETWEEN 0 AND 2147483647);

-- One claim remains the logical hold or appointment. These rows are its
-- physical allocations. Resource and anchor identifiers intentionally do not
-- reference current fact tables: an operator must be able to record loss or
-- retirement without deleting what a retained commitment allocated.
CREATE TABLE scheduling_claim_allocations (
    claim_id uuid NOT NULL REFERENCES scheduling_claims(claim_id),
    requirement_kind text NOT NULL
        CHECK (requirement_kind IN ('primary', 'additional')),
    requirement_index smallint NOT NULL,
    part_index smallint NOT NULL CHECK (part_index BETWEEN 0 AND 255),
    allocation_scope_version smallint NOT NULL DEFAULT 1,
    offering text NOT NULL CHECK (offering <> ''),
    operational_service text,
    operational_location text,
    operational_mode text,
    anchor_id text,
    resource_id text NOT NULL CHECK (resource_id <> ''),
    occupied_start timestamptz NOT NULL,
    occupied_end timestamptz NOT NULL,
    units integer NOT NULL CHECK (units > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (claim_id, requirement_kind, requirement_index, part_index),
    UNIQUE (claim_id, resource_id),
    CONSTRAINT scheduling_claim_allocations_requirement_check CHECK (
        (requirement_kind = 'primary' AND requirement_index = 0)
        OR
        (requirement_kind = 'additional' AND requirement_index BETWEEN 0 AND 14)
    ),
    CONSTRAINT scheduling_claim_allocations_interval_check
        CHECK (occupied_start < occupied_end),
    CONSTRAINT scheduling_claim_allocations_scope_check CHECK (
        (allocation_scope_version = 0
            AND operational_service IS NULL
            AND operational_location IS NULL
            AND operational_mode IS NULL
            AND anchor_id IS NULL)
        OR
        (allocation_scope_version = 1
            AND operational_service IS NOT NULL
            AND operational_service <> ''
            AND operational_location IS NOT NULL
            AND operational_location <> ''
            AND operational_mode IN ('exact-time', 'arrival-window')
            AND anchor_id IS NOT NULL
            AND anchor_id <> '')
    )
);

-- Backfill every legacy claim as one primary allocation. Version 0 keeps the
-- claim's resource identity, and so its capacity, without pretending an
-- anchor or security label was recovered. Claim labels are materialized only
-- after every pending migration applies, so in an upgrade from the 1.0
-- baseline each claim written before it backfills as version 0 here, as does
-- a closed historical claim naming supply no longer present in current facts.
-- The rematerialization that follows the migrations relabels a version-0 row
-- once its claim has labels and its resource a current anchor.
WITH resolved AS (
    SELECT
        c.claim_id,
        c.offering,
        c.operational_service,
        c.operational_location,
        c.operational_mode,
        COALESCE(m.pool_id, w.supply_id) AS anchor_id,
        c.supply_id AS resource_id,
        c.occupied_start,
        c.occupied_end,
        c.units,
        CASE
            WHEN c.operational_scope_version = 1
                AND c.operational_service IS NOT NULL
                AND c.operational_location IS NOT NULL
                AND c.operational_mode IS NOT NULL
                AND COALESCE(m.pool_id, w.supply_id) IS NOT NULL
            THEN 1
            ELSE 0
        END AS allocation_scope_version
    FROM scheduling_claims AS c
    LEFT JOIN scheduling_pool_members AS m
        ON m.resource_id = c.supply_id
    LEFT JOIN scheduling_supply AS w
        ON w.supply_id = c.supply_id AND w.kind = 'window'
)
INSERT INTO scheduling_claim_allocations(
    claim_id,
    requirement_kind,
    requirement_index,
    part_index,
    allocation_scope_version,
    offering,
    operational_service,
    operational_location,
    operational_mode,
    anchor_id,
    resource_id,
    occupied_start,
    occupied_end,
    units
)
SELECT
    claim_id,
    'primary',
    0,
    0,
    allocation_scope_version,
    offering,
    CASE WHEN allocation_scope_version = 1 THEN operational_service END,
    CASE WHEN allocation_scope_version = 1 THEN operational_location END,
    CASE WHEN allocation_scope_version = 1 THEN operational_mode END,
    CASE WHEN allocation_scope_version = 1 THEN anchor_id END,
    resource_id,
    occupied_start,
    occupied_end,
    units
FROM resolved;

CREATE INDEX scheduling_claim_allocations_anchor_interval_idx
    ON scheduling_claim_allocations(anchor_id, occupied_start, occupied_end, claim_id)
    WHERE allocation_scope_version = 1;
CREATE INDEX scheduling_claim_allocations_resource_interval_idx
    ON scheduling_claim_allocations(resource_id, occupied_start, occupied_end, claim_id);
CREATE INDEX scheduling_claim_allocations_offering_idx
    ON scheduling_claim_allocations(offering, claim_id);

-- A runtime that started before this migration knows only the single supply
-- column on scheduling_claims. If it wrote after the migration, it could
-- overbook child allocations or change only one part of a logical bundle.
-- Every new runtime transaction that mutates logical claims or current
-- physical supply must first execute:
--
--     SET LOCAL registry_scheduling.allocation_writer = 'v2'
--
-- This is a mixed-version fail-closed fence, not an authorization boundary.
-- The activation trust check must recognize these migration-owned triggers
-- before this draft is added to SCHEMA_VERSIONS.
CREATE FUNCTION scheduling_require_allocation_writer_v2()
RETURNS trigger
LANGUAGE plpgsql
AS $body$
BEGIN
    IF current_setting('registry_scheduling.allocation_writer', true) IS DISTINCT FROM 'v2' THEN
        RAISE EXCEPTION 'the Scheduling writer predates atomic allocations'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$body$;

CREATE TRIGGER scheduling_claims_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_claims
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_claim_allocations_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_claim_allocations
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_pool_members_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_pool_members
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_pools_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_pools
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_supply_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_supply
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_windows_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_windows
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_window_revision_heads_allocation_writer_v2
    BEFORE INSERT OR UPDATE OR DELETE ON scheduling_window_revision_heads
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
CREATE TRIGGER scheduling_meta_allocation_writer_v2
    BEFORE UPDATE OR DELETE ON scheduling_meta
    FOR EACH ROW EXECUTE FUNCTION scheduling_require_allocation_writer_v2();
