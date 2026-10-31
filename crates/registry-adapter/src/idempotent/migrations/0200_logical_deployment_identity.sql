-- The v0200 runtime changes the opaque scope digest's deployment component
-- from the loaded artifact digest to the stable logical runtime id. Existing
-- v0100 scope digests are one-way: they cannot be safely classified or
-- remapped. Refuse the semantic migration while any such row remains, without
-- altering response custody or spent tombstones. An operator must reconcile
-- those entries before the deployment can adopt the new namespace.
DO $logical_deployment_identity$
BEGIN
    IF EXISTS (SELECT 1 FROM adapter_idempotency_entries LIMIT 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'adapter.idempotency-legacy-deployment-entries';
    END IF;
END
$logical_deployment_identity$;
