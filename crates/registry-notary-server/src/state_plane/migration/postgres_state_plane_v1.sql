CREATE SCHEMA registry_notary_private AUTHORIZATION CURRENT_USER;
CREATE SCHEMA registry_notary_api AUTHORIZATION CURRENT_USER;

REVOKE ALL ON SCHEMA registry_notary_private FROM PUBLIC;
REVOKE ALL ON SCHEMA registry_notary_api FROM PUBLIC;

CREATE TABLE registry_notary_private.schema_metadata (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    capability_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    schema_fingerprint text NOT NULL CHECK (schema_fingerprint ~ '^[0-9a-f]{64}$'),
    owner_role_oid oid NOT NULL,
    runtime_role_oid oid NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CHECK (owner_role_oid <> runtime_role_oid)
);

CREATE TABLE registry_notary_private.replay_identifier (
    scope_hash bytea NOT NULL CHECK (pg_catalog.octet_length(scope_hash) = 32),
    identifier_hash bytea NOT NULL CHECK (pg_catalog.octet_length(identifier_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope_hash, identifier_hash),
    CHECK (expires_at > created_at)
);
CREATE INDEX replay_identifier_expiry_idx
    ON registry_notary_private.replay_identifier (expires_at);

CREATE TABLE registry_notary_private.consumable_nonce (
    scope_hash bytea NOT NULL CHECK (pg_catalog.octet_length(scope_hash) = 32),
    nonce_hash bytea NOT NULL CHECK (pg_catalog.octet_length(nonce_hash) = 32),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN ('reserved', 'consumed')),
    reservation_expires_at timestamptz NOT NULL,
    tombstone_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (scope_hash, nonce_hash),
    CHECK (
        (state = 'reserved' AND tombstone_expires_at IS NULL)
        OR (state = 'consumed' AND tombstone_expires_at IS NOT NULL)
    )
);
CREATE INDEX consumable_nonce_retention_idx
    ON registry_notary_private.consumable_nonce (
        (CASE WHEN state = 'reserved' THEN reservation_expires_at ELSE tombstone_expires_at END)
    );

CREATE TABLE registry_notary_private.evaluation (
    evaluation_id text PRIMARY KEY CHECK (pg_catalog.length(evaluation_id) BETWEEN 1 AND 256),
    client_id_hash bytea NOT NULL CHECK (pg_catalog.octet_length(client_id_hash) = 32),
    request_hash bytea NOT NULL CHECK (pg_catalog.octet_length(request_hash) = 32),
    purpose text NOT NULL CHECK (pg_catalog.length(purpose) BETWEEN 1 AND 256),
    record_version smallint NOT NULL CHECK (record_version = 2),
    record_json jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(record_json) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX evaluation_client_expiry_idx
    ON registry_notary_private.evaluation (client_id_hash, expires_at);
CREATE INDEX evaluation_expiry_idx
    ON registry_notary_private.evaluation (expires_at);

CREATE TABLE registry_notary_private.batch_idempotency (
    key_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(key_hash) = 32),
    request_hash bytea NOT NULL CHECK (pg_catalog.octet_length(request_hash) = 32),
    principal_hash bytea NOT NULL CHECK (pg_catalog.octet_length(principal_hash) = 32),
    state text NOT NULL CHECK (state IN ('in_flight', 'completed', 'failed')),
    owner_token bytea CHECK (owner_token IS NULL OR pg_catalog.octet_length(owner_token) = 32),
    lease_expires_at timestamptz,
    quota_charged boolean NOT NULL,
    response_version smallint,
    response_json jsonb,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retention_expires_at timestamptz NOT NULL,
    CHECK (
        (state = 'in_flight' AND owner_token IS NOT NULL AND lease_expires_at IS NOT NULL
            AND response_version IS NULL AND response_json IS NULL)
        OR (state = 'completed' AND owner_token IS NULL AND lease_expires_at IS NULL
            AND response_version = 2 AND pg_catalog.jsonb_typeof(response_json) = 'object')
        OR (state = 'failed' AND owner_token IS NULL AND lease_expires_at IS NULL
            AND response_version IS NULL AND response_json IS NULL)
    )
);
CREATE INDEX batch_idempotency_retention_idx
    ON registry_notary_private.batch_idempotency (retention_expires_at);
CREATE INDEX batch_idempotency_lease_idx
    ON registry_notary_private.batch_idempotency (lease_expires_at)
    WHERE state = 'in_flight';

CREATE TABLE registry_notary_private.credential_status (
    credential_id text PRIMARY KEY CHECK (pg_catalog.length(credential_id) BETWEEN 1 AND 512),
    issuer text NOT NULL CHECK (pg_catalog.length(issuer) BETWEEN 1 AND 2048),
    profile text NOT NULL CHECK (pg_catalog.length(profile) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('valid', 'suspended', 'revoked')),
    issued_at timestamptz NOT NULL,
    credential_expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    purge_after timestamptz NOT NULL,
    CHECK (credential_expires_at > issued_at),
    CHECK (purge_after > credential_expires_at),
    CHECK (updated_at >= issued_at)
);
CREATE INDEX credential_status_purge_idx
    ON registry_notary_private.credential_status (purge_after);

CREATE TABLE registry_notary_private.machine_quota (
    principal_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(principal_hash) = 32),
    window_started_at timestamptz NOT NULL,
    window_expires_at timestamptz NOT NULL,
    used integer NOT NULL CHECK (used >= 0),
    CHECK (window_expires_at > window_started_at)
);
CREATE INDEX machine_quota_expiry_idx
    ON registry_notary_private.machine_quota (window_expires_at);

CREATE TABLE registry_notary_private.subject_access_quota (
    bucket_kind text NOT NULL CHECK (bucket_kind IN (
        'invalid_token_per_client_address',
        'per_principal',
        'subject_mismatch_per_principal',
        'per_holder_issuance',
        'credential_issuance_per_principal',
        'tx_code_attempt_per_code'
    )),
    key_hash bytea NOT NULL CHECK (pg_catalog.octet_length(key_hash) = 32),
    window_started_at timestamptz NOT NULL,
    window_expires_at timestamptz NOT NULL,
    used integer NOT NULL CHECK (used >= 0),
    PRIMARY KEY (bucket_kind, key_hash),
    CHECK (window_expires_at > window_started_at)
);
CREATE INDEX subject_access_quota_expiry_idx
    ON registry_notary_private.subject_access_quota (window_expires_at);

CREATE TABLE registry_notary_private.preauthorization_login_state (
    state_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(state_hash) = 32),
    credential_configuration_id text NOT NULL
        CHECK (pg_catalog.length(credential_configuration_id) BETWEEN 1 AND 256),
    key_id bytea NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    aead_nonce bytea NOT NULL CHECK (pg_catalog.octet_length(aead_nonce) BETWEEN 12 AND 24),
    ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(ciphertext) BETWEEN 17 AND 8192),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX preauthorization_login_state_expiry_idx
    ON registry_notary_private.preauthorization_login_state (expires_at);

CREATE TABLE registry_notary_private.preauthorization_tx_code (
    jti_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(jti_hash) = 32),
    key_id bytea NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    pin_verifier bytea NOT NULL CHECK (pg_catalog.octet_length(pin_verifier) = 32),
    pin_length smallint NOT NULL CHECK (pin_length BETWEEN 4 AND 12),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX preauthorization_tx_code_expiry_idx
    ON registry_notary_private.preauthorization_tx_code (expires_at);

CREATE TABLE registry_notary_private.oid4vci_issuance_transaction (
    transaction_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(transaction_hash) = 32),
    key_id bytea NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    credential_configuration_id text NOT NULL
        CHECK (pg_catalog.length(credential_configuration_id) BETWEEN 1 AND 256),
    commitment text NOT NULL CHECK (commitment ~ '^sha256:[0-9a-f]{64}$'),
    record_aead_nonce bytea NOT NULL
        CHECK (pg_catalog.octet_length(record_aead_nonce) BETWEEN 12 AND 24),
    record_ciphertext bytea NOT NULL
        CHECK (pg_catalog.octet_length(record_ciphertext) BETWEEN 17 AND 16384),
    token_nonce_hash bytea CHECK (
        token_nonce_hash IS NULL OR pg_catalog.octet_length(token_nonce_hash) = 32
    ),
    state text NOT NULL CHECK (state IN ('ready', 'issuing', 'completed', 'failed')),
    holder_thumbprint_hash bytea CHECK (
        holder_thumbprint_hash IS NULL OR pg_catalog.octet_length(holder_thumbprint_hash) = 32
    ),
    request_hash bytea CHECK (
        request_hash IS NULL OR pg_catalog.octet_length(request_hash) = 32
    ),
    response_aead_nonce bytea CHECK (
        response_aead_nonce IS NULL
        OR pg_catalog.octet_length(response_aead_nonce) BETWEEN 12 AND 24
    ),
    response_ciphertext bytea CHECK (
        response_ciphertext IS NULL
        OR pg_catalog.octet_length(response_ciphertext) BETWEEN 17 AND 65536
    ),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (
        (state = 'ready' AND holder_thumbprint_hash IS NULL AND request_hash IS NULL
            AND response_aead_nonce IS NULL AND response_ciphertext IS NULL)
        OR (state = 'issuing' AND holder_thumbprint_hash IS NOT NULL AND request_hash IS NOT NULL
            AND response_aead_nonce IS NULL AND response_ciphertext IS NULL)
        OR (state = 'completed' AND holder_thumbprint_hash IS NOT NULL AND request_hash IS NOT NULL
            AND response_aead_nonce IS NOT NULL AND response_ciphertext IS NOT NULL)
        OR (state = 'failed' AND holder_thumbprint_hash IS NOT NULL AND request_hash IS NOT NULL
            AND response_aead_nonce IS NULL AND response_ciphertext IS NULL)
    )
);
CREATE INDEX oid4vci_issuance_transaction_expiry_idx
    ON registry_notary_private.oid4vci_issuance_transaction (expires_at);

ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_private
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_private
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_api
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION registry_notary_api.attest_v1()
RETURNS TABLE (
    capability_id text,
    schema_version integer,
    schema_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    caller_role_oid bigint,
    server_major integer,
    database_writable boolean,
    durability_safe boolean
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT metadata.capability_id,
           metadata.schema_version,
           metadata.schema_fingerprint,
           metadata.owner_role_oid::bigint,
           metadata.runtime_role_oid::bigint,
           caller.oid::bigint,
           current_setting('server_version_num')::integer / 10000,
           NOT pg_catalog.pg_is_in_recovery()
             AND NOT current_setting('transaction_read_only')::boolean,
           current_setting('fsync') = 'on'
             AND current_setting('synchronous_commit') = 'on'
             AND current_setting('full_page_writes') = 'on'
      FROM registry_notary_private.schema_metadata AS metadata
      JOIN pg_catalog.pg_roles AS caller ON caller.rolname = session_user
     WHERE metadata.singleton
$function$;

CREATE FUNCTION registry_notary_api.readiness_v1()
RETURNS TABLE (
    capability_id text,
    schema_version integer,
    schema_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    caller_role_oid bigint,
    server_major integer,
    database_writable boolean,
    durability_safe boolean
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT * FROM registry_notary_api.attest_v1()
$function$;

CREATE FUNCTION registry_notary_api.replay_insert_v1(
    p_scope_hash bytea,
    p_identifier_hash bytea,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_identifier_hash) <> 32
       OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid replay input';
    END IF;

    INSERT INTO registry_notary_private.replay_identifier (
        scope_hash, identifier_hash, created_at, expires_at
    ) VALUES (p_scope_hash, p_identifier_hash, v_now, p_expires_at)
    ON CONFLICT (scope_hash, identifier_hash) DO UPDATE
       SET created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at
     WHERE registry_notary_private.replay_identifier.expires_at <= v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.nonce_reserve_v1(
    p_scope_hash bytea,
    p_nonce_hash bytea,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_nonce_hash) <> 32
       OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid nonce input';
    END IF;

    INSERT INTO registry_notary_private.consumable_nonce (
        scope_hash, nonce_hash, generation, state, reservation_expires_at,
        tombstone_expires_at, created_at, updated_at
    ) VALUES (
        p_scope_hash, p_nonce_hash, 1, 'reserved', p_expires_at,
        NULL, v_now, v_now
    )
    ON CONFLICT (scope_hash, nonce_hash) DO UPDATE
       SET generation = registry_notary_private.consumable_nonce.generation + 1,
           state = 'reserved',
           reservation_expires_at = EXCLUDED.reservation_expires_at,
           tombstone_expires_at = NULL,
           created_at = EXCLUDED.created_at,
           updated_at = EXCLUDED.updated_at
     WHERE (
         registry_notary_private.consumable_nonce.state = 'reserved'
         AND registry_notary_private.consumable_nonce.reservation_expires_at <= v_now
     ) OR (
         registry_notary_private.consumable_nonce.state = 'consumed'
         AND registry_notary_private.consumable_nonce.tombstone_expires_at <= v_now
     );
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.nonce_reservation_generation_v1(
    p_scope_hash bytea,
    p_nonce_hash bytea
)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.generation
      FROM registry_notary_private.consumable_nonce AS stored
     WHERE stored.scope_hash = p_scope_hash
       AND stored.nonce_hash = p_nonce_hash
       AND stored.state = 'reserved'
       AND stored.reservation_expires_at > pg_catalog.statement_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.nonce_consume_v1(
    p_scope_hash bytea,
    p_nonce_hash bytea,
    p_generation bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_nonce_hash) <> 32
       OR p_generation <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid nonce input';
    END IF;

    UPDATE registry_notary_private.consumable_nonce
       SET state = 'consumed',
           tombstone_expires_at = v_now + interval '60 seconds',
           updated_at = v_now
     WHERE scope_hash = p_scope_hash
       AND nonce_hash = p_nonce_hash
       AND generation = p_generation
       AND state = 'reserved'
       AND reservation_expires_at > v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.evaluation_insert_v1(
    p_evaluation_id text,
    p_client_id_hash bytea,
    p_request_hash bytea,
    p_purpose text,
    p_record_version smallint,
    p_record_json jsonb,
    p_created_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    INSERT INTO registry_notary_private.evaluation (
        evaluation_id, client_id_hash, request_hash, purpose, record_version,
        record_json, created_at, expires_at
    ) VALUES (
        p_evaluation_id, p_client_id_hash, p_request_hash, p_purpose,
        p_record_version, p_record_json, p_created_at, p_expires_at
    ) ON CONFLICT (evaluation_id) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.evaluation_get_v1(
    p_evaluation_id text,
    p_client_id_hash bytea
)
RETURNS TABLE (
    record_version smallint,
    record_json jsonb,
    created_at timestamptz,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT evaluation.record_version,
           evaluation.record_json,
           evaluation.created_at,
           evaluation.expires_at
      FROM registry_notary_private.evaluation AS evaluation
     WHERE evaluation.evaluation_id = p_evaluation_id
       AND evaluation.client_id_hash = p_client_id_hash
       AND evaluation.expires_at > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.batch_reserve_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_principal_hash bytea,
    p_owner_token bytea,
    p_lease_seconds integer,
    p_quota_limit integer,
    p_quota_cost integer
)
RETURNS TABLE (
    outcome text,
    retry_after_seconds bigint,
    lease_expires_at timestamptz,
    response_version smallint,
    response_json jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_inserted bigint;
    v_fresh boolean;
    v_idempotency registry_notary_private.batch_idempotency%ROWTYPE;
    v_quota registry_notary_private.machine_quota%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_key_hash) <> 32
       OR pg_catalog.octet_length(p_request_hash) <> 32
       OR pg_catalog.octet_length(p_principal_hash) <> 32
       OR pg_catalog.octet_length(p_owner_token) <> 32
       OR p_lease_seconds NOT BETWEEN 1 AND 300
       OR p_quota_cost <= 0
       OR (p_quota_limit IS NOT NULL AND p_quota_limit <= 0) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid idempotency input';
    END IF;

    INSERT INTO registry_notary_private.batch_idempotency (
        key_hash, request_hash, principal_hash, state, owner_token,
        lease_expires_at, quota_charged, created_at, updated_at,
        retention_expires_at
    ) VALUES (
        p_key_hash, p_request_hash, p_principal_hash, 'in_flight', p_owner_token,
        v_now + pg_catalog.make_interval(secs => p_lease_seconds), FALSE,
        v_now, v_now, v_now + interval '15 minutes'
    ) ON CONFLICT (key_hash) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    v_fresh := v_inserted = 1;

    SELECT * INTO STRICT v_idempotency
      FROM registry_notary_private.batch_idempotency
     WHERE key_hash = p_key_hash
     FOR UPDATE;

    IF NOT v_fresh AND v_idempotency.retention_expires_at <= v_now THEN
        v_fresh := TRUE;
    ELSIF NOT v_fresh AND v_idempotency.request_hash <> p_request_hash THEN
        RETURN QUERY SELECT 'conflict'::text, NULL::bigint, NULL::timestamptz,
                            NULL::smallint, NULL::jsonb;
        RETURN;
    ELSIF NOT v_fresh AND v_idempotency.state = 'completed' THEN
        RETURN QUERY SELECT 'replay'::text, 0::bigint, NULL::timestamptz,
                            v_idempotency.response_version, v_idempotency.response_json;
        RETURN;
    ELSIF NOT v_fresh AND v_idempotency.state = 'in_flight'
          AND v_idempotency.lease_expires_at > v_now THEN
        RETURN QUERY SELECT 'wait'::text,
            GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                (v_idempotency.lease_expires_at - v_now)))::bigint),
            v_idempotency.lease_expires_at, NULL::smallint, NULL::jsonb;
        RETURN;
    ELSIF NOT v_fresh THEN
        UPDATE registry_notary_private.batch_idempotency
           SET state = 'in_flight',
               owner_token = p_owner_token,
               lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
               response_version = NULL,
               response_json = NULL,
               updated_at = v_now,
               retention_expires_at = v_now + interval '15 minutes'
         WHERE key_hash = p_key_hash;
        RETURN QUERY SELECT 'owner'::text, 0::bigint,
            v_now + pg_catalog.make_interval(secs => p_lease_seconds),
            NULL::smallint, NULL::jsonb;
        RETURN;
    END IF;

    IF p_quota_limit IS NOT NULL THEN
        INSERT INTO registry_notary_private.machine_quota (
            principal_hash, window_started_at, window_expires_at, used
        ) VALUES (p_principal_hash, v_now, v_now + interval '1 minute', 0)
        ON CONFLICT (principal_hash) DO NOTHING;

        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.machine_quota
         WHERE principal_hash = p_principal_hash
         FOR UPDATE;
        IF v_quota.window_expires_at <= v_now THEN
            UPDATE registry_notary_private.machine_quota
               SET window_started_at = v_now,
                   window_expires_at = v_now + interval '1 minute',
                   used = 0
             WHERE principal_hash = p_principal_hash;
            v_quota.window_expires_at := v_now + interval '1 minute';
            v_quota.used := 0;
        END IF;
        IF p_quota_cost > p_quota_limit - v_quota.used THEN
            DELETE FROM registry_notary_private.batch_idempotency
             WHERE key_hash = p_key_hash;
            RETURN QUERY SELECT 'quota_exceeded'::text,
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint),
                NULL::timestamptz, NULL::smallint, NULL::jsonb;
            RETURN;
        END IF;
        UPDATE registry_notary_private.machine_quota
           SET used = used + p_quota_cost
         WHERE principal_hash = p_principal_hash;
    END IF;

    UPDATE registry_notary_private.batch_idempotency
       SET request_hash = p_request_hash,
           principal_hash = p_principal_hash,
           state = 'in_flight',
           owner_token = p_owner_token,
           lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
           quota_charged = p_quota_limit IS NOT NULL,
           response_version = NULL,
           response_json = NULL,
           created_at = v_now,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash;

    RETURN QUERY SELECT 'owner'::text, 0::bigint,
        v_now + pg_catalog.make_interval(secs => p_lease_seconds),
        NULL::smallint, NULL::jsonb;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_heartbeat_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea,
    p_lease_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    IF p_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid lease';
    END IF;
    UPDATE registry_notary_private.batch_idempotency
       SET lease_expires_at = pg_catalog.clock_timestamp()
                              + pg_catalog.make_interval(secs => p_lease_seconds),
           updated_at = pg_catalog.clock_timestamp()
     WHERE key_hash = p_key_hash
       AND request_hash = p_request_hash
       AND state = 'in_flight'
       AND owner_token = p_owner_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_complete_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea,
    p_evaluations jsonb,
    p_response_version smallint,
    p_response_json jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_idempotency registry_notary_private.batch_idempotency%ROWTYPE;
BEGIN
    IF p_response_version <> 2
       OR pg_catalog.jsonb_typeof(p_response_json) <> 'object'
       OR pg_catalog.jsonb_typeof(p_evaluations) <> 'array'
       OR pg_catalog.jsonb_array_length(p_evaluations) > 1024 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid completion';
    END IF;
    SELECT * INTO v_idempotency
      FROM registry_notary_private.batch_idempotency
     WHERE key_hash = p_key_hash
     FOR UPDATE;
    IF NOT FOUND
       OR v_idempotency.request_hash <> p_request_hash
       OR v_idempotency.state <> 'in_flight'
       OR v_idempotency.owner_token <> p_owner_token THEN
        RETURN FALSE;
    END IF;

    INSERT INTO registry_notary_private.evaluation (
        evaluation_id, client_id_hash, request_hash, purpose, record_version,
        record_json, created_at, expires_at
    )
    SELECT item->>'evaluation_id',
           pg_catalog.decode(item->>'client_id_hash_hex', 'hex'),
           p_request_hash,
           item->>'purpose',
           (item->>'record_version')::smallint,
           item->'record',
           (item->>'created_at')::timestamptz,
           (item->>'expires_at')::timestamptz
      FROM pg_catalog.jsonb_array_elements(p_evaluations) AS item;

    UPDATE registry_notary_private.batch_idempotency
       SET state = 'completed',
           owner_token = NULL,
           lease_expires_at = NULL,
           response_version = p_response_version,
           response_json = p_response_json,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash;
    RETURN TRUE;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_fail_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    UPDATE registry_notary_private.batch_idempotency
       SET state = 'failed',
           owner_token = NULL,
           lease_expires_at = NULL,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash
       AND request_hash = p_request_hash
       AND state = 'in_flight'
       AND owner_token = p_owner_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.credential_status_insert_v1(
    p_credential_id text,
    p_issuer text,
    p_profile text,
    p_issued_at timestamptz,
    p_credential_expires_at timestamptz,
    p_retention_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    IF p_retention_seconds <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid status retention';
    END IF;
    INSERT INTO registry_notary_private.credential_status (
        credential_id, issuer, profile, status, issued_at,
        credential_expires_at, updated_at, purge_after
    ) VALUES (
        p_credential_id, p_issuer, p_profile, 'valid', p_issued_at,
        p_credential_expires_at, p_issued_at,
        p_credential_expires_at + pg_catalog.make_interval(secs => p_retention_seconds)
    ) ON CONFLICT (credential_id) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.credential_status_get_v1(
    p_credential_id text
)
RETURNS TABLE (
    credential_id text,
    issuer text,
    profile text,
    status text,
    effective_status text,
    issued_at timestamptz,
    credential_expires_at timestamptz,
    updated_at timestamptz,
    purge_after timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.credential_id,
           stored.issuer,
           stored.profile,
           stored.status,
           CASE
               WHEN stored.status = 'revoked' THEN stored.status
               WHEN stored.credential_expires_at <= pg_catalog.clock_timestamp() THEN 'expired'
               ELSE stored.status
           END,
           stored.issued_at,
           stored.credential_expires_at,
           stored.updated_at,
           stored.purge_after
      FROM registry_notary_private.credential_status AS stored
     WHERE stored.credential_id = p_credential_id
       AND stored.purge_after > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.credential_status_update_v1(
    p_credential_id text,
    p_status text
)
RETURNS TABLE (
    outcome text,
    credential_id text,
    issuer text,
    profile text,
    status text,
    effective_status text,
    issued_at timestamptz,
    credential_expires_at timestamptz,
    updated_at timestamptz,
    purge_after timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_stored registry_notary_private.credential_status%ROWTYPE;
BEGIN
    IF p_status NOT IN ('valid', 'suspended', 'revoked') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid credential status';
    END IF;
    SELECT * INTO v_stored
      FROM registry_notary_private.credential_status AS stored
     WHERE stored.credential_id = p_credential_id
       AND stored.purge_after > v_now
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::text,
                            NULL::text, NULL::text, NULL::timestamptz, NULL::timestamptz,
                            NULL::timestamptz, NULL::timestamptz;
        RETURN;
    END IF;
    IF v_stored.status = 'revoked' AND p_status <> 'revoked' THEN
        RETURN QUERY SELECT 'invalid_transition'::text,
            v_stored.credential_id, v_stored.issuer, v_stored.profile,
            v_stored.status,
            CASE
                WHEN v_stored.status = 'revoked' THEN v_stored.status
                WHEN v_stored.credential_expires_at <= v_now THEN 'expired'
                ELSE v_stored.status
            END,
            v_stored.issued_at, v_stored.credential_expires_at,
            v_stored.updated_at, v_stored.purge_after;
        RETURN;
    END IF;
    UPDATE registry_notary_private.credential_status AS stored
       SET status = p_status,
           updated_at = CASE
               WHEN v_now > stored.updated_at THEN v_now
               ELSE stored.updated_at
           END
     WHERE stored.credential_id = p_credential_id
     RETURNING stored.* INTO v_stored;
    RETURN QUERY SELECT 'updated'::text,
        v_stored.credential_id, v_stored.issuer, v_stored.profile,
        v_stored.status,
        CASE
            WHEN v_stored.status = 'revoked' THEN v_stored.status
            WHEN v_stored.credential_expires_at <= v_now THEN 'expired'
            ELSE v_stored.status
        END,
        v_stored.issued_at, v_stored.credential_expires_at,
        v_stored.updated_at, v_stored.purge_after;
END
$function$;

CREATE FUNCTION registry_notary_api.machine_quota_debit_v1(
    p_principal_hash bytea,
    p_limit integer,
    p_cost integer
)
RETURNS TABLE (
    allowed boolean,
    remaining integer,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_quota registry_notary_private.machine_quota%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_principal_hash) <> 32
       OR p_limit <= 0 OR p_cost <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid machine quota input';
    END IF;
    INSERT INTO registry_notary_private.machine_quota (
        principal_hash, window_started_at, window_expires_at, used
    ) VALUES (p_principal_hash, v_now, v_now + interval '1 minute', 0)
    ON CONFLICT (principal_hash) DO NOTHING;
    SELECT * INTO STRICT v_quota
      FROM registry_notary_private.machine_quota
     WHERE principal_hash = p_principal_hash
     FOR UPDATE;
    IF v_quota.window_expires_at <= v_now THEN
        UPDATE registry_notary_private.machine_quota
           SET window_started_at = v_now,
               window_expires_at = v_now + interval '1 minute',
               used = 0
         WHERE principal_hash = p_principal_hash;
        v_quota.window_expires_at := v_now + interval '1 minute';
        v_quota.used := 0;
    END IF;
    IF p_cost > p_limit - v_quota.used THEN
        RETURN QUERY SELECT FALSE, GREATEST(0, p_limit - v_quota.used),
            GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                (v_quota.window_expires_at - v_now)))::bigint);
        RETURN;
    END IF;
    UPDATE registry_notary_private.machine_quota
       SET used = used + p_cost
     WHERE principal_hash = p_principal_hash;
    RETURN QUERY SELECT TRUE, p_limit - v_quota.used - p_cost, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.subject_access_quota_debit_v1(
    p_bucket_kinds text[],
    p_key_hashes bytea[],
    p_limits integer[],
    p_window_seconds integer[]
)
RETURNS TABLE (
    allowed boolean,
    denied_bucket text,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_size integer := pg_catalog.cardinality(p_bucket_kinds);
    v_index integer;
    v_other integer;
    v_quota registry_notary_private.subject_access_quota%ROWTYPE;
BEGIN
    IF v_size IS NULL OR v_size < 1 OR v_size > 8
       OR pg_catalog.array_ndims(p_bucket_kinds) <> 1
       OR pg_catalog.array_ndims(p_key_hashes) <> 1
       OR pg_catalog.array_ndims(p_limits) <> 1
       OR pg_catalog.array_ndims(p_window_seconds) <> 1
       OR pg_catalog.array_lower(p_bucket_kinds, 1) <> 1
       OR pg_catalog.array_lower(p_key_hashes, 1) <> 1
       OR pg_catalog.array_lower(p_limits, 1) <> 1
       OR pg_catalog.array_lower(p_window_seconds, 1) <> 1
       OR pg_catalog.cardinality(p_key_hashes) <> v_size
       OR pg_catalog.cardinality(p_limits) <> v_size
       OR pg_catalog.cardinality(p_window_seconds) <> v_size THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota group';
    END IF;
    FOR v_index IN 1..v_size LOOP
        IF p_bucket_kinds[v_index] IS NULL
           OR p_key_hashes[v_index] IS NULL
           OR p_limits[v_index] IS NULL
           OR p_window_seconds[v_index] IS NULL
           OR pg_catalog.octet_length(p_key_hashes[v_index]) <> 32
           OR p_limits[v_index] < 0
           OR p_window_seconds[v_index] NOT IN (60, 3600)
           OR p_bucket_kinds[v_index] NOT IN (
               'invalid_token_per_client_address',
               'per_principal',
               'subject_mismatch_per_principal',
               'per_holder_issuance',
               'credential_issuance_per_principal',
               'tx_code_attempt_per_code'
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota bucket';
        END IF;
        IF v_index > 1 THEN
            FOR v_other IN 1..(v_index - 1) LOOP
                IF p_bucket_kinds[v_other] = p_bucket_kinds[v_index]
                   AND p_key_hashes[v_other] = p_key_hashes[v_index] THEN
                    RAISE EXCEPTION USING ERRCODE = '22023',
                        MESSAGE = 'duplicate quota bucket';
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- Insert and lock in canonical order, independent of caller denial order.
    FOR v_index IN
        SELECT requested.ordinality::integer
          FROM pg_catalog.unnest(p_bucket_kinds) WITH ORDINALITY AS requested(bucket, ordinality)
         ORDER BY requested.bucket,
                  pg_catalog.encode(p_key_hashes[requested.ordinality::integer], 'hex')
    LOOP
        INSERT INTO registry_notary_private.subject_access_quota (
            bucket_kind, key_hash, window_started_at, window_expires_at, used
        ) VALUES (
            p_bucket_kinds[v_index], p_key_hashes[v_index], v_now,
            v_now + pg_catalog.make_interval(secs => p_window_seconds[v_index]), 0
        ) ON CONFLICT (bucket_kind, key_hash) DO NOTHING;
        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index]
         FOR UPDATE;
        IF v_quota.window_expires_at <= v_now THEN
            UPDATE registry_notary_private.subject_access_quota
               SET window_started_at = v_now,
                   window_expires_at = v_now
                       + pg_catalog.make_interval(secs => p_window_seconds[v_index]),
                   used = 0
             WHERE bucket_kind = p_bucket_kinds[v_index]
               AND key_hash = p_key_hashes[v_index];
        END IF;
    END LOOP;

    -- Preserve caller order when selecting the denial bucket.
    FOR v_index IN 1..v_size LOOP
        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
        IF p_limits[v_index] = 0 OR v_quota.used >= p_limits[v_index] THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint);
            RETURN;
        END IF;
    END LOOP;

    FOR v_index IN 1..v_size LOOP
        UPDATE registry_notary_private.subject_access_quota
           SET used = used + 1
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
    END LOOP;
    RETURN QUERY SELECT TRUE, NULL::text, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.subject_access_quota_check_v1(
    p_bucket_kinds text[],
    p_key_hashes bytea[],
    p_limits integer[],
    p_window_seconds integer[]
)
RETURNS TABLE (
    allowed boolean,
    denied_bucket text,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_size integer := pg_catalog.cardinality(p_bucket_kinds);
    v_index integer;
    v_other integer;
    v_quota registry_notary_private.subject_access_quota%ROWTYPE;
BEGIN
    IF v_size IS NULL OR v_size < 1 OR v_size > 8
       OR pg_catalog.array_ndims(p_bucket_kinds) <> 1
       OR pg_catalog.array_ndims(p_key_hashes) <> 1
       OR pg_catalog.array_ndims(p_limits) <> 1
       OR pg_catalog.array_ndims(p_window_seconds) <> 1
       OR pg_catalog.array_lower(p_bucket_kinds, 1) <> 1
       OR pg_catalog.array_lower(p_key_hashes, 1) <> 1
       OR pg_catalog.array_lower(p_limits, 1) <> 1
       OR pg_catalog.array_lower(p_window_seconds, 1) <> 1
       OR pg_catalog.cardinality(p_key_hashes) <> v_size
       OR pg_catalog.cardinality(p_limits) <> v_size
       OR pg_catalog.cardinality(p_window_seconds) <> v_size THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota group';
    END IF;
    FOR v_index IN 1..v_size LOOP
        IF p_bucket_kinds[v_index] IS NULL
           OR p_key_hashes[v_index] IS NULL
           OR p_limits[v_index] IS NULL
           OR p_window_seconds[v_index] IS NULL
           OR pg_catalog.octet_length(p_key_hashes[v_index]) <> 32
           OR p_limits[v_index] < 0
           OR p_window_seconds[v_index] NOT IN (60, 3600)
           OR p_bucket_kinds[v_index] NOT IN (
               'invalid_token_per_client_address',
               'per_principal',
               'subject_mismatch_per_principal',
               'per_holder_issuance',
               'credential_issuance_per_principal',
               'tx_code_attempt_per_code'
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota bucket';
        END IF;
        IF v_index > 1 THEN
            FOR v_other IN 1..(v_index - 1) LOOP
                IF p_bucket_kinds[v_other] = p_bucket_kinds[v_index]
                   AND p_key_hashes[v_other] = p_key_hashes[v_index] THEN
                    RAISE EXCEPTION USING ERRCODE = '22023',
                        MESSAGE = 'duplicate quota bucket';
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- This precheck deliberately does not insert, reset, lock, or debit rows.
    -- A later debit performs its own atomic decision against current state.
    FOR v_index IN 1..v_size LOOP
        IF p_limits[v_index] = 0 THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                p_window_seconds[v_index]::bigint;
            RETURN;
        END IF;
        SELECT * INTO v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
        IF FOUND
           AND v_quota.window_expires_at > v_now
           AND v_quota.used >= p_limits[v_index] THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint);
            RETURN;
        END IF;
    END LOOP;
    RETURN QUERY SELECT TRUE, NULL::text, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_login_reserve_v1(
    p_state_hash bytea,
    p_credential_configuration_id text,
    p_key_id bytea,
    p_aead_nonce bytea,
    p_ciphertext bytea,
    p_expires_at timestamptz
)
RETURNS smallint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_key_id) <> 32 OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid login state expiry';
    END IF;
    -- One domain-specific lock serializes the live sensitive-key generation
    -- decision across both preauthorization tables and all Notary replicas.
    PERFORM pg_catalog.pg_advisory_xact_lock(5642808141211099137);
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.preauthorization_login_state
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.preauthorization_tx_code
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.oid4vci_issuance_transaction
         WHERE expires_at > v_now AND key_id <> p_key_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'sensitive-state key generation mismatch';
    END IF;
    -- The table lock serializes the exact 4,096-row capacity decision across
    -- replicas. It is bounded because this table cannot exceed that capacity.
    LOCK TABLE registry_notary_private.preauthorization_login_state
        IN SHARE ROW EXCLUSIVE MODE;
    DELETE FROM registry_notary_private.preauthorization_login_state
     WHERE expires_at <= v_now;
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.preauthorization_login_state
         WHERE state_hash = p_state_hash
    ) THEN
        RETURN 0;
    END IF;
    SELECT pg_catalog.count(*) INTO v_count
      FROM registry_notary_private.preauthorization_login_state;
    IF v_count >= 4096 THEN
        RETURN -1;
    END IF;
    INSERT INTO registry_notary_private.preauthorization_login_state (
        state_hash, credential_configuration_id, key_id, aead_nonce,
        ciphertext, created_at, expires_at
    ) VALUES (
        p_state_hash, p_credential_configuration_id, p_key_id, p_aead_nonce,
        p_ciphertext, v_now, p_expires_at
    );
    RETURN 1;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_login_consume_v1(
    p_state_hash bytea
)
RETURNS TABLE (
    credential_configuration_id text,
    key_id bytea,
    aead_nonce bytea,
    ciphertext bytea,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    DELETE FROM registry_notary_private.preauthorization_login_state AS stored
     WHERE stored.state_hash = p_state_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
    RETURNING stored.credential_configuration_id,
              stored.key_id,
              stored.aead_nonce,
              stored.ciphertext,
              stored.expires_at
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_tx_code_reserve_v1(
    p_jti_hash bytea,
    p_key_id bytea,
    p_pin_verifier bytea,
    p_pin_length smallint,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_key_id) <> 32 OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid transaction code expiry';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(5642808141211099137);
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.preauthorization_login_state
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.preauthorization_tx_code
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.oid4vci_issuance_transaction
         WHERE expires_at > v_now AND key_id <> p_key_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'sensitive-state key generation mismatch';
    END IF;
    DELETE FROM registry_notary_private.preauthorization_tx_code
     WHERE jti_hash = p_jti_hash AND expires_at <= v_now;
    INSERT INTO registry_notary_private.preauthorization_tx_code (
        jti_hash, key_id, pin_verifier, pin_length, created_at, expires_at
    ) VALUES (
        p_jti_hash, p_key_id, p_pin_verifier, p_pin_length, v_now, p_expires_at
    ) ON CONFLICT (jti_hash) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_key_attest_v1(
    p_key_id bytea
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.octet_length(p_key_id) = 32
       AND NOT EXISTS (
            SELECT 1 FROM registry_notary_private.preauthorization_login_state
             WHERE expires_at > pg_catalog.statement_timestamp() AND key_id <> p_key_id
            UNION ALL
            SELECT 1 FROM registry_notary_private.preauthorization_tx_code
             WHERE expires_at > pg_catalog.statement_timestamp() AND key_id <> p_key_id
            UNION ALL
            SELECT 1 FROM registry_notary_private.oid4vci_issuance_transaction
             WHERE expires_at > pg_catalog.statement_timestamp() AND key_id <> p_key_id
       )
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_tx_code_peek_v1(
    p_jti_hash bytea
)
RETURNS TABLE (
    key_id bytea,
    pin_verifier bytea,
    pin_length smallint,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.key_id,
           stored.pin_verifier,
           stored.pin_length,
           stored.expires_at
      FROM registry_notary_private.preauthorization_tx_code AS stored
     WHERE stored.jti_hash = p_jti_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_redeem_v1(
    p_replay_scope_hash bytea,
    p_jti_hash bytea,
    p_code_expires_at timestamptz,
    p_pin_required boolean,
    p_expected_pin_verifier bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
    v_tx_code registry_notary_private.preauthorization_tx_code%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_replay_scope_hash) <> 32
       OR pg_catalog.octet_length(p_jti_hash) <> 32
       OR p_code_expires_at <= v_now
       OR (p_pin_required AND pg_catalog.octet_length(p_expected_pin_verifier) <> 32)
       OR (NOT p_pin_required AND p_expected_pin_verifier IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid redemption input';
    END IF;
    IF p_pin_required THEN
        SELECT * INTO v_tx_code
          FROM registry_notary_private.preauthorization_tx_code
         WHERE jti_hash = p_jti_hash
         FOR UPDATE;
        IF NOT FOUND
           OR v_tx_code.expires_at <= v_now
           OR v_tx_code.pin_verifier <> p_expected_pin_verifier THEN
            RETURN FALSE;
        END IF;
    END IF;

    INSERT INTO registry_notary_private.replay_identifier (
        scope_hash, identifier_hash, created_at, expires_at
    ) VALUES (p_replay_scope_hash, p_jti_hash, v_now, p_code_expires_at)
    ON CONFLICT (scope_hash, identifier_hash) DO UPDATE
       SET created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at
     WHERE registry_notary_private.replay_identifier.expires_at <= v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count <> 1 THEN
        RETURN FALSE;
    END IF;
    IF p_pin_required THEN
        DELETE FROM registry_notary_private.preauthorization_tx_code
         WHERE jti_hash = p_jti_hash;
    END IF;
    RETURN TRUE;
END
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_reserve_v1(
    p_transaction_hash bytea,
    p_key_id bytea,
    p_configuration_id text,
    p_commitment text,
    p_record_aead_nonce bytea,
    p_record_ciphertext bytea,
    p_expires_at timestamptz
)
RETURNS smallint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_transaction_hash) <> 32
       OR pg_catalog.octet_length(p_key_id) <> 32
       OR p_commitment !~ '^sha256:[0-9a-f]{64}$'
       OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid issuance transaction';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(5642808141211099137);
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.preauthorization_login_state
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.preauthorization_tx_code
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.oid4vci_issuance_transaction
         WHERE expires_at > v_now AND key_id <> p_key_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'sensitive-state key generation mismatch';
    END IF;
    LOCK TABLE registry_notary_private.oid4vci_issuance_transaction
        IN SHARE ROW EXCLUSIVE MODE;
    DELETE FROM registry_notary_private.oid4vci_issuance_transaction
     WHERE expires_at <= v_now;
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.oid4vci_issuance_transaction
         WHERE transaction_hash = p_transaction_hash
    ) THEN
        RETURN 0;
    END IF;
    SELECT pg_catalog.count(*) INTO v_count
      FROM registry_notary_private.oid4vci_issuance_transaction;
    IF v_count >= 4096 THEN
        RETURN -1;
    END IF;
    INSERT INTO registry_notary_private.oid4vci_issuance_transaction (
        transaction_hash, key_id, credential_configuration_id, commitment,
        record_aead_nonce, record_ciphertext, state, created_at, updated_at, expires_at
    ) VALUES (
        p_transaction_hash, p_key_id, p_configuration_id, p_commitment,
        p_record_aead_nonce, p_record_ciphertext, 'ready', v_now, v_now, p_expires_at
    );
    RETURN 1;
END
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_get_v1(p_transaction_hash bytea)
RETURNS TABLE (
    key_id bytea,
    credential_configuration_id text,
    commitment text,
    record_aead_nonce bytea,
    record_ciphertext bytea,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.key_id, stored.credential_configuration_id, stored.commitment,
           stored.record_aead_nonce, stored.record_ciphertext, stored.expires_at
      FROM registry_notary_private.oid4vci_issuance_transaction AS stored
     WHERE stored.transaction_hash = p_transaction_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_bind_nonce_v1(
    p_transaction_hash bytea,
    p_commitment text,
    p_token_nonce_hash bytea
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE registry_notary_private.oid4vci_issuance_transaction AS stored
       SET token_nonce_hash = p_token_nonce_hash,
           updated_at = pg_catalog.clock_timestamp()
     WHERE stored.transaction_hash = p_transaction_hash
       AND stored.commitment = p_commitment
       AND stored.state = 'ready'
       AND stored.token_nonce_hash IS NULL
       AND stored.expires_at > pg_catalog.clock_timestamp()
       AND pg_catalog.octet_length(p_token_nonce_hash) = 32
    RETURNING TRUE
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_begin_v1(
    p_transaction_hash bytea,
    p_commitment text,
    p_configuration_id text,
    p_token_nonce_hash bytea,
    p_holder_thumbprint_hash bytea,
    p_request_hash bytea
)
RETURNS TABLE (
    outcome smallint,
    key_id bytea,
    credential_configuration_id text,
    commitment text,
    record_aead_nonce bytea,
    record_ciphertext bytea,
    response_aead_nonce bytea,
    response_ciphertext bytea,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_stored registry_notary_private.oid4vci_issuance_transaction%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_token_nonce_hash) <> 32
       OR pg_catalog.octet_length(p_holder_thumbprint_hash) <> 32
       OR pg_catalog.octet_length(p_request_hash) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid materialization binding';
    END IF;
    SELECT * INTO v_stored
      FROM registry_notary_private.oid4vci_issuance_transaction
     WHERE transaction_hash = p_transaction_hash
     FOR UPDATE;
    IF NOT FOUND OR v_stored.expires_at <= pg_catalog.clock_timestamp()
       OR v_stored.commitment <> p_commitment
       OR v_stored.credential_configuration_id <> p_configuration_id
       OR v_stored.token_nonce_hash IS DISTINCT FROM p_token_nonce_hash THEN
        RETURN QUERY SELECT -1::smallint, NULL::bytea, NULL::text, NULL::text,
            NULL::bytea, NULL::bytea, NULL::bytea, NULL::bytea, NULL::timestamptz;
        RETURN;
    END IF;
    IF v_stored.state = 'ready' THEN
        UPDATE registry_notary_private.oid4vci_issuance_transaction
           SET state = 'issuing', holder_thumbprint_hash = p_holder_thumbprint_hash,
               request_hash = p_request_hash, updated_at = pg_catalog.clock_timestamp()
         WHERE transaction_hash = p_transaction_hash;
        RETURN QUERY SELECT 1::smallint, v_stored.key_id,
            v_stored.credential_configuration_id, v_stored.commitment,
            v_stored.record_aead_nonce, v_stored.record_ciphertext,
            NULL::bytea, NULL::bytea, v_stored.expires_at;
    ELSIF v_stored.state = 'issuing'
       AND v_stored.holder_thumbprint_hash = p_holder_thumbprint_hash
       AND v_stored.request_hash = p_request_hash THEN
        RETURN QUERY SELECT 0::smallint, NULL::bytea, NULL::text, NULL::text,
            NULL::bytea, NULL::bytea, NULL::bytea, NULL::bytea, NULL::timestamptz;
    ELSIF v_stored.state = 'completed'
       AND v_stored.holder_thumbprint_hash = p_holder_thumbprint_hash
       AND v_stored.request_hash = p_request_hash THEN
        RETURN QUERY SELECT 2::smallint, v_stored.key_id,
            v_stored.credential_configuration_id, v_stored.commitment,
            v_stored.record_aead_nonce, v_stored.record_ciphertext,
            v_stored.response_aead_nonce, v_stored.response_ciphertext, v_stored.expires_at;
    ELSE
        RETURN QUERY SELECT -1::smallint, NULL::bytea, NULL::text, NULL::text,
            NULL::bytea, NULL::bytea, NULL::bytea, NULL::bytea, NULL::timestamptz;
    END IF;
END
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_complete_v1(
    p_transaction_hash bytea,
    p_holder_thumbprint_hash bytea,
    p_request_hash bytea,
    p_response_aead_nonce bytea,
    p_response_ciphertext bytea
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE registry_notary_private.oid4vci_issuance_transaction AS stored
       SET state = 'completed', response_aead_nonce = p_response_aead_nonce,
           response_ciphertext = p_response_ciphertext,
           updated_at = pg_catalog.clock_timestamp()
     WHERE stored.transaction_hash = p_transaction_hash
       AND stored.state = 'issuing'
       AND stored.holder_thumbprint_hash = p_holder_thumbprint_hash
       AND stored.request_hash = p_request_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
    RETURNING TRUE
$function$;

CREATE FUNCTION registry_notary_api.oid4vci_transaction_fail_v1(
    p_transaction_hash bytea,
    p_holder_thumbprint_hash bytea
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE registry_notary_private.oid4vci_issuance_transaction AS stored
       SET state = 'failed', response_aead_nonce = NULL, response_ciphertext = NULL,
           updated_at = pg_catalog.clock_timestamp()
     WHERE stored.transaction_hash = p_transaction_hash
       AND stored.state = 'issuing'
       AND stored.holder_thumbprint_hash = p_holder_thumbprint_hash
    RETURNING TRUE
$function$;

CREATE FUNCTION registry_notary_api.retention_prune_v1(p_batch_size integer)
RETURNS TABLE (deleted_count bigint, batch_saturated boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
    v_total bigint := 0;
    v_saturated boolean := FALSE;
BEGIN
    IF p_batch_size NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid retention batch';
    END IF;

    WITH candidates AS (
        SELECT scope_hash, identifier_hash
          FROM registry_notary_private.replay_identifier
         WHERE expires_at <= v_now
         ORDER BY expires_at, scope_hash, identifier_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.replay_identifier AS stored
         USING candidates
         WHERE stored.scope_hash = candidates.scope_hash
           AND stored.identifier_hash = candidates.identifier_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT scope_hash, nonce_hash
          FROM registry_notary_private.consumable_nonce
         WHERE (state = 'reserved' AND reservation_expires_at <= v_now)
            OR (state = 'consumed' AND tombstone_expires_at <= v_now)
         ORDER BY updated_at, scope_hash, nonce_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.consumable_nonce AS stored
         USING candidates
         WHERE stored.scope_hash = candidates.scope_hash
           AND stored.nonce_hash = candidates.nonce_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT evaluation_id FROM registry_notary_private.evaluation
         WHERE expires_at <= v_now
         ORDER BY expires_at, evaluation_id
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.evaluation AS stored
         USING candidates WHERE stored.evaluation_id = candidates.evaluation_id
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT key_hash FROM registry_notary_private.batch_idempotency
         WHERE retention_expires_at <= v_now
         ORDER BY retention_expires_at, key_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.batch_idempotency AS stored
         USING candidates WHERE stored.key_hash = candidates.key_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT credential_id FROM registry_notary_private.credential_status
         WHERE purge_after <= v_now
         ORDER BY purge_after, credential_id
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.credential_status AS stored
         USING candidates WHERE stored.credential_id = candidates.credential_id
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT principal_hash FROM registry_notary_private.machine_quota
         WHERE window_expires_at <= v_now
         ORDER BY window_expires_at, principal_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.machine_quota AS stored
         USING candidates WHERE stored.principal_hash = candidates.principal_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT bucket_kind, key_hash
          FROM registry_notary_private.subject_access_quota
         WHERE window_expires_at <= v_now
         ORDER BY window_expires_at, bucket_kind, key_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.subject_access_quota AS stored
         USING candidates
         WHERE stored.bucket_kind = candidates.bucket_kind
           AND stored.key_hash = candidates.key_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT state_hash FROM registry_notary_private.preauthorization_login_state
         WHERE expires_at <= v_now
         ORDER BY expires_at, state_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.preauthorization_login_state AS stored
         USING candidates WHERE stored.state_hash = candidates.state_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT jti_hash FROM registry_notary_private.preauthorization_tx_code
         WHERE expires_at <= v_now
         ORDER BY expires_at, jti_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.preauthorization_tx_code AS stored
         USING candidates WHERE stored.jti_hash = candidates.jti_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    WITH candidates AS (
        SELECT transaction_hash
          FROM registry_notary_private.oid4vci_issuance_transaction
         WHERE expires_at <= v_now
         ORDER BY expires_at, transaction_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.oid4vci_issuance_transaction AS stored
         USING candidates WHERE stored.transaction_hash = candidates.transaction_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;
    v_saturated := v_saturated OR v_count = p_batch_size;

    RETURN QUERY SELECT v_total, v_saturated;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA registry_notary_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA registry_notary_private FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM PUBLIC;
