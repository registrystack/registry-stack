-- A source binding generation names what a source means: its id, the BReg
-- instance that emits its events, and its imported description. Releases up
-- to v0.33.0 derived the generation from credentials, transport, and
-- presentation settings as well, and stored their work under that value. When
-- a deployment's first start recognises such work, it records here that the
-- semantic generation continues under the stored one, so a later credential or
-- transport change cannot re-key the work a second time. A row carries two
-- digests and no subject data.
CREATE TABLE IF NOT EXISTS casework_source_generation_adoptions (
    source_id text NOT NULL,
    binding_generation text NOT NULL CHECK (octet_length(binding_generation) BETWEEN 1 AND 512),
    adopted_generation text NOT NULL CHECK (octet_length(adopted_generation) BETWEEN 1 AND 512),
    adopted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, binding_generation)
);
