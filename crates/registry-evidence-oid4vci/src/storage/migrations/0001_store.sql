-- The state a delivery flow carries between its steps, held in PostgreSQL so
-- that more than one replica can serve one exchange.
--
-- Every key is an HMAC tag of the secret it stands for: the pre-authorized
-- code, the transaction code and the access token are never stored. A
-- prepared request is stored only as XChaCha20Poly1305 ciphertext whose
-- associated data binds it to its row, and the row is deleted when the request
-- is handed back. Expiry is a Unix second; every read filters on it and the
-- purge deletes what has passed it.

-- What is kept about an offer for the whole of its life. The failure count and
-- the lockout live here rather than on the offer, so dropping the offer, which
-- a lockout does, does not forget them.
CREATE TABLE offer_ledgers (
    offer_tag text PRIMARY KEY CHECK (length(offer_tag) BETWEEN 1 AND 64),
    state text NOT NULL CHECK (state IN ('open', 'redeemed', 'locked_out')),
    failures integer NOT NULL CHECK (failures >= 0),
    expires_at bigint NOT NULL
);
CREATE INDEX offer_ledgers_expires_at ON offer_ledgers (expires_at);

-- An offer that has not been redeemed yet, and the sealed request it carries.
CREATE TABLE offers (
    offer_tag text PRIMARY KEY
        REFERENCES offer_ledgers (offer_tag) ON DELETE CASCADE,
    tag_key_version bigint NOT NULL CHECK (tag_key_version BETWEEN 0 AND 4294967295),
    transaction_code_tag text CHECK (length(transaction_code_tag) BETWEEN 1 AND 64),
    catalog_generation text NOT NULL CHECK (length(catalog_generation) BETWEEN 1 AND 128),
    sealing_key_version bigint NOT NULL CHECK (sealing_key_version BETWEEN 0 AND 4294967295),
    prepared_nonce bytea NOT NULL CHECK (octet_length(prepared_nonce) = 24),
    prepared_ciphertext bytea NOT NULL CHECK (octet_length(prepared_ciphertext) > 16),
    expires_at bigint NOT NULL
);
CREATE INDEX offers_expires_at ON offers (expires_at);

-- A redeemed offer's request, carried forward under the access token it was
-- exchanged for until the token is claimed.
CREATE TABLE access_tokens (
    token_tag text PRIMARY KEY CHECK (length(token_tag) BETWEEN 1 AND 64),
    tag_key_version bigint NOT NULL CHECK (tag_key_version BETWEEN 0 AND 4294967295),
    catalog_generation text NOT NULL CHECK (length(catalog_generation) BETWEEN 1 AND 128),
    sealing_key_version bigint NOT NULL CHECK (sealing_key_version BETWEEN 0 AND 4294967295),
    prepared_nonce bytea NOT NULL CHECK (octet_length(prepared_nonce) = 24),
    prepared_ciphertext bytea NOT NULL CHECK (octet_length(prepared_ciphertext) > 16),
    expires_at bigint NOT NULL
);
CREATE INDEX access_tokens_expires_at ON access_tokens (expires_at);
