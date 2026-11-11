SELECT 'CREATE ROLE registry_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'registry_migration') \gexec
SELECT 'CREATE ROLE registry_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'registry_runtime') \gexec
DO $$
BEGIN
  IF EXISTS (
    SELECT FROM pg_roles
    WHERE rolname IN ('registry_migration', 'registry_runtime')
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolinherit OR rolbypassrls OR NOT rolcanlogin)
  ) THEN
    RAISE EXCEPTION 'BReg local roles need unprivileged LOGIN and NOINHERIT';
  END IF;
END
$$;
SELECT 'CREATE DATABASE registry_breg'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'registry_breg') \gexec

REVOKE ALL ON DATABASE registry_breg FROM PUBLIC;
REVOKE CREATE ON DATABASE registry_breg FROM registry_migration, registry_runtime;
GRANT CONNECT ON DATABASE registry_breg TO registry_migration, registry_runtime;

\if :prepare_schema
\connect registry_breg
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE SCHEMA IF NOT EXISTS registry_internal AUTHORIZATION registry_migration;
CREATE SCHEMA IF NOT EXISTS registry_data AUTHORIZATION registry_migration;
CREATE SCHEMA IF NOT EXISTS registry_source AUTHORIZATION registry_migration;
CREATE SCHEMA IF NOT EXISTS registry_derived AUTHORIZATION registry_migration;
CREATE SCHEMA IF NOT EXISTS registry_context AUTHORIZATION registry_migration;
REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;
\endif
