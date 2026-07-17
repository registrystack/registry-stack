CREATE ROLE relay_state_owner NOLOGIN;
CREATE ROLE relay_state_runtime LOGIN;
CREATE ROLE relay_state_maintenance LOGIN;
CREATE ROLE relay_state_reader LOGIN;
GRANT CREATE ON DATABASE registry_relay TO relay_state_owner;
GRANT CONNECT ON DATABASE registry_relay TO relay_state_runtime;
GRANT CONNECT ON DATABASE registry_relay TO relay_state_maintenance;
GRANT CONNECT ON DATABASE registry_relay TO relay_state_reader;
