# Operations Posture Lab Contract

`registry-lab` exposes read-only operations posture endpoints so local clients,
automation, and monitoring tools can observe the lab runtime through stable
HTTP contracts.

## Civil Relay

- Base URL: `http://127.0.0.1:4311`
- Ops base URL: `http://127.0.0.1:4319`
- Posture endpoint: `GET /admin/v1/posture`
- Credential scheme: `x-api-key`
- Generated raw credential: `CIVIL_RELAY_OPS_RAW`
- Required scope: `registry_relay:ops_read`

## Civil Notary

- Base URL: `http://127.0.0.1:4321`
- Posture endpoint: `GET /admin/v1/posture`
- Credential scheme: `x-api-key`
- Generated raw credential: `CIVIL_NOTARY_OPS_TOKEN`
- Required scope: `registry_notary:ops_read`

The civil notary admin listener runs on a dedicated internal port (8082) that is
not published to the host in the default Lab 1 compose topology. The posture
endpoint is reachable from within the Compose network but not directly from the
host. Use the Lab 2 overlay for host-accessible notary posture (see below).

## Lab 2 Overlay

The Lab 2 governed-config overlay adds dedicated admin host ports for both
services. Run `just generate` then `just lab2-generate` and `just lab2-up`
before using these endpoints.

### Lab 2 Civil Relay

- Base URL: `http://127.0.0.1:4411`
- Ops base URL: `http://127.0.0.1:4419`
- Posture endpoint: `GET /admin/v1/posture`
- Credential scheme: `Bearer`
- Generated raw credential: `CIVIL_RELAY_OPS_RAW`
- Required scope: `registry_relay:ops_read`

### Lab 2 Civil Notary

- Base URL: `http://127.0.0.1:4421`
- Ops base URL: `http://127.0.0.1:4422`
- Posture endpoint: `GET /admin/v1/posture`
- Credential scheme: `Bearer`
- Generated raw credential: `CIVIL_NOTARY_OPS_BEARER`
- Required scope: `registry_notary:ops_read`

## Preparation

Generate credentials and start the lab with the normal public commands:

```sh
just generate
just build
just up
just smoke
```

The generated `.env` file is local-only and ignored by Git.

