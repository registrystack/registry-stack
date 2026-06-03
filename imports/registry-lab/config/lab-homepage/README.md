# Registry Lab Homepage Config

This directory contains public demo material for `lab.registrystack.org`.

`public-demo-credentials.env` is intentionally committed. Its values are
public lab credentials for seeded demo data only. Do not add infrastructure
secrets, source connector tokens, signing keys, database credentials, live
DHIS2 credentials, OpenCRVS DCI client secrets, eSignet private keys, or
Coolify webhook values here.

The homepage should read these values from environment in Coolify. The committed
file is the reviewable source for which public demo credentials are meant to be
shown on the page.

Use `public-demo-credentials.json` for presentation metadata: labels, service
URLs, endpoints, status checks, and sample subjects. Keep token values in the
`.env` file only.
