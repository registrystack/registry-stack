# Contributing

Registry Lab owns demo orchestration, fixtures, static metadata publication,
walkthrough scripts, hosted-demo configuration, and proof-harness checks.

Keep product code changes in the product repositories:

- `registry-platform`
- `registry-manifest`
- `registry-notary`
- `registry-relay`
- `crosswalk`

## Local Checks

For the local demo path:

```sh
just generate
just build
just up
just smoke
just client
```

For release proof, use:

```sh
scripts/release-check.sh
```

Do not commit `.env`, generated fixture output, hosted secrets, private
operator notes, or real upstream credentials.
