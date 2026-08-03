
## Paired Registry Mint deployment

This project was scaffolded with `--with-mint`, so it carries the Registry Mint
configuration that issues the access tokens it verifies. Mint exists for a
deployment that has many callers and no identity provider; it is a supporting
service, not a second product to adopt.

```text
mint/
  mint.yaml                             issuer, signing key, token policy
  clients/                              one registration per caller, public data
    {{mint_client_id}}.yaml.example     rename it once its key is real
  secrets/                              Mint's signing key, created empty, mode 0700
caller/                                 the example caller's own key, mode 0700
```

`caller/` is deliberately outside `mint/`. The caller is a different party from
the service that registers it, and only the public half of its key belongs to
Mint. Promote `mint/` to its own host and the caller's private key stays here.

The dependency runs one way. Evidence knows nothing about Mint beyond an issuer,
a key set and a set of claim names, and these values were written from one
source when the project was scaffolded:

| `bundle/evidence.yaml` | `mint/mint.yaml` |
|---|---|
| `authentication.issuer` | `issuer` |
| `authentication.audiences` | `accessTokens.audiences` |
| `authentication.jwksUri` | `issuer` followed by `signing.jwksPath` |
| `authentication.algorithms` | `signing.algorithm` |
| `authentication.principalClaim` | `accessTokens.claims.principal` |
| `authentication.requesterTagsClaim` | `accessTokens.claims.requesterTags` |
| `authentication.evidenceAudienceClaim` | `accessTokens.claims.evidenceAudience` |
| `authentication.grantIdClaim` | `accessTokens.claims.grantId` |
| `authentication.grantAuthorityClaim` | `accessTokens.claims.grantAuthority` |

Change any of them in both documents. A single-sided edit produces tokens Mint
issues happily and Evidence refuses. The caller registration is the same story
in one more place: its `requesterTags` must match an authority profile in
`bundle/evidence.yaml`, or the caller authenticates and is then refused
everything.

### Next steps for Mint

Generate Mint's own signing key. Its id must equal `signing.activeKeyId`:

```bash
evidencectl keygen signing --out-dir {{mint_secret_root}} \
  --kid {{mint_signing_key_id}}
```

Generate a key for the example caller. This one belongs to the caller rather
than to Mint: keep the public half here and move the private half to wherever
that client runs.

```bash
evidencectl keygen signing --out-dir {{caller_secret_root}} \
  --kid {{mint_client_key_id}}
```

Copy the `x` member of
`{{caller_secret_root}}/signing-ed25519-public.jwk.json` into the `keys`
entry of `{{mint_clients_directory}}/{{mint_client_id}}.yaml.example`, rename
that file to `{{mint_client_id}}.yaml`, then load the deployment:

```bash
mint check --config {{mint_config_path}}
mint serve --config {{mint_config_path}}
```

`check` loads the configuration, the signing key and the client registry, then
exits without opening a socket. Mint reads `clients/*.yaml` only, so a
registration still carrying the placeholder key is ignored rather than
half-applied, and `SIGHUP` reloads that directory in place: onboarding a caller
never restarts Evidence.

### Obtaining a token

```bash
mint token --url {{mint_token_endpoint}} \
  --client-id {{mint_client_id}} \
  --key {{caller_secret_root}}/signing-ed25519-private-jwk
```

`mint token` is a caller tool. It signs a client assertion with the caller's own
key and presents it to a running endpoint, which decides on its own terms;
nothing it can obtain is anything the same client could not have obtained over
the wire. It prints the access token on stdout and nothing else.

Mint serves plain HTTP and expects TLS termination it does not manage. The
issuer is `https`, and Evidence insists on `https` for both the issuer and the
key set with no exception for loopback, so put a terminator in front of Mint
before this is anything but a local experiment.

The scaffold generates no key material, and none of the commands above print
any. `.gitignore` already excludes every `secrets/` directory in this project,
including Mint's.
