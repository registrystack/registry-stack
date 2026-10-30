# Git-managed deployment targets

This directory is a source-neutral, ready-to-copy configuration-repository
shape. It keeps reviewed Evidence semantics under `shared/evidence-project/`
and every environment's complete deployment bindings under
`environments/<name>/`. Private keys, audit masters, provider tokens, auto-auth
credentials, access tokens, live responses, and real identifiers never belong
here.

The examples deliberately repeat complete environment documents. They use no
overlays, environment branches, symlinks, or runtime substitutions. Replace the
reserved `example.org` identities with controlled endpoints and replace the
example public keys with the exact public projections of independently created
environment keys. Evidence signing, Evidence audit, and subject-binding keys
must all remain distinct.

Run `./check-public-key-separation.sh` after replacing keys. It uses Python 3
and PyYAML to parse client registrations structurally, fingerprints the complete
public material of Ed25519, P-256, and RSA client keys, verifies every
service-key filename and `kid` against the RFC 7638 thumbprint, and rejects
private, malformed, or reused public material across roles or environments.

```text
shared/
  evidence-project/
environments/
  local/
    evidence/{target.yaml,authority.yaml,public-keys/}
  staging/
    evidence/{target.yaml,authority.yaml,public-keys/}
    transit/{proxy-configs/,policies/}
  production/
    evidence/{target.yaml,authority.yaml,public-keys/}
    transit/{proxy-configs/,policies/}
```

For staging or production, copy the reviewed shared project at one source
revision, select `environments/<name>/evidence/` as the `evidencectl package`
target, and create a new candidate. `target.yaml` is a normalized `EvidenceTarget` and references the complete
`EvidenceTargetAuthority` in `authority.yaml`. Set both `project` fields to the
shared EvidenceProject ID and review each definition, purpose, role, selector,
representation and binding against its ceiling. The example grant names
`record-status` and `record-reference-v1`; replace these with your project's
identifiers. Add the connections or extract bindings required by its Sources.
`evidencectl package` resolves the signer's public key from the target, then
emits `bundle/`, `runtime.yaml` and `compiled-authority.yaml` in one candidate. Build staging
and production separately from the same source revision. Do not promote a
staging candidate by editing its bytes.

The proxy configurations use a dedicated Unix socket, force the proxy's
auto-auth token, and require the `X-Vault-Request` header Evidence sends.
They explicitly disable provider retries so one application signing attempt is
one Transit signing request. Leave `VAULT_MAX_RETRIES` unset for these workloads
because it overrides the reviewed proxy value. The application timeout remains
the outer bound.
The included Kubernetes auto-auth block is the one deployment-specific part:
replace its server address, CA path, auth mount, role, socket user/group, and
namespace as applicable. Vault Proxy and OpenBao Agent accept the same relevant
listener, auto-auth, and API-proxy shape. Use one proxy identity and one policy
per service.

ACLs grant read metadata and sign access to one named key. Their required and
allowed parameter constraints admit only the exact signing request shape and
the version pinned by Evidence. Evidence sends `key_version` as a string, which
OpenBao accepts and matches against the policy, so pin quoted version strings.
During planned rotation, add the next quoted version string to
`allowed_parameters.key_version`, deploy the overlap, then
remove the old version after the token or assertion validity window and
consumer skew have elapsed. Raising the Transit key's
`min_encryption_version` is a second retirement control. Emergency retirement
raises it immediately, removes the public JWK, and deny-lists the thumbprint in
affected consumers.

Local private JWKs and audit masters are disposable files created outside Git.
`evidencectl init` and `evidencectl dev` remain the normal application-developer
path; the local target documents disposable bindings and cannot be packaged
as a production candidate.

Install the candidate's `bundle/` at the emitted runtime's `package.root`,
provision its referenced secrets and signer transport, and activate
`compiled-authority.yaml` with `evidence authority activate --runtime-config
<candidate>/runtime.yaml --document <candidate>/compiled-authority.yaml`.
Before routing an environment, run `evidencectl doctor --runtime-config
<candidate>/runtime.yaml`, all Evidence fixtures, and
`evidence check --runtime-config <candidate>/runtime.yaml
--require-runtime-dependencies`, then confirm the Evidence `/ready` endpoint. A
signer whose controls, pinned version, or public key differ from these governed
files must fail the handoff.

The Transit API and proxy assumptions follow the provider documentation:

- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- [Vault Proxy API proxy](https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/apiproxy)
- [OpenBao Agent](https://openbao.org/docs/agent-and-proxy/agent/)
- [OpenBao Transit API](https://openbao.org/api-docs/secret/transit/)
