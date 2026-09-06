# Source credential rotation

Credential files are process-local secret inputs. Their bytes stay outside the
governed bundle and its configuration revision. Changing an endpoint, a secret
reference, an authentication policy, an audience or a TLS trust-profile name
requires a newly built and reviewed governed candidate.

Static credentials are read when used. OAuth credentials are read when a token
exchange is needed. Replacing a file at the same `secret:file/...` reference
therefore leaves an unexpired cached OAuth token in use until its bounded
expiry. A named connection shares that cache among its operations in one
process. Separate connection names and processes have independent caches.
There is no credential-file watcher or immediate cache invalidation promise.

Use this conservative sequence for an ordinary rotation:

1. Provision the successor credential with the provider while the predecessor
   remains valid for an agreed overlap. Preserve the existing narrow source
   permissions and both configured OAuth audiences.
2. Place the successor in owner-only files under the existing mounted secret
   root, readable by the eventual Evidence service identity. Replace each file
   atomically. Coordinate a multi-file credential change while the service is
   drained so no token request sees a mixed pair.
3. If immediate token replacement is required, pause new traffic, drain active
   requests, and restart every Evidence process using the credential. Restart
   preserves the configured audit storage and starts an empty OAuth cache.
4. Under the actual service identity, perform the documented synthetic source
   check against the intended provider and request an independently verified
   Evidence assertion. Offline fixtures do not prove current source access,
   TLS trust, provider permissions or token audience. Resume traffic after the
   check succeeds.
5. Retire the predecessor after the agreed provider overlap and token lifetime.
   Record the provider's successful retirement without storing credentials,
   tokens or source responses in logs or review evidence.

For emergency revocation, follow the provider's actual access-token validity
and revocation behavior. Revoking a client secret or assertion key may prevent
new exchanges while already issued access tokens remain valid. Restart clears
Evidence's cache but cannot revoke a token at the provider. Evidence performs
no automatic fallback to a predecessor credential and no hidden source retry.
