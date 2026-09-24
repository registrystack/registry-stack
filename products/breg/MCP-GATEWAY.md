# Citizen MCP gateway

Two small services let a citizen use an MCP-capable chat application to read
their own permitted Base Registry Engine (BReg) data and prepare a
change-request draft, then submit it themselves on a page built for that one
purpose:

- `registry-breg-mcp` (binary `breg-mcp`) is the MCP gateway. A chat host
  connects to it on the citizen's behalf; it reads the citizen's own data and
  creates or patches change-request drafts. It never submits, revises,
  cancels, or applies anything.
- `registry-breg-review` (binary `breg-review`) is a minimal server-rendered
  review page. The citizen signs in, reads the canonical draft BReg holds,
  and submits it.

Casework reviews the submitted request; BReg applies it once approved. The
two services are shaped like `registry-evidence-oid4vci`: protocol front
ends beside one product that add none of that product's semantics, and that
no product crate depends on.

The two services are separate processes with separate configuration and
separate credentials. No single process ever holds both prepare authority
and submit authority.

## Journey

```text
chat:    ask -> sign in -> read own data -> collect a correction
              -> create or patch a draft -> get a review link
browser: open the review link -> sign in -> read the draft -> confirm -> submit
casework: review
breg:    apply
chat:    ask again -> reports the current status
```

The chat host always reports the state BReg reports (prepared, submitted,
under review, approved, rejected, applied, or cancelled), never a state
either service remembers on its own.

## Boundaries

The gateway can read the citizen's own data and create or patch a
change-request draft; it has no code path to submit, revise, cancel, or
apply a request, or to write any entity directly. Its `clippy.toml`
disallows the `registry-breg-client` methods that would let it do any of
those things, and a boundary check proves that disallowed list still
resolves and still refuses each one.

The review page has no authority of its own. It signs the citizen in, keeps
their access token on the server, and makes every read and the submit with
that token through one configured access profile. What the citizen may see
and submit is BReg's decision, not the page's.

BReg enforces the prepare/submit split; neither service's good behavior is
the boundary. The access profile a standing citizen agent uses, which both
the gateway's outbound token and the chat host's requests carry, may only
read and create or patch change-request drafts: BReg's compiler refuses a
profile of that kind that also holds `submit_request`, `revise_request`,
`cancel_request`, `apply_request`, or any direct mutation outside a change
request. A task grant carries a human's approval inside the grant itself; a
standing agent carries none, so the human has to confirm the change
themselves, by submitting it on the review page. See
[task grants for governed writes](TASK_GRANTS.md) for the compiled ceiling
and its refusal codes.

Binding a change request's target to the citizen is layered, not enforced at
one point. The gateway derives the target from the citizen's own linked
record and never accepts a target identifier as a tool argument. The review
page reads the draft's target under the citizen's own token before offering
Submit, and again before calling it, so a draft naming a record the citizen
cannot read never reaches a submittable form. Casework staff review every
submitted request before BReg applies it. BReg itself does not yet tie a
change request's referenced records to the submitter's own read authority at
the point the request is written or submitted; a request naming another
citizen's record is not refused by the registry on that basis alone. The
gateway, the review page, and Casework review are what close that gap for
this deployment; closing it at the registry is tracked separately and is not
part of either service.

## Configuration

Each service reads its own closed YAML runtime configuration document.
[The gateway's README](../../crates/registry-breg-mcp/README.md) and
[the review page's README](../../crates/registry-breg-review/README.md) give
the full key list, defaults, and an example document for each; this page
does not repeat them. Both refuse an inline secret value: every credential
is a `secret:file/` or `secret:env/` reference, never a literal in the
configuration document.

## Token path

The gateway never holds a citizen identity of its own. For every tool call,
it exchanges the chat host's verified inbound access token for a BReg token
using RFC 8693 token exchange: the inbound token is the `subject_token`, and
the gateway's own client-credentials token, obtained with `private_key_jwt`,
is the `actor_token`. The authorization server re-validates the citizen on
every exchange, so the gateway can never mint a citizen identity of its own;
a compromised gateway cannot impersonate a citizen whose token it was never
handed.

The exchanged token carries the citizen as its subject and the gateway as
its actor, in the `act` claim. BReg accepts `act` as exactly `{sub}`, or as
`{sub, iss}` when `iss` equals the token's own verified issuer; any other
shape, or a nested `act`, is refused. The gateway's actor identity is looked
up under BReg's `trustedActors` mapping for the verified client (see
[task grants for governed writes](TASK_GRANTS.md)); a token whose `act.sub`
does not match the configured value for that client is refused. A token
carrying a verified trusted actor is treated as an agent whatever its own
actor-kind claim says, because a token exchange copies that claim from the
subject token, so it describes the citizen, not the gateway.

For this exchange to work, the authorization server must support:

- Access-token subject exchange: `subject_token_type` names the access-token
  URN, and the server accepts an already-issued access token as the subject,
  not only its own first-party assertions.
- An actor token: the server accepts an `actor_token` obtained by the
  gateway's own client-credentials grant, and folds it into the issued
  token's `act` claim as `{sub}` or `{sub, iss}`.
- An actor token that is not a registry token: the gateway's
  client-credentials grant names the gateway's own resource identifier as
  its `resource`, and the server issues the actor token for that resource,
  never with the registry's audience.
- A bounded exchanged lifetime: the issued token's validity does not exceed
  what the gateway's own client is configured to accept, and the gateway
  clamps it rather than trusting the server to.

Both services are identity-provider neutral: each is configured with an
issuer, a token endpoint, and a JWKS location, not tied to one vendor. The
exchange behavior above was verified against ThunderID, which refuses
anonymous or self-service dynamic client registration for a resource-server
client. Because of that, every chat host a deployment accepts, and the
review page's own client, must be preregistered with the authorization
server ahead of time, each with its own client identity and key; a chat host
cannot bootstrap its own registration at connect time.

## Operation

Both services serve `/health` (the process is up) and `/ready` (its audit
journal is writable).

Both log JSON, filtered by an environment variable: `BREG_MCP_LOG` for the
gateway and `BREG_REVIEW_LOG` for the review page. The two are not the same
kind of setting. `BREG_REVIEW_LOG` accepts exactly `error`, `warn`, or
`info` (the default); any other value stops startup with exit status 2, so a
typo cannot silently change what is logged. `BREG_MCP_LOG` is a tracing
filter directive; it defaults to `info` when unset or when it does not
parse. See
[environment variables](../../docs/site/src/content/docs/reference/environment-variables.mdx)
for both entries in full.

Both services keep a hash-chained audit journal of every action: the request
identifier, the action, keyed pseudonyms of the citizen and the client, and
the outcome. Neither journal records a field value, a prompt, a token, or
model output. An action whose audit record cannot be written fails closed.

The gateway rate limits per citizen and per client. The review page limits
each signed-in citizen, and caps its unauthenticated sign-in routes with one
limit shared by everyone, because it reads neither peer addresses nor
forwarded headers and cannot tell browsers apart before sign-in. Per-client
limiting in front of the review page belongs at the edge proxy, and the
operator must configure it there. A request over any limit gets a `429` with
`Retry-After`.

The review page keeps sign-in and review state in memory only. Restarting it
discards every open sign-in and every in-progress review; a citizen
mid-review signs in again and reads the current draft from BReg. The gateway
is stateless apart from its MCP transport session: restarting it loses
nothing a citizen would need recovered, since every draft it wrote already
lives in BReg.
