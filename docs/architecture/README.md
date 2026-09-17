# Registry Stack architecture

Use these diagrams to understand BReg, Casework and Evidence responsibilities,
follow requests and events, and inspect the contracts between independently deployed products.
The model pins source revision `c02e470085f48eae0204ba8400f9f919c5d05500`, reviewed on
13 September 2026. It includes unreleased contextual authorization changes and does
not describe the published v0.30.0 release.

## Open the explorer

You need Node.js 22.22.3 or newer and npm. From this directory:

```sh
npm ci
npm run dev
```

Open the URL printed by LikeC4, normally [the local explorer](http://localhost:5184/).
In navigation, **By folders** groups the `Product / NN. Title` view-title prefixes;
**By files** follows source directories. Select a component or relationship to read
its description and pinned source links. **Navigate to view** follows a linked flow
or opens a runtime's internal responsibilities. For a long flow, select **Sequence**,
then **Start** to read its steps in order.

These links use the default local port:

| Your question | Views |
| --- | --- |
| How do the three products connect? | [Product composition](http://localhost:5184/view/composition/), [BReg interoperability](http://localhost:5184/view/interoperability/), [Casework interoperability](http://localhost:5184/view/casework_interoperability/), [Evidence interoperability](http://localhost:5184/view/evidence_interoperability/) |
| Who issues each credential, and when does it expire? | [Token trust](http://localhost:5184/view/authentication/), [credentials and deadlines](http://localhost:5184/view/task_authority/) |
| Who approves agent work, and how does the agent obtain authority? | [Human approval](http://localhost:5184/view/casework_task_approval/), [task exchange](http://localhost:5184/view/task_token_exchange/) |
| What happens after revocation? | [Revocation and remaining reads](http://localhost:5184/view/task_revocation/), [task writes](http://localhost:5184/view/breg_task_write/) |
| What gates data access and response release? | [BReg reads](http://localhost:5184/view/breg_read/), [Evidence assertions](http://localhost:5184/view/evidence_assertion/), [Evidence task authorization](http://localhost:5184/view/evidence_task_assertion/) |
| How are events and uncertain actions handled? | [BReg delivery](http://localhost:5184/view/event_delivery/), [delivery recovery](http://localhost:5184/view/event_recovery/), [Casework event intake](http://localhost:5184/view/casework_source_event/), [action recovery](http://localhost:5184/view/casework_attempt_recovery/) |
| What owns wallet delivery? | [Wallet architecture](http://localhost:5184/view/evidence_wallet_architecture/), [wallet delivery](http://localhost:5184/view/evidence_wallet_delivery/) |

Each product folder also contains architecture, runtime, and authoring views.

## Read the boundaries

Blue rectangles represent runtimes and their internal responsibilities; blue component
shapes represent libraries running inside their consumers. Grey shapes represent
people, external systems, storage, artifacts and credentials. Grey rectangles with a
dashed border are command-line tools. The viewer's legend names each element kind.
Tags mark optional integrations, trial interfaces and task authority.

Solid arrows represent calls and replies, dashed arrows represent asynchronous events,
and dotted arrows represent artifact or credential movement. The configuration's
solid relationship default also applies to return and self steps; keep that default
when changing styles so replies are not mistaken for asynchronous events.

The products retain separate authentication, authorization, disclosure, audit and
storage boundaries. A shared issuer or exported description grants no shared access.
Casework can host decisions without BReg; Evidence can use other fixed sources.
The BReg action-to-Evidence integration remains a trial surface.

Task profiles can authorize BReg reads as well as governed change-request work.
Fresh Casework status gates new BReg task writes and later approval/application.
BReg task reads and task-bound Evidence requests check expiry locally. In the maintained
ThunderID setup, existing-token re-exchange can keep reads available after revocation
until the original grant deadline, at most 900 seconds after approval. The 300-second
access-token setting does not shorten that entire window; other issuers own their
registration and exchange policy. The credential and revocation views show these limits.

Audit minimization differs by product. Evidence source-access and terminal events
record requirement and purpose identifiers in plain text while omitting raw task
subjects; authorization refusals omit unresolved requirement and purpose. BReg audit
records the grant source issuer; Evidence audit has no corresponding source-issuer
field. Both use their product-specific pseudonyms for identity context.

For exact contracts, use the pinned [BReg task rules][breg-tasks],
[Casework task rules][casework-tasks], [BReg event contract][events],
[Casework runtime contract][casework-runtime], and [Evidence operator contract][evidence].
The diagrams link to implementation where a source document is less precise.

## Maintain and build

`specification.c4` defines kinds, tags and notation. `Authentication/` describes
credentials and their use. Product `model.c4` files declare runtimes and selected
supporting systems; relationships are also extended in `Authentication/model.c4`
and `interoperability.c4`. Product `views.c4` files select structures and flows;
`composition.c4` selects the combined view. `shared-views.c4` supplies common
relationship labels for structural views.

Keep existing view IDs stable because they form shared URLs. Update the model and
its pinned source evidence together. LikeC4 checks model syntax and layout; it does
not infer architecture or verify prose against Rust.

```sh
npm exec -- likec4 format
npm run check
npm run build
```

`check` validates and checks formatting. `build` creates the static explorer in
`dist/`. Dependencies and generated output are ignored; maintain the model,
configuration and lockfile. This explorer is separate from the Astro/Starlight site.
If port 5184 is occupied, use `npm run dev -- --port 5185` and adjust the links above.

[breg-tasks]: https://github.com/registrystack/registry-stack/blob/c02e470085f48eae0204ba8400f9f919c5d05500/products/breg/TASK_GRANTS.md
[casework-tasks]: https://github.com/registrystack/registry-stack/blob/c02e470085f48eae0204ba8400f9f919c5d05500/products/casework/TASK_GRANTS.md
[events]: https://github.com/registrystack/registry-stack/blob/c02e470085f48eae0204ba8400f9f919c5d05500/products/breg/EVENTS-AND-WEBHOOKS.md
[casework-runtime]: https://github.com/registrystack/registry-stack/blob/c02e470085f48eae0204ba8400f9f919c5d05500/products/casework/RUNTIME-CONFIG.md
[evidence]: https://github.com/registrystack/registry-stack/blob/c02e470085f48eae0204ba8400f9f919c5d05500/products/evidence/OPERATOR-CONTRACT.md
