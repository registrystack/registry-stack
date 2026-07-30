# Custom HTTP Registry Stack project

This starter demonstrates one bounded product-neutral HTTP integration.

From this workspace directory:

```bash
registryctl -C . tooling editor
registryctl -C . test --integration person-record --fixture active-person --trace
registryctl -C . test --integration person-record --fixture active-person --watch
registryctl -C . test
registryctl -C . dev --environment local --detach
registryctl -C . dev --environment local smoke
registryctl -C . dev --environment local down
registryctl -C . check --environment local --explain
registryctl -C . build --environment local
```

`tooling editor`, `test`, `check`, and `build` are human-readable by default. Use `--format json`
with those report commands only for machine consumers. Editor setup uses the five schemas copied
from this `registryctl` build for VS Code and Zed.

Edit `integrations/person-record/integration.yaml` and its synthetic fixtures.
Keep real destinations and credentials only in `environments/` secret bindings.
The authored `local` environment selects the `active-person` synthetic fixture,
so `registryctl dev` needs no integration or fixture flags. Generated development
lanes under `.registry-stack/dev-artifacts/` and bound runtime state under
`.registry-stack/dev/` are disposable, ignored by Git, and are not production
inputs.

After the local journey succeeds, use the maintained
[initial approval](https://docs.registrystack.org/operate/approve-initial-baseline/)
and [generated Compose package](https://docs.registrystack.org/operate/single-node-compose-behind-proxy/)
guides. Signing, operator secrets, initialization, and Docker activation stay
explicit and separate from `registryctl dev`.
