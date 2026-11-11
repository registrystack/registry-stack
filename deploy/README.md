# Deploy Registry Stack with Helm

Use the Registry Stack chart on Ubuntu 24.04 amd64 with K3s, or give it the same inputs on an existing Kubernetes cluster. The chart runs BReg, Casework, Evidence and a prebuilt App Kit host. Each component is opt-in. Use the same Stack release for the products, tools and clients in one installation.

The deployment commands use Python 3.11 or newer. Ubuntu 24.04 includes Python 3.12.

## Plan one installation

Choose a namespace and release name, an HTTPS hostname for each public component, an institutional OIDC issuer, and an encrypted backup destination on another system. Start with one BReg registry per release. A partner can deploy additional registries as separate releases with their own names, credentials and storage.

Use PostgreSQL 17 with one database and distinct runtime and migration roles per product. The single-server example runs PostgreSQL on the same server with a retained local volume. Reserve space for database, packages, audits and backup staging. Four cores, 8 GiB RAM and SSD storage are a starting point for a small pilot. Size from the expected records, writes and enabled components before accepting traffic.

| Component | Deployment input |
| --- | --- |
| BReg | Published Stack OCI image, sealed BReg package, runtime config and audit claim |
| Casework | Same-release image, sealed package, separate PostgreSQL database and audited producer and reviewer identities |
| Evidence | Same-release image, sealed bundle, retained authority and audit, and an institution-operated Transit signer |
| App Kit | Partner-built OCI image with matching Stack client, host config, PostgreSQL state and its OIDC client |
| Optional object storage | Operator-owned S3-compatible service. See the [SeaweedFS profile](examples/seaweedfs/README.md). |
| Workspace endpoints | Partner-built OCI images. Publish endpoint names and paths with the workspace and deploy them as a [separate release of the same chart](examples/intake-status/README.md). |

Messaging, Scheduling, Discovery, Render, Coordinator and the BReg MCP and review and Evidence OID4VCI images have their own release contracts. They have no modules in this chart. Document Store is held from the release. Adapter has native binaries in v0.46.0. Check the target release manifest before selecting an additional service.

## Install one Ubuntu server

From a checked-out deployment revision on the new server, install the pinned K3s and Helm tools. Use the private API DNS name only when it already resolves to the server or an operator-provided load balancer.

```bash
sudo bash deploy/bin/bootstrap-k3s.sh --install
sudo bash deploy/bin/install-helm.sh /usr/local/lib/registry-stack
sudo k3s kubectl apply -f deploy/k3s/traefik-https.yaml
sudo k3s kubectl -n kube-system rollout status deployment/traefik --timeout=3m
```

Point the application DNS names at the ingress address. Permit inbound 443 and 80 for the HTTPS redirect. Restrict 6443 and SSH to the administrative network. Install a certificate trusted by your clients and include any issuing intermediates. Use an existing certificate renewal mechanism and replace the TLS Secret before expiry. The chart uses the ingress controller for TLS termination. Choose a controller or load balancer policy that drops or redirects HTTP before it can reach an application.

### Prepare and start BReg

Run the same-release `bregctl check --production`, `test`, and `package` on the selected project. The test requires a disposable schema-test database and the journey's real authorization bindings. Use the [BReg package and runtime instructions](https://docs.registrystack.org/operate/breg/#check-test-package). Copy the sealed `package/` root, its digest and the runtime config into a private directory on the server. A saved Studio Publish handover can select the products and generate chart values after you bind the approved artifacts. See [Use a published workspace](#use-a-published-workspace).

Copy [the v0.46.0 example values](examples/local-breg/values.json) into that directory as `values.json`. Set the hostname, package digest, versioned input names and namespace selectors for your installation. This layout is used by `prepare_local.py`.

| Path inside the private input directory | Contents |
| --- | --- |
| `values.json` | Helm bindings with no credential values |
| `runtime.yaml` | BReg runtime file with the [chart's fixed mount paths](helm/registry-stack/README.md#breg-input-contract), exact issuer, audience and clients, and stable database and instance IDs |
| `package/` | Closed package reported by the matching release of `bregctl package` |
| `breg-runtime/` | `runtime-database-url`, `database-ca`, `audit-key`, `cursor-key`, and any other reviewed runtime files |
| `breg-migration/` | `migration-database-url` and any files needed only by migration Jobs |
| `pg-server.crt`, `pg-server.key` | PostgreSQL server certificate with the Service DNS name and matching key |
| `pg-bootstrap` | A random, owner-only initial PostgreSQL administrative password file |
| `ingress.crt`, `ingress.key` | HTTPS server certificate chain and key for BReg |

Keep credential and private-key files owner-only. The two database URLs name `registry_runtime` and `registry_migration`, respectively, on `registry-postgres.<namespace>.svc.cluster.local:5432/registry_breg`. Encode any reserved characters in passwords as URL components. Put the PostgreSQL CA in `breg-runtime/database-ca` and bind it using `database.trustedRootCertificateRef`. If the OIDC issuer uses a private CA, supply its CA with the chart's `breg.caBundleKey` as well. Configure its exact HTTPS origin and a network policy that admits the actual issuer endpoint. On K3s, traffic to a Service can be matched at its destination Pod and target port.

```bash
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/prepare_local.py \
  --kube-context default --namespace directory --release directory \
  --inputs /srv/registry-directory/inputs

sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
  --helm-bin /usr/local/lib/registry-stack/helm --kube-context default \
  --namespace directory --release directory --database-id directory-db \
  --values /srv/registry-directory/inputs/values.json install

curl --fail https://directory.example.org/ready
```

The first command prepares the local database and retained storage, then stages immutable named inputs. The second command checks the BReg plan, applies the exact initial package, verifies the ledger and doctor report, and starts serving. Reuse the same inputs to retry. Use a new package claim and versioned input names for a changed package.

Use your identity provider to register the exact clients and return the claims the package requires. Test with one allowed and one denied request before opening the service. The [ThunderID reference](identity/README.md) illustrates the identity contracts with synthetic users and secrets.

### Enable other components

Prepare their database, immutable configuration, Secrets and retained claims using the [chart inputs](helm/registry-stack/README.md). Use the product operation Jobs before enabling traffic for Casework or Evidence. The [Casework and Evidence qualification](examples/casework-evidence/README.md) shows those sequences with synthetic data. For App Kit, apply the state schema as its database owner and use the chart's documented host config paths. A runtime client gets only its own narrow role, audience and scope. Treat a generated App Kit UI model as an input to the image build and host configuration.

## Use a published workspace

In Studio, save, check and publish the workspace. Use the output directory with `workspace/generated.json`. Run the same-release product compilers on the published files and prepare operator values containing their image and package digests. Set `workspaceSourceHash` in that input to the approved Publish source hash. Bind private runtime inputs by Kubernetes name.

```bash
python3 deploy/workspace_values.py \
  --workspace-root /srv/registry-directory/published \
  --bindings /srv/registry-directory/operator-bindings.json \
  --product breg > /srv/registry-directory/inputs/values.json
```

Repeat `--product` for the chart modules you want to serve. With no selection, the adapter selects the generated products and reports any that lack chart modules. The adapter checks every indexed file and binds values to the saved source hash. The product compiler still validates and seals the actual package. Preserve the package receipt with the handover.

## Expand to a small cluster

Use three K3s servers with embedded etcd on independent machines or failure domains. Establish a private load-balanced API address and a stable HTTPS ingress address. Supply the same API DNS name and K3s version to each server. On the first server, use `--install api.example.org`. Copy the first server's `/var/lib/rancher/k3s/server/token` directly into a root-only file on each peer through an encrypted administrative channel.

```bash
sudo bash deploy/bin/bootstrap-k3s.sh \
  --join https://api.example.org:6443 /etc/rancher/k3s/server-token api.example.org
sudo k3s kubectl get nodes
```

Size for quorum and storage separately. The application chart still has a single serving BReg replica per registry. A retained local PostgreSQL or audit volume stays on its node. If you require service continuity through a node outage, supply an existing highly available PostgreSQL service and storage class that can reattach the required volumes on another node. Qualify the ingress and each storage dependency under a real node outage before committing to a recovery time.

On a standard Kubernetes cluster, use its existing ingress, storage and encryption controls. Create a Restricted namespace, provision the same named inputs, and use the same chart and operator. Ensure the CNI enforces NetworkPolicy. Place current Linux amd64-only product artifacts on eligible nodes. Standard Kubernetes deployment does not require K3s-specific CRDs.

See [Operate the installation](OPERATIONS.md) for upgrades, recovery and monitoring.
