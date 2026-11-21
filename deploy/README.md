# Deploy Registry Stack with Helm

This folder is a public reference. It is not a supported product, is not published with Registry Stack releases, and has not been checked for production use.

Use the Registry Stack chart on Ubuntu 24.04 or 26.04 amd64 with K3s. On an existing Kubernetes cluster, give it the same inputs. The chart runs Base Registry Engine (BReg), Casework, Evidence and a prebuilt App Kit host. Each component is opt-in. Use the same Stack release for the products, tools and clients in one installation.

This guide targets Registry Stack v0.46.0. The example values pin every image by digest from that release manifest. The `deploy/` folder is not part of any release tag. Use it from the commit that carries this guide, and record that commit with the installation. Install `bregctl` v0.46.0 to match the images.

The deployment commands use Python 3.11 or newer. Both supported Ubuntu releases provide a suitable Python version. Helm 4 is the only supported Helm version. The install section installs it.

## Plan one installation

Choose a namespace and release name, an HTTPS hostname for each public component, an institutional OIDC issuer, and an encrypted backup destination on another system. Start with one BReg registry per release. A partner can deploy additional registries as separate releases with their own names, credentials and storage.

Use PostgreSQL 17 with one database and distinct runtime and migration roles per product. On the shared reference PostgreSQL, revoke CONNECT on each product database from PUBLIC and grant it only to that product's roles. `prepare_local.py` does this for BReg. The single-server example runs PostgreSQL on the same server with a retained local volume. Reserve space for database, packages, audits and backup staging. Four cores, 8 GiB RAM and SSD storage are a starting point for a small registry. Size from the expected records, writes and enabled components before accepting traffic.

The single-server preparation stores retained application volumes below `/var/lib/registry-stack/storage`. When the server has a dedicated data filesystem, mount it there persistently before running `prepare_local.py`. Otherwise those volumes use the operating-system filesystem.

| Component | Deployment input |
| --- | --- |
| BReg | Published Stack OCI image, sealed BReg package, runtime config and audit claim |
| Casework | Same-release image, sealed package, separate PostgreSQL database and audited producer and reviewer identities |
| Evidence | Same-release image, sealed bundle, retained authority and audit, and an institution-operated Vault Transit signer reached through the chart's Transit proxy. Evidence in this chart cannot serve without it. |
| App Kit | Partner-built OCI image with matching Stack client, host config, PostgreSQL state and its OIDC client |
| Optional object storage | Operator-owned S3-compatible service. See the [SeaweedFS profile](examples/seaweedfs/README.md). |
| Extension endpoints | Partner-built OCI images. Bind their names and paths in the chart's `extensions` values and deploy them as a [separate release of the same chart](examples/intake-status/README.md). |

Messaging, Scheduling, Discovery, Render, Coordinator and the BReg MCP and review and Evidence OID4VCI images have their own release contracts. They have no modules in this chart. Document Store is held from the release. Adapter has native binaries in v0.46.0. Check the release manifest before selecting an additional service.

## Install one Ubuntu server

Decide now whether you may add servers later. A server installed without a private API DNS name can never join a cluster, because the bootstrap records its inputs and refuses changed ones. Pass the name now if you might expand. The name must already resolve to the server or to an operator-provided load balancer. The bootstrap installs a pinned K3s version. You do not choose it.

On the new server, from a checkout of that commit, install K3s and Helm. Add the API DNS name after `--install` if you need it.

```bash
sudo bash deploy/bin/bootstrap-k3s.sh --install
sudo bash deploy/bin/install-helm.sh /usr/local/lib/registry-stack
sudo k3s kubectl -n kube-system wait --for=create job/helm-install-traefik --timeout=3m
sudo k3s kubectl -n kube-system wait --for=condition=complete job/helm-install-traefik --timeout=5m
sudo k3s kubectl apply -f deploy/k3s/traefik-https.yaml
sudo k3s kubectl -n kube-system rollout status deployment/traefik --timeout=3m
```

The bootstrap waits only for the node to be ready. K3s installs Traefik afterwards through a Job, so the two `wait` commands make the rollout check start after that Job exists and has finished. Applying the configuration restarts Traefik, so the last command waits for the new rollout. If a command reports that the resource is not found, wait a minute and run it again.

Point the application DNS names at the ingress address. Permit inbound 443 and 80 for the HTTPS redirect. Restrict 6443 and SSH to the administrative network. Install a certificate trusted by your clients and include any issuing intermediates. Use an existing certificate renewal mechanism and replace the TLS Secret before expiry. The chart uses the ingress controller for TLS termination. Choose a controller or load balancer policy that drops or redirects HTTP before it can reach an application.

### Prepare and start BReg

Do this step on a build workstation, not the server. Install `bregctl` v0.46.0 with the [BReg installer](https://docs.registrystack.org/operate/breg/#obtain-the-runtime) and provide a disposable PostgreSQL 17 database for the schema test. Then run the same-release `bregctl check --production`, `test`, and `package` on your project. The test needs the journey's real authorisation bindings. Follow the [BReg package and runtime instructions](https://docs.registrystack.org/operate/breg/#check-test-package). Copy the sealed `package/` root, its digest and the runtime config into a private directory on the server.

Copy [the v0.46.0 example values](examples/local-breg/values.json) into that directory as `values.json`. Set the hostname, package digest, versioned input names and namespace selectors for your installation. `prepare_local.py` uses this layout.

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

Create the certificates, keys and passwords on the server. You choose the two role passwords. `prepare_local.py` sets them on the PostgreSQL roles. Hexadecimal passwords need no URL encoding. Replace `directory` with your namespace. Run the block as root, for example from `sudo -i`, so that only root can read the files.

```bash
IN=/srv/registry-directory/inputs
umask 077
install -d -m 0700 "$IN" "$IN/breg-runtime" "$IN/breg-migration"

# Private CA for PostgreSQL. The CA certificate is the database trust root.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$IN/pg-ca.key"
openssl req -x509 -new -key "$IN/pg-ca.key" -sha256 -days 3650 \
  -subj "/CN=Registry PostgreSQL CA" -out "$IN/breg-runtime/database-ca"

# PostgreSQL server certificate for its Service DNS name.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$IN/pg-server.key"
openssl req -new -key "$IN/pg-server.key" -subj "/CN=registry-postgres" -out "$IN/pg-server.csr"
printf 'subjectAltName=DNS:registry-postgres.directory.svc.cluster.local\n' > "$IN/pg-server.ext"
openssl x509 -req -in "$IN/pg-server.csr" -CA "$IN/breg-runtime/database-ca" -CAkey "$IN/pg-ca.key" \
  -CAserial "$IN/pg-ca.srl" -CAcreateserial -days 365 -sha256 -extfile "$IN/pg-server.ext" -out "$IN/pg-server.crt"

# Keys and passwords. Files carry no trailing newline.
openssl rand -hex 32 | tr -d '\n' > "$IN/pg-bootstrap"
openssl rand -hex 32 | tr -d '\n' > "$IN/breg-runtime/audit-key"
openssl rand -hex 32 | tr -d '\n' > "$IN/breg-runtime/cursor-key"
RUNTIME_PASSWORD=$(openssl rand -hex 24)
MIGRATION_PASSWORD=$(openssl rand -hex 24)
URL_HOST=registry-postgres.directory.svc.cluster.local:5432/registry_breg
printf 'postgresql://registry_runtime:%s@%s' "$RUNTIME_PASSWORD" "$URL_HOST" > "$IN/breg-runtime/runtime-database-url"
printf 'postgresql://registry_migration:%s@%s' "$MIGRATION_PASSWORD" "$URL_HOST" > "$IN/breg-migration/migration-database-url"
unset RUNTIME_PASSWORD MIGRATION_PASSWORD
```

Every file in `breg-runtime/` and `breg-migration/` becomes a key of a Kubernetes Secret, so keep other files out of those folders. Move `pg-ca.key` off the server once the certificate is issued, and keep it with your other CA keys.

For the HTTPS certificate, use one issued by a CA your clients trust. Save its chain as `ingress.crt` and its key as `ingress.key`. A self-signed certificate made with `openssl req -x509` works for a test, but clients will refuse it.

Keep credential and private-key files owner-only. The two database URLs name `registry_runtime` and `registry_migration`, respectively, on `registry-postgres.<namespace>.svc.cluster.local:5432/registry_breg`. Encode any reserved characters in passwords as URL components. Put the PostgreSQL CA in `breg-runtime/database-ca`. Reference it from the `trustedRootCertificateRef` field of the BReg `runtime.yaml`. That field is part of the BReg runtime file, not a chart value. If the OIDC issuer uses a private CA, also supply its CA with the chart's `breg.caBundleKey`. Configure the issuer's exact HTTPS origin and a network policy that admits the actual issuer endpoint. On K3s, traffic to a Service can be matched at its destination Pod and target port.

Pass the `--database-id` below the same value as `identity.databaseId` in `runtime.yaml`. The claim check refuses an install when the two differ. Pass `--operator-reference` with the change or ticket reference for this installation. BReg records a keyed hash of it with the first activation, so its runtime audit profile must be keyed. Running `install` again later, for example to reopen after `stop`, activates nothing and needs no reference.

```bash
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/prepare_local.py \
  --kube-context default --namespace directory --release directory \
  --inputs /srv/registry-directory/inputs

sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml python3 deploy/stack_operator.py \
  --helm-bin /usr/local/lib/registry-stack/helm --kube-context default \
  --namespace directory --release directory --database-id directory-db \
  --values /srv/registry-directory/inputs/values.json \
  install --operator-reference CHANGE-1234

curl --fail https://directory.example.org/ready
```

The first command prepares the local database and retained storage, then stages immutable named inputs. The second command checks the BReg plan, applies the exact initial package, verifies the ledger and doctor report, and starts serving. Reuse the same inputs to retry. Use a new package claim and versioned input names for a changed package.

Use your identity provider to register the exact clients and return the claims the package requires. Test with one allowed and one denied request before opening the service. The [ThunderID reference](identity/README.md) illustrates the identity contracts with synthetic users and secrets. Its ThunderID namespace is `registry-identity-qualification`, separate from the product namespace (`directory` in this guide).

### Enable other components

Prepare their database, immutable configuration, Secrets and retained claims using the [chart inputs](helm/registry-stack/README.md). Use the product operation Jobs before enabling traffic for Casework or Evidence. The [Casework and Evidence checks](examples/casework-evidence/README.md) show those sequences with synthetic data. Evidence also needs a Vault Transit signer reached through the chart's Transit proxy. It will not serve without one.

For App Kit, apply the state schema as its database owner and use the chart's documented host config paths. A runtime client gets only its own narrow role, audience and scope. Treat a generated App Kit UI model as an input to the image build and host configuration.

PostgreSQL admits only Pods labelled `registrystack.org/database-client: "true"`. The chart sets that label on BReg, Casework and App Kit. Anything else that connects to the database needs its own NetworkPolicy, as [`identity/postgres-network-policy.yaml`](identity/postgres-network-policy.yaml) does.

## Use a Restricted namespace

On the single server, `prepare_local.py` creates the namespace with the Restricted Pod Security level. On an existing cluster, create it yourself:

```bash
kubectl create namespace directory
kubectl label namespace directory pod-security.kubernetes.io/enforce=restricted
```

Then provision the named inputs in that namespace. The chart's Pods run as non-root with a read-only root filesystem, so they pass the Restricted level. An image that needs more privilege is refused at admission.

## Expand to a small cluster

Use three K3s servers with embedded etcd on independent machines or failure domains. Establish a private load-balanced API address and a stable HTTPS ingress address. Install the first server with the API DNS name, as described in the install section. Pass the same API DNS name to each peer. Copy the first server's `/var/lib/rancher/k3s/server/token` directly into a root-only file on each peer through an encrypted administrative channel.

```bash
sudo bash deploy/bin/bootstrap-k3s.sh \
  --join https://api.example.org:6443 /etc/rancher/k3s/server-token api.example.org
sudo k3s kubectl get nodes
```

Size for quorum and storage separately. The application chart still has a single serving BReg replica per registry. A retained local PostgreSQL or audit volume stays on its node. For service continuity through a node outage, supply an existing highly available PostgreSQL service. Also supply a storage class that can reattach the required volumes on another node. Test the ingress and each storage dependency under a real node outage before you commit to a recovery time.

On a standard Kubernetes cluster, use its existing ingress, storage and encryption controls. Create a Restricted namespace as shown above, provision the same named inputs, and use the same chart and operator. Ensure the CNI enforces NetworkPolicy. An empty ingress list admits no other Pod. On K3s, the node itself and `hostNetwork` Pods on that node still reach the Pod. Treat access to the node as access to its service ports. Place current Linux amd64-only product artifacts on eligible nodes. Standard Kubernetes deployment does not require K3s-specific CRDs.

The status and doctor Jobs mount the BReg audit claim while BReg is serving. That claim is ReadWriteOnce. On a multi-node cluster, a Job Pod scheduled on a different node cannot attach the volume and waits. This is expected behaviour of the reference. The chart sets no affinity by default and applies `breg.nodeSelector` and `breg.affinity` to the Jobs as well as to serving. Set one of them to keep both on one node, or use storage that allows Pods on different nodes to share the volume.

See [Operate the installation](OPERATIONS.md) for upgrades, recovery and monitoring.
