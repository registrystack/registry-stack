# Optional SeaweedFS storage for BReg attachments

This profile adds one small SeaweedFS S3-compatible store to a K3s Registry
Stack installation. It uses the unmodified upstream chart and image. It does
not install an operator, admin UI, worker, COSI driver, object-versioning
workflow, or a Registry Stack-owned storage chart.

The reference layout is a single-node pilot, not an HA storage service. It has
one master, one filer, one volume server, and one S3 gateway. Master metadata,
filer metadata, and object bytes use separate PVCs. Loss of the node or any one
PVC can lose the attachment store, so the backup procedure below is part of the
operating contract.

## Pinned upstream inputs

| Input | Exact identity |
| --- | --- |
| Chart repository | `https://seaweedfs.github.io/seaweedfs/helm` |
| Chart | `seaweedfs`, version `4.53.0` |
| Chart archive SHA-256 | `778f079cfbdf026a1a523569d385816d00df51ac049b1383db0cfaf6a094656c` |
| Source tag | `4.53`, commit `4ab66fb76da83700739f5839e62fcaf15fb7d02a` |
| Image | `chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0` |

The upstream sources for this profile are the [4.53 release](https://github.com/seaweedfs/seaweedfs/releases/tag/4.53), the [4.53 chart README](https://github.com/seaweedfs/seaweedfs/blob/4.53/k8s/charts/seaweedfs/README.md), its [values contract](https://github.com/seaweedfs/seaweedfs/blob/4.53/k8s/charts/seaweedfs/values.yaml), and the [S3 API guide](https://github.com/seaweedfs/seaweedfs/wiki/Amazon-S3-API).

Verify the downloaded chart before rendering it:

```bash
helm repo add seaweedfs https://seaweedfs.github.io/seaweedfs/helm
helm repo update seaweedfs
helm pull seaweedfs/seaweedfs --version 4.53.0 \
  --destination /absolute/private/seaweedfs-chart
printf '%s  %s\n' \
  778f079cfbdf026a1a523569d385816d00df51ac049b1383db0cfaf6a094656c \
  /absolute/private/seaweedfs-chart/seaweedfs-4.53.0.tgz | shasum -a 256 -c -
helm template registry-seaweedfs \
  /absolute/private/seaweedfs-chart/seaweedfs-4.53.0.tgz \
  --namespace registry-storage \
  --values deploy/examples/seaweedfs/values.reference.yaml \
  >/absolute/private/seaweedfs-rendered.yaml
```

Review the render before applying it. Confirm every master, filer, volume, and
S3 container uses the digest above; only three PVCs are rendered; no
ClusterRole, admin, worker, COSI, all-in-one, resize-hook, or extra image is
present.

## Authority and secret split

SeaweedFS expands the `${...}` references in the static S3 identity file from
the container environment. The checked-in Secret manifests contain only those
references, never credential values.

The steady-state `registry-breg` identity has exactly these actions:

- `Read:registry-breg-attachments`
- `Write:registry-breg-attachments`

Those are sufficient for BReg v0.46.0 to probe bucket versioning, put an exact
object, read it back for integrity verification, and delete it. It cannot
create or delete a bucket, list other buckets, or reach an object in another
bucket. Keep the bucket dedicated to this BReg deployment.

Bucket creation uses a separate, short-lived bootstrap identity with only
`Admin:registry-breg-attachments`. It exists for the first bucket creation,
then is removed from the S3 configuration and its Kubernetes Secret is
deleted. Do not give BReg the bootstrap credential.

Prepare four owner-only files outside the checkout, one value per file, without
a trailing newline. Kubernetes preserves file bytes in the Secret, and a
newline becomes part of the S3 credential when the chart injects it as an
environment variable.

```text
/absolute/private/seaweedfs-secrets/app-access-key-id
/absolute/private/seaweedfs-secrets/app-secret-access-key
/absolute/private/seaweedfs-secrets/bootstrap-access-key-id
/absolute/private/seaweedfs-secrets/bootstrap-secret-access-key
```

Generate them with the institution's secret manager. The following commands
read the files and do not print their values:

```bash
kubectl create namespace registry-storage
kubectl -n registry-storage create secret generic registry-breg-s3 \
  --from-file=access-key-id=/absolute/private/seaweedfs-secrets/app-access-key-id \
  --from-file=secret-access-key=/absolute/private/seaweedfs-secrets/app-secret-access-key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n registry-storage create secret generic registry-seaweedfs-bootstrap \
  --from-file=access-key-id=/absolute/private/seaweedfs-secrets/bootstrap-access-key-id \
  --from-file=secret-access-key=/absolute/private/seaweedfs-secrets/bootstrap-secret-access-key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n registry-storage apply \
  -f deploy/examples/seaweedfs/s3-config-bootstrap-secret.yaml
```

`values.reference.yaml` admits only the chart's own workload traffic. The
stable HTTPS overlay below admits Traefik to S3; BReg reaches only that TLS
endpoint. The S3 Service remains `ClusterIP`.

## Install and create the bucket

Install once with the bootstrap overlay:

```bash
helm install registry-seaweedfs \
  /absolute/private/seaweedfs-chart/seaweedfs-4.53.0.tgz \
  --namespace registry-storage \
  --values deploy/examples/seaweedfs/values.reference.yaml \
  --values deploy/examples/seaweedfs/values.bootstrap.yaml \
  --wait --timeout 10m
kubectl -n registry-storage rollout status deployment/registry-seaweedfs-s3 \
  --timeout=5m
```

In a private scratch directory, prepare a curl config whose `user` value is
`<bootstrap-access-key-id>:<bootstrap-secret-access-key>`, mode `0600`. Start a
loopback-only port-forward in a second terminal, then create only the named
bucket. This operator-only loopback HTTP probe is not the BReg binding:

```bash
kubectl -n registry-storage port-forward \
  service/registry-seaweedfs-s3 18333:8333
curl --config /absolute/private/bootstrap.curl \
  --aws-sigv4 'aws:amz:us-east-1:s3' \
  --fail --silent --show-error \
  -X PUT http://127.0.0.1:18333/registry-breg-attachments
```

Apply the steady-state config, upgrade without the bootstrap overlay, wait for
the S3 rollout, and only then delete the bootstrap Secret:

```bash
kubectl -n registry-storage apply \
  -f deploy/examples/seaweedfs/s3-config-secret.yaml
helm upgrade registry-seaweedfs \
  /absolute/private/seaweedfs-chart/seaweedfs-4.53.0.tgz \
  --namespace registry-storage \
  --values deploy/examples/seaweedfs/values.reference.yaml \
  --wait --timeout 10m
kubectl -n registry-storage rollout status deployment/registry-seaweedfs-s3 \
  --timeout=5m
kubectl -n registry-storage delete secret registry-seaweedfs-bootstrap
```

Retest the old bootstrap credential through the loopback port-forward. It must
now receive `AccessDenied`. Treat an accepted request as a failed rotation.

SeaweedFS 4.53 protects the IAM gRPC handlers even without mTLS, and this
profile also sets `jwt.filer_signing.key` through the chart's
`filerWrite: true` switch for authenticated cross-pod IAM propagation. This is
important because older default S3 gRPC deployments were exposed to the
[critical IAM injection issue](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-5fx4-c9qp-36jc).

## BReg v0.46.0 binding

Mount the two application credential files and exact issuing CA bundle into
BReg's secret root with these names:

```text
s3-access-key-id
s3-secret-access-key
s3-ca.pem
```

There is one supported BReg binding: merge
`breg-attachment-storage.tls.yaml` into the BReg runtime file and replace the
example hostname only before the first activation. The example is the exact
v0.46.0 `attachmentStorage` shape. BReg rejects non-loopback HTTP, including a
plain Kubernetes Service DNS URL. Cluster-local BReg pods must therefore use
the same stable HTTPS hostname as every other caller. The certificate leaf
must contain the exact SAN `DNS:storage.registry.example.gov`, and `s3-ca.pem`
must contain the exact issuing CA bundle selected by `caBundleRef`.

BReg checks `GET ?versioning` at startup and verifies every write by reading
the bytes back. The stable hostname must resolve to the current SeaweedFS TLS
endpoint from the BReg namespace. Split-horizon DNS may keep that route inside
the cluster, but must not change the configured URL or certificate identity.

Object versioning must remain disabled. SeaweedFS `Enabled` or `Suspended`
versioning is refused because deleting an attachment must not leave a
recoverable older object.

### Stable HTTPS at the existing K3s edge

Use the chart's standard S3 Ingress with the existing K3s Traefik controller
for both cluster-local and external callers. TLS terminates at that Ingress;
its backend remains the NetworkPolicy-isolated ClusterIP service. Create the
TLS Secret from an institution-controlled leaf whose SAN is the stable
hostname, then add a private values overlay like this:

```yaml
s3:
  ingress:
    enabled: true
    className: traefik
    host: storage.registry.example.gov
    tls:
      - secretName: registry-seaweedfs-s3-tls
        hosts: [storage.registry.example.gov]
networkPolicy:
  extraIngress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: traefik
      ports:
        - protocol: TCP
          port: 8333
```

The Ingress host, certificate SAN, BReg URL, and DNS name must remain the same
identity. `caBundleRef` keeps BReg on verified HTTPS. Rotate credentials,
certificate, and CA bundle in place when needed, but never replace verified
TLS with `dangerAcceptInvalidCertificates` or a host-wide trust bypass.

Verify the exact issuing CA and hostname before mounting the files or changing
the Ingress:

```bash
openssl verify -CAfile /absolute/private/s3-ca.pem \
  -verify_hostname storage.registry.example.gov \
  /absolute/private/registry-seaweedfs-s3-tls.crt
```

## Qualification

The fast local check runs the exact pinned multi-architecture image on OrbStack,
creates the dedicated bucket through the bootstrap identity, proves the app
identity can probe versioning and put, read, and delete one object, then proves
it cannot create another bucket:

```bash
deploy/examples/seaweedfs/qualify-s3.sh
```

Set `RUN_BREG_S3_TESTS=1` to keep that same server alive while running the two
maintained Rust targets used by BReg's S3 proof:

```bash
RUN_BREG_S3_TESTS=1 deploy/examples/seaweedfs/qualify-s3.sh
```

The maintained BReg proof reaches the real
`registry-platform-objectstore` adapter and BReg attachment namespace. Run it
from the Registry Stack root when Rust test capacity is available:

```bash
products/breg/scripts/test-attachment-s3.sh
```

That script owns a disposable loopback SeaweedFS container and synthetic
credentials. It proves BReg storage semantics, not this Kubernetes chart.
Keep the chart render, local S3 qualification, and BReg proof as distinct
evidence.

## Backup

A valid backup contains all of the following from the same quiesced point:

- the master PVC, including topology and volume assignment state;
- the filer PVC, including file metadata and S3 bucket state;
- the volume PVC, containing attachment bytes and indexes;
- `registry-seaweedfs-s3-config` and the `registry-breg-s3` credential input;
- any S3 Ingress TLS leaf, key, and issuing CA;
- this exact chart archive, lock, values, and the BReg runtime binding;
- the BReg database backup from the same application maintenance window;
- the exact `attachmentStorage.url`, bucket, and region, plus BReg's logical
  `databaseId` and `registryId` for every retained attachment scope.

Do not snapshot the three PVCs independently while writes continue. Stop BReg
attachment writers first, wait for in-flight requests to finish, scale the S3
Deployment to zero, then the filer, volume, and master StatefulSets to zero.
Confirm every pod is gone before taking CSI VolumeSnapshots or the storage
provider's equivalent crash-consistent copies. Record the exact PVC names,
snapshot identifiers, chart digest, image digest, namespace, bucket, URL,
region, `databaseId`, `registryId`, and time. Resume master, volume, filer, S3,
then BReg, and perform a fresh write-read-delete check.

BReg's attachment binding digest commits to the bucket URL, region, and the
hash of the logical scope `["databaseId", "registryId"]`. Recovery must use the
same exact `attachmentStorage.url`, bucket, and the same exact `region`, then
restore the same `databaseId` and activate the same `registryId`. Credentials,
the certificate, and `caBundleRef` may rotate without changing that binding.

An ordinary BReg database backup without these PVCs is incomplete. The database
holds attachment references and state, not the attachment bytes.

## Recovery exercise

Exercise restore in a clean namespace, never over the only retained copy:

1. Restore the three PVC snapshots under the exact names recorded at backup.
2. Restore the steady-state S3 config, application credential, and TLS inputs.
   Do not restore the revoked bootstrap identity or Secret.
3. Install the exact verified chart with `values.reference.yaml`, adjusted only
   for the clean namespace and restored claim names if the storage provider
   requires explicit existing claims. The Kubernetes namespace or backend may
   change behind that stable HTTPS identity; the BReg URL must not change.
4. Wait for master, volume, filer, and S3 readiness in that order, then route
   the unchanged stable hostname to the recovered TLS endpoint. Require the
   leaf SAN and issuing CA bundle to verify that same hostname.
5. Through a loopback port-forward, authenticate as the application identity,
   confirm `GET ?versioning` reports neither `Enabled` nor `Suspended`, and read
   a pre-backup canary object by its exact key and checksum.
6. Restore BReg from its matching backup with the original `databaseId`,
   activate the original `registryId`, and keep the recorded URL, bucket, and
   region in its runtime. Require the computed attachment binding digest to
   match the recorded digest, BReg readiness, and one authorized attachment
   download. A mismatch fails the exercise; it is not a new recovery binding.
7. Create, read, and delete a new synthetic attachment. Separately prove the
   revoked bootstrap credential and a second bucket remain denied.

PVC readiness proves only that Kubernetes mounted storage. The canary checksum
proves retained bytes, BReg download proves reference continuity, and the new
write-read-delete proves current operation. Preserve those as separate recovery
evidence.
