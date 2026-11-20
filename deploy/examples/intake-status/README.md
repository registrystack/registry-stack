# Publish an extension endpoint

This example adds a public intake-status endpoint to a Registry Stack installation. It runs a small Python image. A partner can use Node.js or any other runtime that listens on `PORT`, serves `PUBLIC_PATH` and runs as UID/GID 65532 with a read-only root filesystem.

The chart deploys the endpoint as its own release, in its own namespace and on its own HTTPS hostname. You bind the endpoint directly in the chart's `extensions` values. No other tool is needed. The chart's [values schema](../../helm/registry-stack/values.schema.json) is the contract for the fields below.

## Build the image

Build the example image and publish it to the registry you use for deployment. Record the OCI digest reported by your build and check it against the published image.

```bash
docker buildx build --platform linux/amd64,linux/arm64 --push \
  --tag registry.example.org/nursing/intake-status:1 deploy/examples/intake-status
```

The server answers one exact path. It sends no `Server` header that names the runtime or its version.

## Prepare the namespace

Create a namespace that enforces the Restricted Pod Security level. Use a trusted HTTPS certificate for its own hostname. The separate hostname keeps extension responses away from the App Kit browser origin and its session cookies.

Put `status.json` in a named ConfigMap and place the certificate and key in a TLS Secret in that namespace.

```bash
sudo k3s kubectl create namespace nursing-extensions
sudo k3s kubectl label namespace nursing-extensions \
  pod-security.kubernetes.io/enforce=restricted
sudo k3s kubectl -n nursing-extensions create configmap intake-status-v1 \
  --from-file=status.json=deploy/examples/intake-status/status.json
sudo k3s kubectl -n nursing-extensions create secret tls extensions-tls \
  --cert=/absolute/private/extensions.crt --key=/absolute/private/extensions.key
```

For a private image registry, create an image-pull Secret in the same namespace and list it under the chart's `global.imagePullSecrets` (a list of `name` entries).

## Bind the endpoint

Write the `extensions` values. Set the real ingress class, ingress namespace and ingress Pod labels. Declare one distinct exact path below `/extensions/` for each endpoint. Supply the image by digest and the ConfigMap by name.

```yaml
extensions:
  namespace: nursing-extensions
  publicHost: extensions.nursing.example.org
  ingressClassName: traefik
  ingressNamespace: kube-system
  ingressPodLabels:
    app.kubernetes.io/name: traefik
  tlsSecretName: extensions-tls
  endpoints:
    intake-status:
      image: registry.example.org/nursing/intake-status@sha256:0000000000000000000000000000000000000000000000000000000000000000
      path: /extensions/intake-status
      port: 8080
      configMapName: intake-status-v1
```

Replace the all-zero digest with the one you recorded. Save the values as `/srv/nursing/extension-values.yaml` and install the release. Keep the file with the deployment receipt.

```bash
sudo env KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
  /usr/local/lib/registry-stack/helm upgrade --install nursing-extensions \
  deploy/helm/registry-stack --namespace nursing-extensions \
  --values /srv/nursing/extension-values.yaml --wait

curl --fail https://extensions.nursing.example.org/extensions/intake-status
```

The exact path serves the public status from the ConfigMap. Confirm that an undeclared route returns 404. Confirm that plain HTTP redirects to HTTPS or is refused. The default policy admits ingress controller traffic and denies egress.

## Call a private API

For a private Registry Stack API call, register a separate service client in the institutional issuer. Grant it only its required product scope, purpose and record boundary. Supply `credentialsSecretName` and the exact destination and port in `egress` for that endpoint.

The chart mounts the credentials read-only at `/run/registry-extension`. Supply non-secret settings through the ConfigMap, mounted at `/etc/registry-extension`. Use the public product API with verified TLS. Keep database credentials and migration authority out of the extension namespace. The partner owns its image, endpoint authorisation and maintenance.
