# Publish a workspace endpoint

This example adds a public intake-status endpoint to a Studio workspace. It runs a small Python image. A partner can use Node.js or any other runtime that listens on `PORT`, serves `PUBLIC_PATH` and runs as UID/GID 65532 with a read-only root filesystem.

## Declare the path in the workspace

Copy [endpoints.json](endpoints.json) to `workspace/native/deployment/endpoints.json`. Add this entry to the workspace's existing `nativeParts` list.

```yaml
- id: deployment-endpoints
  file: native/deployment/endpoints.json
  mapping:
    product: deployment
    targetFile: deployment/endpoints.json
```

Save and publish the workspace. Publish copies the Helm values fragment and hashes it in `workspace/generated.json`. Declare one distinct exact path below `/extensions/` per endpoint. The fragment declares the endpoint ID and path.

## Bind and deploy

Build the example image and publish it to the registry you use for deployment. Record the OCI digest reported by your build and verify it against the published image.

```bash
docker buildx build --platform linux/amd64,linux/arm64 --push \
  --tag registry.example.org/nursing/intake-status:1 deploy/examples/intake-status
```

Prepare a Restricted namespace for extensions and a trusted HTTPS certificate for their own hostname. The separate hostname isolates extension responses from the App Kit browser origin and its session cookies. Put `status.json` in a named ConfigMap in the extension namespace and place the certificate and key in its TLS Secret.

Add the `extensions` object to the same operator bindings you pass to `workspace_values.py`. Set the real ingress class, namespace and Pod selector. Supply the image by digest and the ConfigMap by name.
For a private image registry, set `extensions.imagePullSecrets` to a list of named image-pull Secrets in the extension namespace.

```json
{
  "extensions": {
    "namespace": "nursing-extensions",
    "publicHost": "extensions.nursing.example.org",
    "ingressClassName": "traefik",
    "ingressNamespace": "kube-system",
    "ingressPodLabels": {"app.kubernetes.io/name": "traefik"},
    "tlsSecretName": "extensions-tls",
    "endpoints": {
      "intake-status": {
        "image": "registry.example.org/nursing/intake-status@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "port": 8080,
        "configMapName": "intake-status-v1"
      }
    }
  }
}
```

Run the workspace command with its normal product bindings and source hash. Keep both outputs with the deployment receipt.

```bash
python3 deploy/workspace_values.py --workspace-root /srv/nursing/published \
  --bindings /srv/nursing/operator-bindings.json --product breg \
  --extension-values /srv/nursing/extension-values.json > /srv/nursing/stack-values.json

helm upgrade --install nursing-extensions deploy/helm/registry-stack \
  --kube-context default --namespace nursing-extensions \
  --values /srv/nursing/extension-values.json --wait

curl --fail https://extensions.nursing.example.org/extensions/intake-status
```

The exact path serves the public status from the ConfigMap. Confirm an undeclared route returns 404 and plain HTTP redirects to HTTPS or is refused. The default policy admits ingress controller traffic and denies egress.

For a private Registry Stack API call, register a separate service client in the institutional issuer and grant only its required product scope, purpose and record boundary. Supply `credentialsSecretName` and the exact destination and port in `egress` for that endpoint. Its credentials are mounted read-only at `/run/registry-extension`. Supply non-secret settings via `/etc/registry-extension`. Use the public product API with verified TLS. Keep database credentials and migration authority out of the extension namespace. The partner owns its image, endpoint authorization and maintenance.
