# OpenFn Sidecar Egress Hardening

> **Page type:** Runbook · **Product:** Registry Notary · **Layer:** operations · **Audience:** operator, security reviewer

This guide covers network-layer egress hardening for deployments that use the
source adapter sidecar with OpenFn sources. It documents the residual gap
between in-process SSRF defenses (which cover the `http_json`, `http_flow`, and
`fhir` engine paths) and the Node.js OpenFn engine path, and gives operators
concrete controls to close that gap.

## Threat model

The source adapter sidecar runs two distinct outbound HTTP paths.

**The Rust-managed paths** (`http_json`, `http_flow`, `fhir`) enforce SSRF
defenses in-process at every request. Specifically:

- `http_json` sources must declare a non-empty `allowed_base_urls`; the config
  validator rejects empty lists (`sidecar.rs:1991-1994`).
- Every request URL is gated by `ensure_allowed_base_url` before a connection
  is opened (`sidecar.rs:4925`, `sidecar.rs:2315`, `sidecar.rs:2492`).
- DNS-resolved IPs are checked by `ensure_ip_allowed`, which calls
  `is_cloud_metadata_ip` and `is_private_or_link_local_ip`
  (`sidecar.rs:5082-5101`, `sidecar.rs:5118-5133`).
- `is_cloud_metadata_ip` blocks `169.254.169.254` (IPv4) and `fd00:ec2::254`
  (IPv6) as well as their IPv4-mapped IPv6 forms (`sidecar.rs:5118-5129`).
- `is_private_or_link_local_ip` blocks RFC 1918 ranges, link-local, and
  unspecified addresses.
- No-redirect handling prevents redirect-based bypass.

These defenses mean the `http_json`, `http_flow`, and `fhir` paths are not
affected by this finding.

**The Node.js OpenFn engine path** executes compiled OpenFn workflow expressions
through the `@openfn/runtime` engine (`openfn_worker.mjs`). Outbound HTTP made
by an OpenFn adaptor (for example `@openfn/language-http`) is issued by the
Node.js process and is never observed by the Rust `FetchUrlPolicy`. There is no
in-process IP or URL filter on that path.

**Severity:** LOW. Exploitation requires malicious code in a TUF-signed OpenFn
workflow expression. The TUF signing and signer-threshold controls documented in
[Governed configuration](../../registry-platform/docs/governed-configuration.md)
are a substantial prerequisite barrier. This is a defense-in-depth gap, not a
standalone vulnerability. However, if an adversary can introduce malicious
expressions into the signed bundle, network-layer controls are the last line of
defense against SSRF or data exfiltration from the worker pod.

## Required operator action

Network-layer egress controls for the sidecar worker pod are **required**
when:

- The sidecar is deployed with any OpenFn sources (engine: `openfn`).
- Workflow expressions are signed by a key set whose compromise or coercion
  could not be immediately detected.
- The sidecar pod has network access to internal services, cloud metadata
  endpoints, or any infrastructure the Node.js process should not be able to
  reach.

Egress controls are your only defense once signed workflow code is running.
Treating them as optional in production deployments weakens the defense-in-depth
posture documented in `sidecar-trust-and-secrets.md`.

## Option 1: Kubernetes NetworkPolicy

Apply the following NetworkPolicy to the namespace and pods that run the
sidecar. This policy denies egress to the cloud metadata IP, RFC 1918 ranges,
and link-local ranges, while allowing only the DNS, HTTPS, and internal pod
traffic the sidecar legitimately needs.

**Requirements:**
- A CNI plugin that enforces `NetworkPolicy` egress rules. Calico and Cilium
  both enforce egress NetworkPolicies. The default `kubenet` CNI and kubeproxy
  do not enforce NetworkPolicy egress rules; verify your CNI before relying on
  this control.
- Kubernetes 1.21 or later for stable `NetworkPolicy` API.
- No broader egress-allowing `NetworkPolicy` selects the same sidecar pods.
  Kubernetes NetworkPolicies are additive; a second policy that allows all
  egress to the selected pods can bypass the narrower example below.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: registry-notary-sidecar-egress
  namespace: <your-namespace>
spec:
  podSelector:
    matchLabels:
      app: registry-notary-sidecar   # adjust to match your pod labels
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow Notary-to-sidecar traffic on the sidecar listener port (9191).
    # The sidecar should only be reachable from the Notary pod, not from the
    # public network. This is *inbound* traffic to the sidecar, so it belongs
    # under `ingress`. Adjust the podSelector or namespaceSelector to match your
    # Notary pod labels.
    - from:
        - podSelector:
            matchLabels:
              app: registry-notary   # adjust to match your Notary pod labels
      ports:
        - protocol: TCP
          port: 9191
  egress:
    # Allow DNS (UDP and TCP on port 53).
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

    # Allow HTTPS to the internet (public source registries).
    # Restrict ipBlock to the specific CIDR ranges of your upstream registries
    # if they are known. The example below permits all non-blocked public egress;
    # tighten it to named CIDRs in production.
    - ports:
        - protocol: TCP
          port: 443
      to:
        # Block cloud metadata IP (AWS/GCP/Azure/DigitalOcean/Oracle/Alibaba).
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # Cloud metadata endpoints (IPv4).
              - 169.254.169.254/32
              # Link-local range (also covers 169.254.169.254/32 via the broader block,
              # listed here explicitly for clarity).
              - 169.254.0.0/16
              # Loopback.
              - 127.0.0.0/8
              # RFC 1918 private ranges.
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
```

**Notes:**

- IPv6 metadata address `fd00:ec2::254` (the address blocked by
  `is_cloud_metadata_ip` in the Rust path) is not covered by an IPv4
  `NetworkPolicy`. If your cluster uses IPv6 or dual-stack networking, add a
  matching `NetworkPolicy` for the IPv6 address family, or use Cilium
  `CiliumNetworkPolicy` which supports both address families in a single policy.
- The `except` blocks above match the IP ranges that the Rust `ensure_ip_allowed`
  helper blocks for the in-process paths. The intent is consistency: the
  network layer enforces the same denied set that the Rust code enforces for
  `http_json`, `http_flow`, and `fhir`.
- After applying the policy, verify it from a pod selected by the same
  `podSelector`, not from an unlabeled ad hoc pod. For example:
  `kubectl run -n <your-namespace> registry-notary-sidecar-egress-test --rm -it --restart=Never --image=curlimages/curl --labels=app=registry-notary-sidecar --command -- curl -sS --max-time 3 http://169.254.169.254/`
  should time out or be refused. You can also exec into the actual sidecar pod
  or attach a disposable debug container to it.
- This policy restricts **both** directions (`policyTypes: [Ingress, Egress]`):
  the `ingress` rule limits inbound connections on port 9191 to the Notary pod,
  and the `egress` rules constrain outbound traffic. Selecting a pod under a
  `policyTypes` direction switches that direction to default-deny for the pod.
  Because policies are additive, only the union of all policies selecting the pod
  is allowed. Audit every `NetworkPolicy` that selects the sidecar labels before
  treating the example as an effective block.

### Minimal allow-list variant

If you cannot enumerate all legitimate egress CIDRs but need to block the
highest-risk destinations immediately, apply this egress allow-list variant
targeting the metadata and RFC 1918 ranges:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: registry-notary-sidecar-deny-metadata
  namespace: <your-namespace>
spec:
  podSelector:
    matchLabels:
      app: registry-notary-sidecar
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - ports:
        - protocol: TCP
          port: 443
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
              - 169.254.0.0/16
              - 127.0.0.0/8
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
```

This variant is not an explicit deny rule. It selects the sidecar pods, puts
their egress into default-deny, then allows DNS and public HTTPS except the
listed ranges. It is effective only when no other `NetworkPolicy` selecting the
same pods allows the blocked ranges. Tighten it to known upstream CIDRs before
production use.

## Option 2: Egress proxy (environments without CNI enforcement)

If your cluster does not use a CNI that enforces `NetworkPolicy` egress rules,
route all worker outbound HTTP through an allow-listing proxy or egress gateway
that is enforced at the network layer.

Do **not** rely on `HTTP_PROXY` / `HTTPS_PROXY` environment variables alone for
the current OpenFn worker image. The pinned OpenFn `@openfn/language-http` path
uses Undici dispatchers inside the adaptor stack, and the sidecar worker does
not install an `EnvHttpProxyAgent` or equivalent proxy dispatcher. Environment
variables are acceptable only after you have tested the exact worker/adaptor
traffic and confirmed it cannot bypass the proxy.

1. Run an allow-listing HTTP/HTTPS proxy or egress gateway, for example Squid
   with a destination-domain allowlist, an OPA-based policy proxy, a service-mesh
   egress gateway, or a transparent sidecar proxy with traffic redirection.
2. Enforce routing so all TCP egress from the sidecar pod to HTTP/HTTPS
   destinations must go through that proxy or gateway. Use mesh sidecar
   interception, host firewall rules, cloud security groups, or another
   infrastructure control that prevents direct outbound connections from the
   worker process.
3. Configure the proxy to allow only the specific hostnames of your source
   registries and deny everything else, including by-IP requests to
   `169.254.169.254` and RFC 1918 addresses.
4. Confirm the proxy rejects requests to `http://169.254.169.254/` and to a
   private IP (for example `http://10.0.0.1/`) before routing production traffic
   through it. The test must originate from the actual sidecar pod or an
   equivalently selected pod, and proxy logs should show the attempted request.

The egress-proxy approach works only when direct sidecar egress is blocked or
transparently captured. It is useful on clusters where the CNI does not enforce
`NetworkPolicy`, but it requires operating and monitoring an additional
component and proving that the OpenFn worker cannot bypass it.

## Verification checklist

Before routing production OpenFn source traffic through the sidecar, confirm:

- [ ] A CNI that enforces `NetworkPolicy` egress is installed and active, **or**
  an enforced allow-listing egress proxy is configured and tested with the
  actual sidecar pod.
- [ ] Every `NetworkPolicy` selecting the sidecar pod labels has been reviewed;
  no broader policy re-allows metadata, loopback, link-local, or RFC 1918
  egress.
- [ ] A NetworkPolicy or proxy rule explicitly blocks `169.254.169.254/32` and
  `169.254.0.0/16`.
- [ ] RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and
  loopback (`127.0.0.0/8`) are blocked at the network layer for the sidecar pod.
- [ ] The sidecar pod, or a test pod with the same selected labels, cannot reach
  `http://169.254.169.254/` (test before go-live).
- [ ] If using a proxy or gateway, direct outbound HTTP/HTTPS from the sidecar is
  blocked or transparently captured, and proxy logs show the OpenFn worker's test
  requests.
- [ ] IPv6 metadata address `fd00:ec2::254` is blocked if the cluster uses IPv6.
- [ ] Ingress to the sidecar is restricted so only the Notary pod can connect on
  port 9191.

## Relationship to other controls

This guide addresses only the network-layer gap for the **OpenFn engine path**.
The following related controls are covered elsewhere and are not replaced by this
guide:

- In-process SSRF defenses for `http_json`, `http_flow`, and `fhir`:
  `ensure_allowed_base_url`, `ensure_ip_allowed`, and the
  `allow_insecure_localhost` / `allow_insecure_private_network` gates. These are
  always active for those source types and are not affected by this finding.
- Configuration integrity (TUF signing, signer thresholds, anti-rollback):
  [Governed configuration](../../registry-platform/docs/governed-configuration.md).
- Sidecar identity pinning and assurance verification: `expected_sidecar` in
  the source connection config. See
  [Sidecar trust and secret handling](sidecar-trust-and-secrets.md).
- General network boundary and TLS controls:
  [Deployment hardening runbook](deployment-hardening-runbook.md).
- Image provenance and signing: [Security assurance](security-assurance.md).
