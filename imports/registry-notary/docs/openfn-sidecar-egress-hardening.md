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

## Option 1 — Kubernetes NetworkPolicy

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
    - Egress
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

    # Allow Notary-to-sidecar traffic on the sidecar listener port (9191).
    # The sidecar should only be reachable from the Notary pod, not from the
    # public network. Adjust the podSelector or namespaceSelector to match
    # your Notary pod labels.
    - ports:
        - protocol: TCP
          port: 9191
      to:
        - podSelector:
            matchLabels:
              app: registry-notary   # adjust to match your Notary pod labels
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
- After applying the policy, verify it with a test pod in the same namespace:
  `kubectl run -it --rm test --image=curlimages/curl -- curl -s --max-time 3 http://169.254.169.254/` should time out or be refused.
- The `policyTypes: [Egress]` declaration without a matching `podSelector`
  on the `from` side means ingress is **not** restricted by this policy. Apply
  a separate ingress `NetworkPolicy` to ensure the sidecar is reachable only
  from the Notary pod.

### Minimal deny-only variant

If you cannot enumerate all legitimate egress CIDRs but need to block the
highest-risk destinations immediately, apply a deny-only policy targeting only
the metadata and RFC 1918 ranges:

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
    - ports:
        - protocol: TCP
          port: 9191
```

This variant allows all public HTTPS egress except the blocked ranges and should
be tightened to known upstream CIDRs before production use.

## Option 2 — Egress proxy (environments without CNI enforcement)

If your cluster does not use a CNI that enforces `NetworkPolicy` egress rules,
route all worker outbound HTTP through an allow-listing forward proxy.

1. Run an allow-listing HTTP/HTTPS forward proxy (for example Squid with an
   `acl` dstdomain allowlist, or an OPA-based policy proxy) as a sidecar
   container or a shared cluster service.
2. Set the `HTTP_PROXY` and `HTTPS_PROXY` environment variables on the sidecar
   pod to point to the proxy. The Node.js `@openfn/runtime` and `@openfn/language-http`
   packages respect standard Node.js proxy environment variables.
3. Configure the proxy to allow only the specific hostnames of your source
   registries and deny everything else, including by-IP requests to
   `169.254.169.254` and RFC 1918 addresses.
4. Confirm the proxy rejects requests to `http://169.254.169.254/` and to a
   private IP (for example `http://10.0.0.1/`) before routing production traffic
   through it.

The egress-proxy approach works even on clusters where the CNI does not enforce
`NetworkPolicy`, but it requires operating and monitoring an additional
component.

## Verification checklist

Before routing production OpenFn source traffic through the sidecar, confirm:

- [ ] A CNI that enforces `NetworkPolicy` egress is installed and active, **or**
  an allow-listing egress proxy is configured and tested.
- [ ] A NetworkPolicy or proxy rule explicitly blocks `169.254.169.254/32` and
  `169.254.0.0/16`.
- [ ] RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and
  loopback (`127.0.0.0/8`) are blocked at the network layer for the sidecar pod.
- [ ] The sidecar pod cannot reach `http://169.254.169.254/` (test before go-live).
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
