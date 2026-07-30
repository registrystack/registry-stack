# Adopter runtime Compose conformance probe

This directory is test evidence for the deployment specification. It is not a
shipped deployment package, a renderer, or a product configuration authority.
The fixtures use non-routable example images and contain no credentials.

`deployment-plan.probe.v1.json` is a complete, value-free serialization of the
current three-lane topology. The Compose fixtures exercise the renderer
constraints that must be proved before renderer implementation:

- the ordinary model excludes preparation and initialization services;
- initialization appears only when its separate model is explicitly selected;
- an unrelated parent service can join the public edge network;
- parent services cannot join the private network or private namespace;
- an included product service cannot be changed by the parent;
- short include syntax and explicit `project_directory` resolve product-owned
  relative paths identically.

Compose permits a parent file to express the three forbidden merges. The
verifier policy rejects the normalized effective model before execution. The
negative fixtures prove those policy rejections; they do not claim that
Compose itself enforces Registry Stack ownership.

Run the current and minimum supported Compose implementations:

```sh
bash release/scripts/check_adopter_compose_contract.sh
```

The checker invokes the real `docker compose config` normalization path with
the committed zero-byte environment file, interpolation disabled, and
environment resolution disabled. Health commands and images are inert,
conformance-only placeholders. The checker does not start them.
