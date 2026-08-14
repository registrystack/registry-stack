# Discovery authoring fixture

This is a complete offline-checkable catalog authoring project. From the
repository root, run:

```sh
cargo run --locked -p registry-discoveryctl -- check \
  --project products/discovery/fixtures/project
```

The two `.invalid` description URLs are deliberate. `check` performs no
network access. The product HTTP journey replaces them with bounded local
providers, builds the index, and drives the real runtime and client.
