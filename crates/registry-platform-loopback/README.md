# Registry Platform Loopback

`registry-platform-loopback` is the one definition of "loopback" for outbound destinations and loopback origins. It depends on nothing outside `std`, so a crate that only needs the rule does not pull in an HTTP server stack.

- `loopback_address`, `loopback_host` and `loopback_literal`. A literal in `127.0.0.0/8`, `::1` or the IPv4-mapped form of `127.0.0.0/8` is loopback, and so is the exact name `localhost` once the connection is pinned to loopback addresses (`LoopbackHost::pinned_by`). `*.localhost`, `localhost.` and a bracketed IPv4 literal such as `[127.0.0.1]` are never loopback.
- A site that accepts the name `localhost` must pin the connection; a site that cannot pin uses `loopback_literal`. Bind sites keep their own, stricter rule.

`registry-platform-httpsec` and `registry-platform-httputil` re-export this crate as `loopback`.
