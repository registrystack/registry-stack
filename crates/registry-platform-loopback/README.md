# Registry Platform Loopback

`registry-platform-loopback` is the one definition of "loopback" and "private" for outbound destinations and loopback origins. It depends on nothing outside `std`, so a crate that only needs the rule does not pull in an HTTP server stack.

- `loopback_address`, `loopback_host` and `loopback_literal`. A literal in `127.0.0.0/8`, `::1` or the IPv4-mapped form of `127.0.0.0/8` is loopback, and so is the exact name `localhost` once the connection is pinned to loopback addresses (`LoopbackHost::pinned_by`). `*.localhost`, `localhost.` and a bracketed IPv4 literal such as `[127.0.0.1]` are never loopback.
- `TransportClass` names how an outbound destination is reached: `VerifiedTls`, `LoopbackPlaintext` or `PrivateNetworkPlaintext`.
- `private_address_eligible` and `private_range_eligible` say whether an address, or a whole range, lies inside RFC 1918, RFC 6598 or `fc00::/7`. Eligible does not mean admitted: `100.100.100.200` and `fd00:ec2::254` are cloud metadata addresses inside private space, and a caller refuses a cloud metadata address first.
- `PrivateRange` parses `address/prefix` with a typed `PrivateRangeError`, displays in canonical form, and answers `contains` with IPv4-mapped addresses judged as IPv4. `MAX_PRIVATE_RANGES` (16) is the bound on a list of them.
- A site that accepts the name `localhost` must pin the connection; a site that cannot pin uses `loopback_literal`. Bind sites keep their own, stricter rule.

`registry-platform-httpsec` and `registry-platform-httputil` re-export this crate as `loopback`.
