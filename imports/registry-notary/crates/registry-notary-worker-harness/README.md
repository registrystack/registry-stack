# Registry Notary Worker Harness

Generic hardened JSON-line worker process pool used by Registry Notary worker
integrations. The harness owns process spawning, environment scrubbing,
resource limits, bounded request and response IO, timeout kill, replacement,
and pool snapshots. Protocol semantics stay with the caller.
