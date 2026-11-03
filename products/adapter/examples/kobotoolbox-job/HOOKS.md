# KoboToolbox webhook trigger

`job.hook.yaml` and `job-runtime.hook.example.yaml` add a webhook trigger to
the direct KoboToolbox example. Build the job host with the explicit
`job-hook` feature. A build without that feature refuses the hook job.

Configure the KoboToolbox webhook to send `POST` requests to the public HTTPS
URL whose path is `/hooks/kobo-submissions`, using HTTP Basic authentication.
Put the exact username and password in the two files referenced by
`hookIngress.sources.kobo-submissions`, with the file permissions required by
the platform secret provider (mode `0400` or `0600`). Write them without a
trailing newline, for example `printf '%s' "$PASSWORD" > hook-password`; the
host refuses a value that ends with a newline. The Adapter resolves and
captures them at host startup, and `adapter-job check` resolves them too, so a
missing, unsafe or malformed credential is refused with the runtime member and
the secret reference named instead of failing later as a `401`.

The job listener is deliberately loopback-only. In production, an
operator-controlled reverse proxy must terminate TLS, expose only the one
reviewed webhook path, preserve the `Authorization` header, bound request
sizes, header-read and idle timeouts, and connections, rate-limit failed
authentication, and forward to `127.0.0.1:8091`. The host limits only
authenticated requests per source; it does not time out a partly sent request
head or count unauthenticated attempts. Do not expose the
loopback plaintext listener directly or change it to a non-loopback bind.
`development-loopback` and port `0` are only for local development and tests.
When port `0` is selected, the host writes one startup line to standard error
as `adapter.job.hook-listening address=<loopback-address>:<assigned-port>`;
standard output remains reserved for command reports.

The generated authoring schema accepts canonical loopback socket text: any
canonical `127.0.0.0/8` IPv4 address or `[::1]`, followed by an unpadded
decimal port from `0` through `65535`. The shared typed reader parses socket
addresses directly and can normalize equivalent noncanonical IPv6 loopback or
padded port text, but that broader textual grammar is deliberately not
duplicated in the Adapter schema. Use `[::1]` and an unpadded port when
authoring a listener.

Hook paths are slash-separated, nonempty ASCII segments. Each segment uses
only letters, digits, `-`, `.`, `_`, or `~`; `.` and `..` segments are
refused. This keeps the authored path identical through ordinary HTTP clients
and reverse proxies, without percent-decoding or Unicode normalization.

Start the same controlled loop used by the interval-only example:

```sh
adapter-job pass <example-dir>/job.hook.yaml \
  --pack <source-checkout>/products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime <example-dir>/job-runtime.hook.example.yaml \
  --profile <example-dir>/profile.yaml \
  --project <example-dir>/project.yaml \
  --loop
```

An authenticated request starts one pass early when the host is idle. Further
requests join the pending pass. Requests that arrive while a pass runs queue
one follow-up pass, which starts when the running pass ends; however many
arrive, there is only one follow-up. After a stopped pass or a held lease, a
request waits out the error backoff or the lease instead of starting a pass
at once. The request body is read only through
a 1 MiB bounded discard that must finish within 10 seconds, and is never
parsed, stored, logged, forwarded, or used to choose a job, cursor, rescan,
source, or destination. The compiled job and saved store position make every
one of those choices.

On shutdown (`SIGTERM` or `Ctrl+C`), accepted ingress connections have 10
seconds to drain. A client
that leaves a request head or body incomplete cannot hold the process open
after that bound; the host closes the ingress and reports the value-free
`adapter.job.hook-shutdown-timeout` diagnostic.

The interval trigger remains mandatory and continues reconciling the source.
A forged request fails authentication, duplicate requests coalesce, and a
lost request waits for the next interval. These cases can change timing, but
not the set or meaning of source items processed.
