# Registry Render native client

Internal binding used by the unified Registry Stack client. HTTP behavior and
validation belong to `registry-render-client`. The public facade accepts an
explicit token or a resource-bound provider and performs one render exchange.

Request validation runs before token acquisition. Provider failures retain the
provider's classification. Transport errors expose their shared kind and
whether an exchange may have completed. No automatic retry is added.
