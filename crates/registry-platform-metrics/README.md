# Registry Platform Metrics

`registry-platform-metrics` writes the Prometheus text exposition format 0.0.4 and holds the counter and histogram state behind it, with label sets that cannot grow with traffic. It depends on nothing outside `std`.

- `Exposition` writes `# HELP` and `# TYPE` headers, samples, and histograms. It validates metric and label names, escapes label values (backslash, double quote, newline) and HELP text (backslash, newline), and writes samples in the order given, so a product keeps its scrape bytes. Integers print as integers; floats print in Rust's shortest form without an exponent (`1`, `0.005`); non-finite values print as `NaN`, `+Inf`, `-Inf`. `CONTENT_TYPE` is the response media type.
- `CounterVec` and `HistogramVec` hold state over a `LabelSpace`. A closed space (`closed`, `closed_zero_filled`) declares every series in render order; anything else is refused. A bounded space (`bounded`) admits up to a fixed number of series (at most 10,000) and renders them in sorted label-value order. Label values longer than 256 bytes, a wrong number of values, and non-finite observations are refused. A refusal never adds a series, is counted in `refused()`, and its error never repeats a label value.

Label values are chosen by the caller from closed vocabularies. Request paths, identifiers, principals, and any personal data are never labels: map them onto a route table or enum first, and let the space refuse what does not map.

The primitive owns format and bounds only. Each product keeps its metric names, help text, bucket choices, sampling at scrape, and the listener that serves `/metrics`.
