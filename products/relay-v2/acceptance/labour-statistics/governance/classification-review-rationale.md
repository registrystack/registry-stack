# Classification review rationale

The public dataflow reads a reviewed pre-aggregated non-personal view. The
authority-confined dataflow treats its row-binding column and processing as
internal, requires a verified purpose and authority claim, and remains
non-cacheable for authenticated callers. SDMX identity and wire-format
selection do not alter either dataset's single fixed access rule.
