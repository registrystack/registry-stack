# Registry Platform Script

`registry-platform-script` is the product-neutral script execution mechanics
crate shared by Registry Stack products. It owns how reviewed script source is
prepared and run under explicit resource limits; it never decides what a
product's scripts mean.

For Rhai, the crate applies a product-supplied profile (numeric engine limits,
disabled symbols, base engine spelling, anonymous-function policy, source byte
bound) to engine construction, compiles source under an entry-point contract
(exactly one public function at a declared arity, unique function names),
invokes through a fresh scope per call without evaluating top-level statements,
and recognizes engine-level resource exhaustion as a bounded failure category.
Products register their own helpers through a registration closure at engine
construction.

The crate deliberately does not own product policy: entry-point names, helper
inventories, source review, input and output conversion, result validation,
cancellation handling, and every public error stay with the owning product.
Product adapters may name Rhai types directly; there is deliberately no
engine-neutral facade and no requirement to pass values through JSON. Both
engine lifetimes are supported: a product may construct a fresh engine per call
or retain one engine with its registration surface for the process lifetime.

A WASM backend is a sibling module behind the crate's non-default `wasm`
feature: a deterministic Wasmtime configuration (native and Pulley targets),
strict validation of a guest byte ABI at prepare time, one fresh store and
instance per call under fuel, epoch, memory, table, and stack budgets, and
host-generated bounded error strings. The duplicate-JSON-member check that
guards the byte-transfer outcome boundary rides behind the same feature.
Whether and when prepared modules run stays with the owning product; the
feature supplies execution mechanics, not a calling site.
