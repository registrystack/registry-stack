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

A profile chooses one of two base engines. A deadline is checked only between
operations, so neither base carries a native function that reads the clock,
sleeps, or never returns. `Deterministic` is Rhai's standard language surface
without the language-core package (`sleep`, `exit`, `take`, `tag`, `set_tag`,
`parse_json`, `get_fn_metadata_list`) and the time package (`timestamp`,
`elapsed`, instant arithmetic). String `pad` is replaced by a version that
refuses an empty padding string, and string `replace` by one that works out
the size of its result and refuses one over the string bound before building
it. The `curry` keyword is disabled, because Rhai does not count data curried
into a function pointer against the size bounds and every copy of the pointer
copies that data; a script that uses it fails to compile. A script that calls
a left-out function fails at run time with a function-not-found error. `Raw`
carries no packages at all, for a product that registers every callable itself.

The deterministic base has no clock, no sleep, and no ambient input: a script
sees only its arguments and what the product registers, so the same call gives
the same result on the same host. Floating-point transcendental functions
(`sin`, `exp`, `ln`, and the like) use the host's maths library, so their last
digits can differ across platforms.

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

## Rhai dependency review

The workspace selects Rhai's `compact_str` feature. This keeps owned-string
conversion, `ImmutableString`, identifiers, and object-map keys off
`smartstring`'s reported unsound conversion path. The unit test
`rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips` names the
selected key type and exercises an owned Unicode string through a compiled
script, so silently returning to Rhai's default backend fails visibly.

Rhai 1.27 still declares `smartstring` as an unconditional dependency. Cargo
therefore resolves and builds it even though Rhai's selected string code uses
`compact_str`; the advisory remains in the dependency graph until upstream
makes `smartstring` optional or removes it. The workspace advisory exception
records that narrower residual rather than claiming the package is absent.

The upgrade does not raise any product's operation limit. Rhai 1.27 now counts
script callbacks invoked by native functions instead of discarding their
operations. The Evidence, BReg, Messaging, and Coordinator hosts reviewed for
this update register no native helper that invokes a script callback, and the
maintained Rhai files use no callback-based collection method. A separately
governed script that does use one may reach its existing limit sooner and
should be evaluated before promotion. The existing platform unit and consumer
test suites own these checks; this review adds no separate blocking CI gate.

A Rhai upgrade must also recheck the deterministic base. The unit test
`deterministic_base_engine_leaves_out_the_language_core_and_time_packages`
pins exactly which function names the base leaves out of Rhai's standard
engine, so a function added to a left-out package, or a package added to the
standard engine, fails it. A function added to a kept package passes it, so
review every new standard function for clock reads, sleeping, unbounded loops,
or allocation before the engine's size checks, and confirm the `pad` and
`replace` overrides still match the package's signatures.
