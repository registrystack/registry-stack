// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

#[test]
fn admin_handlers_use_required_scoped_extractors() {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/admin.rs"))
        .expect("admin.rs reads");

    assert!(
        !source.contains("principal: Option<Extension<Principal>>"),
        "admin route handlers must not accept optional principals directly"
    );
    assert!(
        source.contains("struct AdminPrincipal") && source.contains("struct OpsReadPrincipal"),
        "admin routes must keep required auth extraction explicit in handler signatures"
    );
    assert!(
        source.contains("async fn reload_all(runtime: RuntimeSnapshot, _admin: AdminPrincipal)")
            && source.contains("async fn reload_table(")
            && source.contains("_admin: AdminPrincipal")
            && source.contains(
                "async fn capabilities(runtime: RuntimeSnapshot, _ops: OpsReadPrincipal)"
            )
            && source.contains("_ops: OpsReadPrincipal"),
        "admin routes must carry explicit scoped extractors in their route surface"
    );
}
