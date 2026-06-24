// SPDX-License-Identifier: Apache-2.0
//! Registry Notary CEL worker process.

fn main() {
    registry_notary_server::cel_worker::run_stdio_worker();
}
