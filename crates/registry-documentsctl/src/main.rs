// SPDX-License-Identifier: Apache-2.0

//! The `documentsctl` binary entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    registry_documentsctl::main_entry()
}
