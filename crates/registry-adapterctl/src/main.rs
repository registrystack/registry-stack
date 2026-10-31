// SPDX-License-Identifier: Apache-2.0

//! The `adapterctl` binary entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    registry_adapterctl::main_entry()
}
