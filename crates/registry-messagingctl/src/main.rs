// SPDX-License-Identifier: Apache-2.0

//! The `messagingctl` binary entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    registry_messagingctl::main_entry()
}
