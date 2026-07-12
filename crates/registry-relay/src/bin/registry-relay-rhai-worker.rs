// SPDX-License-Identifier: Apache-2.0
//! Minimal one-shot process entry point for Relay's isolated Rhai worker.

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    if registry_relay::rhai_worker::is_worker_invocation(env::args_os()) {
        registry_relay::rhai_worker::run_worker_stdio()
    } else {
        ExitCode::FAILURE
    }
}
