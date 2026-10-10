// SPDX-License-Identifier: Apache-2.0
#[tokio::main]
async fn main() -> std::process::ExitCode {
    registry_coordinator::service::run().await
}
