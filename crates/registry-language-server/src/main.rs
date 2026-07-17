// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() {
    registry_language_server::run_stdio().await;
}
