// SPDX-License-Identifier: Apache-2.0

use clap::{error::ErrorKind, Parser};
use registry_cli_api::ApiArgs;

#[derive(Parser)]
struct Harness {
    #[command(flatten)]
    api: ApiArgs,
}

#[test]
fn client_flag_is_refused() {
    let error = Harness::try_parse_from(["api", "v1/status", "--client", "operator"])
        .err()
        .expect("--client is not an api argument");
    assert_eq!(error.kind(), ErrorKind::UnknownArgument);
}
