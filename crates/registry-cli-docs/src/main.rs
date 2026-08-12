// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), serde_json::Error> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &registry_cli_docs::catalog())?;
    use std::io::Write as _;
    output.write_all(b"\n").map_err(serde_json::Error::io)
}
