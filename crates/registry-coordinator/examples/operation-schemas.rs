// SPDX-License-Identifier: Apache-2.0
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: operation-schemas --output <directory>".into());
    }
    let output = args
        .next()
        .ok_or("usage: operation-schemas --output <directory>")?;
    if args.next().is_some() {
        return Err("usage: operation-schemas --output <directory>".into());
    }
    std::fs::create_dir_all(&output)?;
    for (name, text) in registry_coordinator::contracts::generate()? {
        std::fs::write(std::path::Path::new(&output).join(name), text)?;
    }
    Ok(())
}
