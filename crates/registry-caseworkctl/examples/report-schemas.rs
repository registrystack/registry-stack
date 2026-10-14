// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "schema")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: report-schemas --output <directory>".into());
    }
    let output = std::path::PathBuf::from(args.next().ok_or("missing output directory")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    std::fs::create_dir_all(&output)?;
    for (name, bytes) in registry_caseworkctl::schema::report_documents()? {
        std::fs::write(output.join(name), bytes)?;
    }
    Ok(())
}
#[cfg(not(feature = "schema"))]
fn main() {
    eprintln!("report-schemas requires schema feature");
    std::process::exit(2);
}
