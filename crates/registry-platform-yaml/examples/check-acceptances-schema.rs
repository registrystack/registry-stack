// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: check-acceptances-schema --output <directory>".into());
    }
    let output = arguments.next().ok_or("--output requires a directory")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let directory = std::path::Path::new(&output);
    std::fs::create_dir_all(directory)?;
    let schema = registry_platform_yaml::check_acceptances_schema();
    let mut text = serde_json::to_string_pretty(&schema)?;
    text.push('\n');
    std::fs::write(directory.join("check-acceptances.schema.json"), text)?;
    Ok(())
}
