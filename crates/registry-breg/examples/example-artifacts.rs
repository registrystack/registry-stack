// SPDX-License-Identifier: Apache-2.0
//! Reproduce the canonical BReg examples with the product's artifact generator.
use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
};
use std::{env, fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err(
            "usage: example-artifacts --output DIRECTORY [--project minimal|facility]".into(),
        );
    }
    let output = PathBuf::from(args.next().ok_or("missing output directory")?);
    let selected = match args.next() {
        None => "facility".to_owned(),
        Some(flag) if flag == "--project" => args
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or("--project requires minimal or facility")?,
        _ => return Err("unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let (source, assets): (&[u8], Vec<ModuleAssetSource>) = match selected.as_str() {
        "minimal" => (
            include_bytes!("../../../products/breg/examples/minimal/registry.yaml"),
            Vec::new(),
        ),
        "facility" => (
            include_bytes!("../../../products/breg/examples/facility/registry.yaml"),
            vec![ModuleAssetSource {
                module: None,
                path: "plans/correct-address.rhai".to_owned(),
                bytes: include_bytes!(
                    "../../../products/breg/examples/facility/plans/correct-address.rhai"
                )
                .to_vec(),
            }],
        ),
        _ => return Err("--project requires minimal or facility".into()),
    };
    let project = parse_project_yaml(source)?;
    let model = compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)?;
    fs::create_dir_all(&output)?;
    for artifact in model.artifacts().entries().values() {
        let path = output.join(&artifact.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &artifact.bytes)?;
    }
    Ok(())
}
