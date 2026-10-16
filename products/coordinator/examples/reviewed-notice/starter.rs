// SPDX-License-Identifier: Apache-2.0
//! Build the bounded input for one reviewed-notice run from a current BReg record.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use registry_breg_client::{
    BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig, StaticToken,
};
use registry_review_protocol::{canonical_bytes, ContentDigest};
use serde_json::{json, Map, Value};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(about = "Prepare one owner-only reviewed-notice input file")]
struct Arguments {
    #[arg(long)]
    breg_url: Url,
    #[arg(long)]
    record_id: Uuid,
    #[arg(long, default_value = "follow-up-reader")]
    access_profile: String,
    /// Owner-only file containing a bearer token or an Authorization header.
    #[arg(long)]
    token_file: PathBuf,
    /// New owner-only JSON file. Existing paths are refused.
    #[arg(long)]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let token = read_token(&arguments.token_file)?;
    let client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(arguments.breg_url)
            .with_token_provider(Arc::new(StaticToken::new(token)?)),
    )?;
    let options = BRegRecordOptions::default().access_profile(arguments.access_profile)?;
    let response = client
        .get_record("applications", &arguments.record_id.to_string(), &options)
        .await?;
    let record = response.value.data;
    if record.record_identifier != arguments.record_id.to_string()
        || response.value.meta.entity_type_identifier != "application"
    {
        return Err(invalid("BReg returned a different application identity").into());
    }

    let projection = projection(&record.domain_data)?;
    let digest = ContentDigest::for_bytes(&canonical_bytes(&projection)?);
    let input = json!({
        "applicationId": record.record_identifier,
        "applicationRevision": record.revision_identifier,
        "applicationDigest": digest,
    });
    write_private_new(&arguments.output, &serde_json::to_vec_pretty(&input)?)?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "ok": true,
            "command": "reviewed-notice-input",
            "inputFile": arguments.output,
        }))?
    );
    Ok(())
}

fn projection(domain_data: &std::collections::BTreeMap<String, Value>) -> io::Result<Value> {
    let mut projection = Map::new();
    for field in ["applicantName", "benefitProgram", "requestedAmount"] {
        let value = domain_data
            .get(field)
            .ok_or_else(|| invalid("the application omits a reviewed field"))?;
        match (field, value) {
            ("applicantName" | "benefitProgram", Value::String(value))
                if !value.is_empty() && value.len() <= 256 => {}
            ("requestedAmount", Value::Number(value)) if value.as_u64().is_some() => {}
            _ => {
                return Err(invalid(
                    "an application reviewed field has an invalid value",
                ))
            }
        }
        projection.insert(field.to_owned(), value.clone());
    }
    Ok(Value::Object(projection))
}

fn read_token(path: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid("the token path must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                "the token file must not be accessible to group or other",
            ));
        }
    }
    let contents = fs::read_to_string(path)?;
    if contents.len() > 16 * 1024 {
        return Err(invalid("the token file exceeds the accepted bound"));
    }
    let token = contents
        .lines()
        .find_map(|line| line.strip_prefix("Authorization: Bearer "))
        .or_else(|| {
            let trimmed = contents.trim();
            (!trimmed.is_empty() && !trimmed.contains(char::is_whitespace)).then_some(trimmed)
        })
        .ok_or_else(|| invalid("the token file does not contain one bearer credential"))?;
    Ok(token.to_owned())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 16 * 1024 {
        return Err(invalid("the prepared input exceeds the accepted bound"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
