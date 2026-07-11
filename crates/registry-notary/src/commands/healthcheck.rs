use crate::*;

pub(crate) async fn run_healthcheck(
    url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(url)
        .send()
        .await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("health endpoint returned HTTP {}", response.status()).into())
    }
}

pub(crate) fn lightweight_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Registry Notary standalone config",
        "type": "object",
        "required": ["auth", "evidence"],
        "properties": {
            "server": { "type": "object" },
            "auth": { "type": "object" },
            "audit": { "type": "object" },
            "replay": { "type": "object" },
            "credential_status": { "type": "object" },
            "self_attestation": { "type": "object" },
            "oid4vci": { "type": "object" },
            "evidence": { "type": "object" },
            "federation": { "type": "object" }
        },
        "additionalProperties": false
    })
}
#[cfg(test)]
#[path = "healthcheck/tests.rs"]
mod tests;
