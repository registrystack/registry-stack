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

#[cfg(test)]
#[path = "healthcheck/tests.rs"]
mod tests;
