use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogFormat {
    Text,
    Json,
}

pub(crate) fn log_format_from_env() -> Result<LogFormat, String> {
    match std::env::var("REGISTRY_NOTARY_LOG_FORMAT")
        .unwrap_or_else(|_| "text".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        value => Err(format!(
            "REGISTRY_NOTARY_LOG_FORMAT must be 'text' or 'json', got '{value}'"
        )),
    }
}

pub(crate) fn default_log_filter() -> &'static str {
    DEFAULT_LOG_FILTER
}

pub(crate) fn log_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_log_filter()))
}

pub(crate) fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    let result = match log_format_from_env()? {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(log_env_filter())
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_env_filter())
            .try_init(),
    };
    if let Err(error) = result {
        let message = error.to_string();
        if message.contains("global default trace dispatcher has already been set") {
            return Ok(());
        }
        return Err(std::io::Error::other(format!("failed to initialize tracing: {error}")).into());
    };
    Ok(())
}

pub(crate) fn http_trace_span(request: &Request<Body>) -> tracing::Span {
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| request.uri().path());
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        matched_path,
    )
}
#[cfg(test)]
#[path = "logging/tests.rs"]
mod tests;
