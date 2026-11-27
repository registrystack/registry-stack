//! Paths and bodies of the liveness and readiness probes every Registry Stack
//! service answers.

/// Path of the liveness probe. It needs no authentication and does no I/O.
pub const HEALTH_PATH: &str = "/health";
/// Path of the readiness probe. It needs no authentication.
pub const READY_PATH: &str = "/ready";
/// Body of a successful liveness probe, served as `application/json`.
pub const HEALTH_BODY: &str = r#"{"status":"ok"}"#;
/// Body of a successful readiness probe, served as `application/json`.
pub const READY_BODY: &str = r#"{"status":"ready"}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_the_documented_probe_routes() {
        assert_eq!(HEALTH_PATH, "/health");
        assert_eq!(READY_PATH, "/ready");
    }

    #[test]
    fn bodies_are_json_objects_with_the_status_word() {
        let health: serde_json::Value = serde_json::from_str(HEALTH_BODY).unwrap();
        let ready: serde_json::Value = serde_json::from_str(READY_BODY).unwrap();
        assert_eq!(health, serde_json::json!({"status": "ok"}));
        assert_eq!(ready, serde_json::json!({"status": "ready"}));
    }

    #[test]
    fn bodies_are_compact_so_they_compare_byte_for_byte() {
        assert_eq!(HEALTH_BODY, r#"{"status":"ok"}"#);
        assert_eq!(READY_BODY, r#"{"status":"ready"}"#);
    }
}
