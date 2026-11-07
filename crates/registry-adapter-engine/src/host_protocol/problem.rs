use super::{HostProtocolError, HostProtocolWireResponse};

use registry_platform_canonical_json::parse_json_preserving_integers;
use serde_json::{Map, Value};

const MAXIMUM_CLASSIFIER_CONFIG_BYTES: usize = 4 * 1024;
const MAXIMUM_PROBLEM_BYTES: usize = 64 * 1024;
const MAXIMUM_TYPE_URI_CHARACTERS: usize = 512;
const MAXIMUM_CODE_BYTES: usize = 64;
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// A compiled exact Problem Details tuple used by trusted host protocols.
#[derive(Clone)]
pub struct ExactProblemClassifier {
    type_uri: String,
    code: String,
}

impl ExactProblemClassifier {
    /// Compile one closed `{status,type,code}` classifier configuration.
    pub fn from_config(config: &[u8]) -> Result<Self, HostProtocolError> {
        if config.is_empty() || config.len() > MAXIMUM_CLASSIFIER_CONFIG_BYTES {
            return Err(HostProtocolError);
        }
        let value = parse_json_preserving_integers(config).map_err(|_| HostProtocolError)?;
        let object = value.as_object().ok_or(HostProtocolError)?;
        if object.len() != 3 || !exact_status(object.get("status"), 404) {
            return Err(HostProtocolError);
        }
        let type_uri = object
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| valid_type_uri(value))
            .ok_or(HostProtocolError)?;
        let code = object
            .get("code")
            .and_then(Value::as_str)
            .filter(|value| valid_code(value))
            .ok_or(HostProtocolError)?;
        Ok(Self {
            type_uri: type_uri.to_owned(),
            code: code.to_owned(),
        })
    }

    /// Classify a response without exposing its raw body to a route or script.
    pub fn classify(&self, response: &HostProtocolWireResponse) -> Result<bool, HostProtocolError> {
        if response.status() == 404 {
            self.classify_not_found(response)
        } else {
            Ok(false)
        }
    }

    fn classify_not_found(
        &self,
        response: &HostProtocolWireResponse,
    ) -> Result<bool, HostProtocolError> {
        let mut content_types = response
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let value = match (content_types.next(), content_types.next()) {
            (Some((_, value)), None) => value,
            _ => return Err(HostProtocolError),
        };
        if !is_problem_media_type(value) {
            return Err(HostProtocolError);
        }
        let body = response.body();
        if body.is_empty() || body.len() > MAXIMUM_PROBLEM_BYTES {
            return Err(HostProtocolError);
        }
        let value = parse_json_preserving_integers(body).map_err(|_| HostProtocolError)?;
        let object = value.as_object().ok_or(HostProtocolError)?;
        if !required_problem_members(object)
            || !exact_status(object.get("status"), 404)
            || object.get("type").and_then(Value::as_str) != Some(self.type_uri.as_str())
            || object.get("code").and_then(Value::as_str) != Some(self.code.as_str())
        {
            return Err(HostProtocolError);
        }
        Ok(true)
    }
}

fn valid_type_uri(value: &str) -> bool {
    if value.is_empty()
        || value.chars().count() > MAXIMUM_TYPE_URI_CHARACTERS
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return false;
    }
    url::Url::parse(value).is_ok_and(|uri| {
        uri.scheme() == "https"
            && uri.host().is_some()
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.fragment().is_none()
    })
}

fn valid_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAXIMUM_CODE_BYTES).contains(&bytes.len())
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn exact_status(value: Option<&Value>, expected: u64) -> bool {
    value
        .and_then(Value::as_number)
        .and_then(serde_json::Number::as_u64)
        == Some(expected)
}

/// Media types are case-insensitive and may carry parameters (`charset`).
fn is_problem_media_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(PROBLEM_MEDIA_TYPE))
}

/// The required members must be present and typed; members this classifier
/// does not know are ignored, so a later minor release may add some.
fn required_problem_members(object: &Map<String, Value>) -> bool {
    ["type", "title", "detail", "code", "traceId"]
        .into_iter()
        .all(|name| object.get(name).is_some_and(Value::is_string))
        && object.get("status").is_some_and(Value::is_number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const TYPE_URI: &str = "https://source.example/problems/registry/not-found";
    const CODE: &str = "registry.record-not-found";
    const VALID_CONFIG: &str = r#"{"status":404,"type":"https://source.example/problems/registry/not-found","code":"registry.record-not-found"}"#;
    const VALID_PROBLEM: &str = r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}"#;

    fn classifier() -> ExactProblemClassifier {
        ExactProblemClassifier::from_config(VALID_CONFIG.as_bytes()).expect("valid classifier")
    }

    fn response(
        status: u16,
        headers: &[(&str, &str)],
        body: impl AsRef<[u8]>,
    ) -> HostProtocolWireResponse {
        HostProtocolWireResponse::new(
            status,
            headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            Zeroizing::new(body.as_ref().to_vec()),
            chrono::DateTime::UNIX_EPOCH,
        )
    }

    fn problem_response(body: impl AsRef<[u8]>) -> HostProtocolWireResponse {
        response(404, &[("content-type", "application/problem+json")], body)
    }

    #[test]
    fn exact_classifier_accepts_only_its_closed_configuration() {
        assert!(ExactProblemClassifier::from_config(VALID_CONFIG.as_bytes()).is_ok());

        let maximum_code = format!("a{}", "0".repeat(63));
        let boundary = format!(
            r#"{{"status":404,"type":"https://source.example/problem","code":"{maximum_code}"}}"#
        );
        assert!(ExactProblemClassifier::from_config(boundary.as_bytes()).is_ok());

        let type_prefix = "https://source.example/";
        let maximum_type = format!(
            "{type_prefix}{}",
            "a".repeat(MAXIMUM_TYPE_URI_CHARACTERS - type_prefix.chars().count())
        );
        let boundary =
            format!(r#"{{"status":404,"type":"{maximum_type}","code":"source.missing"}}"#);
        assert!(ExactProblemClassifier::from_config(boundary.as_bytes()).is_ok());

        let mut boundary = VALID_CONFIG.as_bytes().to_vec();
        boundary.resize(MAXIMUM_CLASSIFIER_CONFIG_BYTES, b' ');
        assert!(ExactProblemClassifier::from_config(&boundary).is_ok());
        boundary.push(b' ');
        assert!(ExactProblemClassifier::from_config(&boundary).is_err());

        let refusals = [
            "",
            "null",
            "[]",
            r#"{"status":404,"type":"https://source.example/problem"}"#,
            r#"{"status":404,"type":"https://source.example/problem","code":"source.missing","extra":true}"#,
            r#"{"status":404,"status":404,"type":"https://source.example/problem","code":"source.missing"}"#,
            r#"{"status":403,"type":"https://source.example/problem","code":"source.missing"}"#,
            r#"{"status":404.0,"type":"https://source.example/problem","code":"source.missing"}"#,
            r#"{"status":"404","type":"https://source.example/problem","code":"source.missing"}"#,
            r#"{"status":404,"type":false,"code":"source.missing"}"#,
            r#"{"status":404,"type":"http://source.example/problem","code":"source.missing"}"#,
            r#"{"status":404,"type":"/problem","code":"source.missing"}"#,
            r#"{"status":404,"type":"https://user@source.example/problem","code":"source.missing"}"#,
            r#"{"status":404,"type":" https://source.example/problem","code":"source.missing"}"#,
            r#"{"status":404,"type":"https://source.example/problem#fragment","code":"source.missing"}"#,
            r#"{"status":404,"type":"https://source.example/problem","code":false}"#,
            r#"{"status":404,"type":"https://source.example/problem","code":""}"#,
            r#"{"status":404,"type":"https://source.example/problem","code":"Invalid.Code"}"#,
            r#"{"status":404,"type":"https://source.example/problem","code":"source/missing"}"#,
        ];
        for config in refusals {
            assert!(
                ExactProblemClassifier::from_config(config.as_bytes()).is_err(),
                "configuration should be refused: {config}"
            );
        }

        let oversized_code = "a".repeat(65);
        let config = format!(
            r#"{{"status":404,"type":"https://source.example/problem","code":"{oversized_code}"}}"#
        );
        assert!(ExactProblemClassifier::from_config(config.as_bytes()).is_err());

        let oversized_type = format!("https://source.example/{}", "a".repeat(512));
        let config =
            format!(r#"{{"status":404,"type":"{oversized_type}","code":"source.missing"}}"#);
        assert!(ExactProblemClassifier::from_config(config.as_bytes()).is_err());
    }

    #[test]
    fn exact_problem_tuple_is_classified_and_body_remains_borrowable() {
        let response = response(
            404,
            &[
                ("content-type", "application/problem+json"),
                (
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                ),
            ],
            VALID_PROBLEM,
        );
        assert!(classifier().classify(&response).expect("exact problem"));
        assert_eq!(response.body(), VALID_PROBLEM.as_bytes());
    }

    #[test]
    fn non_404_responses_are_never_problem_matches() {
        let oversized = vec![b'x'; 65_537];
        let response = response(200, &[], oversized);
        assert!(!classifier().classify(&response).expect("ordinary response"));
    }

    #[test]
    fn problem_media_type_ignores_case_and_parameters() {
        for value in [
            "Application/Problem+Json",
            "application/problem+json; charset=utf-8",
            "application/problem+json;charset=utf-8",
            "APPLICATION/PROBLEM+JSON ; profile=x",
        ] {
            let response = response(404, &[("content-type", value)], VALID_PROBLEM);
            assert!(
                classifier().classify(&response).expect(value),
                "media type: {value}"
            );
        }
    }

    #[test]
    fn exact_problem_ignores_members_it_does_not_recognise() {
        let extended = VALID_PROBLEM.replace(
            "\"traceId\"",
            "\"instance\":\"/lookups/1\",\"errors\":[{\"field\":\"id\"}],\"traceId\"",
        );
        assert_ne!(extended, VALID_PROBLEM);
        assert!(classifier()
            .classify(&problem_response(extended))
            .expect("additive members are ignored"));
    }

    #[test]
    fn exact_problem_requires_one_problem_content_type_header() {
        let cases: &[&[(&str, &str)]] = &[
            &[],
            &[("content-type", "application/json")],
            &[("content-type", "application/problem+json-seq")],
            &[("content-type", "application/problem+jsonx; charset=utf-8")],
            &[
                ("content-type", "application/problem+json"),
                ("Content-Type", "application/problem+json"),
            ],
        ];
        for headers in cases {
            let response = response(404, headers, VALID_PROBLEM);
            assert!(
                classifier().classify(&response).is_err(),
                "headers: {headers:?}"
            );
        }
    }

    #[test]
    fn exact_problem_refuses_malformed_duplicate_open_or_mistyped_bodies() {
        let cases = [
            "",
            "not-json",
            &format!("{VALID_PROBLEM} trailing"),
            r#"{"type":"https://source.example/problems/registry/not-found","type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":"No matching record exists.","code":"registry.record-not-found"}"#,
            r#"{"type":1,"title":"Record not found","status":404,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":null,"status":404,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":"404","detail":"No matching record exists.","code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404.0,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":[],"code":"registry.record-not-found","traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":"No matching record exists.","code":false,"traceId":"trace"}"#,
            r#"{"type":"https://source.example/problems/registry/not-found","title":"Record not found","status":404,"detail":"No matching record exists.","code":"registry.record-not-found","traceId":12}"#,
        ];
        for body in cases {
            assert!(
                classifier().classify(&problem_response(body)).is_err(),
                "body: {body}"
            );
        }
    }

    #[test]
    fn exact_problem_refuses_every_tuple_mismatch() {
        for body in [
            VALID_PROBLEM.replace(TYPE_URI, "https://source.example/problems/other"),
            VALID_PROBLEM.replace(CODE, "registry.other"),
            VALID_PROBLEM.replace("\"status\":404", "\"status\":403"),
        ] {
            assert!(classifier().classify(&problem_response(body)).is_err());
        }
    }

    #[test]
    fn exact_problem_holds_the_64_kib_wire_bound() {
        let mut exact = VALID_PROBLEM.as_bytes().to_vec();
        exact.resize(65_536, b' ');
        assert!(classifier()
            .classify(&problem_response(&exact))
            .expect("at bound"));
        exact.push(b' ');
        assert!(classifier().classify(&problem_response(&exact)).is_err());
    }
}
