// SPDX-License-Identifier: Apache-2.0

//! HTTP wire documents the runtime and every client share.

use serde::{Deserialize, Serialize};

use crate::problem::{type_uri, ProblemCode};

/// The problem document every refusal answers with, as a client reads it.
/// Field names match the Registry Stack problem envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProblemDocument {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub trace_id: String,
}

impl ProblemDocument {
    /// The closed-vocabulary code this document carries, when the document
    /// is exactly the one the runtime renders for that code: the type URI,
    /// title, detail, and status all match what the vocabulary pins.
    #[must_use]
    pub fn problem(&self) -> Option<ProblemCode> {
        let code = ProblemCode::from_code(&self.code)?;
        (self.type_uri == type_uri(code.code())
            && self.status == code.http_status()
            && self.title == code.title()
            && self.detail == code.detail())
        .then_some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rendered(code: ProblemCode) -> serde_json::Value {
        json!({
            "type": type_uri(code.code()),
            "title": code.title(),
            "status": code.http_status(),
            "detail": code.detail(),
            "code": code.code(),
            "traceId": "0af7651916cd43dd8448eb211c80319c",
        })
    }

    #[test]
    fn a_pinned_problem_document_reads_back_as_its_code() {
        for code in ProblemCode::ALL {
            let document: ProblemDocument = serde_json::from_value(rendered(*code)).unwrap();
            assert_eq!(document.problem(), Some(*code));
        }
    }

    #[test]
    fn a_document_that_disagrees_with_the_vocabulary_is_not_trusted() {
        let mut value = rendered(ProblemCode::MessageNotVisible);
        value["status"] = json!(403);
        let document: ProblemDocument = serde_json::from_value(value).unwrap();
        assert_eq!(document.problem(), None);

        let mut value = rendered(ProblemCode::MessageNotVisible);
        value["code"] = json!("message.unknown");
        let document: ProblemDocument = serde_json::from_value(value).unwrap();
        assert_eq!(document.problem(), None);
    }
}
