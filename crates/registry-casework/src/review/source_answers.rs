//! Live answers are joined only to this request's asks, outside authored fields.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn join(
    asks: &mut Vec<ReviewContextAsk>,
    mut answers: BTreeMap<Uuid, ReviewContextAnswer>,
    delegated: bool,
) -> Result<usize, ReviewRuntimeError> {
    if delegated {
        asks.clear();
        return Ok(0);
    }
    for ask in asks {
        ask.answer = None;
        if let Some(answer) = answers.remove(&ask.ask_id) {
            validate(&answer)?;
            if answer.answered_at < ask.asked_at
                || ask
                    .wants
                    .iter()
                    .any(|want| matches!(want, ReviewAskWant::Answer {}))
                    && answer.text.is_none()
                || ask
                    .wants
                    .iter()
                    .any(|want| matches!(want, ReviewAskWant::Document {}))
                    && answer.documents.is_empty()
            {
                return Err(ReviewRuntimeError::SourceInvalid);
            }
            ask.answer = Some(answer);
        }
    }
    Ok(answers.len())
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate(answer: &ReviewContextAnswer) -> Result<(), ReviewRuntimeError> {
    if answer
        .text
        .as_ref()
        .is_some_and(|text| text.trim().is_empty() || text.len() > 2000 || text.contains('\0'))
        || answer.documents.len() > 32
        || !answer
            .answered_at
            .timestamp_subsec_nanos()
            .is_multiple_of(1000)
    {
        return Err(ReviewRuntimeError::SourceInvalid);
    }
    let mut ids = BTreeSet::new();
    for document in &answer.documents {
        if !bounded(&document.id, 128)
            || !ids.insert(&document.id)
            || document.sha256.len() != 64
            || !document
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !bounded(&document.content_type, 255)
            || document.byte_size == 0
            || document.byte_size > 9_007_199_254_740_991
            || document
                .verification_status
                .as_ref()
                .is_some_and(|status| !bounded(status, 32))
        {
            return Err(ReviewRuntimeError::SourceInvalid);
        }
        if let Some(link) = &document.download {
            if link.method != "GET"
                || !bounded(&link.operation, 128)
                || !bounded(&link.access_profile, 128)
                || !bounded(&link.path, 8192)
                || !link.path.starts_with('/')
                || link.path.starts_with("//")
            {
                return Err(ReviewRuntimeError::SourceInvalid);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask() -> ReviewContextAsk {
        serde_json::from_value(json!({
            "askId":Uuid::new_v4(),"taskId":Uuid::new_v4(),"text":"Why?",
            "wants":[{"kind":"answer"}],"askedAt":"2026-11-27T00:00:00Z","state":"open"
        }))
        .unwrap()
    }
    fn answer() -> ReviewContextAnswer {
        serde_json::from_value(json!({"text":"Private source answer","documents":[],"answeredAt":"2026-11-27T01:00:00Z"})).unwrap()
    }

    #[test]
    fn source_answer_documents_accept_the_breg_media_type_bound() {
        let mut answer = answer();
        answer.documents = serde_json::from_value(json!([{
            "id":"00000000-0000-4000-8000-000000000001", "sha256":"a".repeat(64),
            "contentType":format!("{}/{}", "a".repeat(127), "a".repeat(127)), "byteSize":1
        }]))
        .unwrap();
        assert!(validate(&answer).is_ok());
        answer.documents[0].content_type.push('a');
        assert!(validate(&answer).is_err());
    }

    #[test]
    fn unknown_source_answers_are_counted_and_never_joined_to_another_request() {
        let mut asks = vec![ask()];
        let count = join(
            &mut asks,
            BTreeMap::from([(Uuid::new_v4(), answer())]),
            false,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert!(asks[0].answer.is_none());
    }

    #[test]
    fn delegated_reads_discard_questions_and_source_answers() {
        let mut asks = vec![ask()];
        let answers = BTreeMap::from([(asks[0].ask_id, answer())]);
        assert_eq!(join(&mut asks, answers, true).unwrap(), 0);
        assert!(asks.is_empty());
    }

    #[test]
    fn every_join_uses_only_the_current_source_observation() {
        let mut asks = vec![ask()];
        let answers = BTreeMap::from([(asks[0].ask_id, answer())]);
        assert_eq!(join(&mut asks, answers, false).unwrap(), 0);
        assert!(asks[0].answer.is_some());
        assert!(!format!("{:?}", asks[0].answer).contains("Private source answer"));
        join(&mut asks, BTreeMap::new(), false).unwrap();
        assert!(asks[0].answer.is_none());
    }
}
