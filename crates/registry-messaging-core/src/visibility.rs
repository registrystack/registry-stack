// SPDX-License-Identifier: Apache-2.0

//! Who may see a message.
//!
//! A message is visible to the caller that submitted it, identified by issuer
//! and subject together, and to every operator profile. Everyone else is told
//! the message is not visible, exactly as if it did not exist, so reading a
//! status is never an existence oracle for another caller's messages.

use serde::{Deserialize, Serialize};

use crate::access::{AccessRole, Caller};
use crate::problem::ProblemCode;

/// A principal as the token issuer names it. A subject is only unique within
/// its issuer, so the pair is the identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CallerIdentity {
    pub issuer: String,
    pub subject: String,
}

/// Decide whether `caller` may see a message submitted by `submitter`.
/// `None` means no such message exists, which answers the same way.
pub fn check_message_visibility(
    caller: &Caller,
    submitter: Option<&CallerIdentity>,
) -> Result<(), ProblemCode> {
    match (caller.role(), submitter) {
        (_, None) => Err(ProblemCode::MessageNotVisible),
        (AccessRole::Operator, Some(_)) => Ok(()),
        (AccessRole::Sender, Some(submitter)) if *submitter == caller.identity => Ok(()),
        (AccessRole::Sender, Some(_)) => Err(ProblemCode::MessageNotVisible),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{AccessProfile, ActorKind};

    fn identity(issuer: &str, subject: &str) -> CallerIdentity {
        CallerIdentity {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
        }
    }

    fn caller(role: AccessRole, issuer: &str, subject: &str) -> Caller {
        Caller {
            identity: identity(issuer, subject),
            actor_kind: Some(ActorKind::Service),
            profile: AccessProfile {
                id: "profile".to_owned(),
                principal_claim: "sub".to_owned(),
                required_scopes: Vec::new(),
                requester_clients: vec!["client".to_owned()],
                actor_kind: None,
                role,
                sender_profiles: Vec::new(),
                templates: Vec::new(),
                allow_direct_content: false,
                requests_per_minute: 1,
                burst: 1,
                daily_limit: None,
            },
        }
    }

    /// Security invariant 4: status and cancel are visible only to the
    /// submitter and operators; another caller is answered as if the message
    /// did not exist.
    #[test]
    fn another_caller_is_told_the_message_is_not_visible() {
        let submitter = identity("https://issuer-a.test", "principal-1");
        let own = caller(AccessRole::Sender, "https://issuer-a.test", "principal-1");
        assert_eq!(check_message_visibility(&own, Some(&submitter)), Ok(()));

        let other_subject = caller(AccessRole::Sender, "https://issuer-a.test", "principal-2");
        assert_eq!(
            check_message_visibility(&other_subject, Some(&submitter)),
            Err(ProblemCode::MessageNotVisible)
        );
        // The same subject from another issuer is another principal.
        let other_issuer = caller(AccessRole::Sender, "https://issuer-b.test", "principal-1");
        assert_eq!(
            check_message_visibility(&other_issuer, Some(&submitter)),
            Err(ProblemCode::MessageNotVisible)
        );
        let operator = caller(AccessRole::Operator, "https://ops.test", "operator-1");
        assert_eq!(
            check_message_visibility(&operator, Some(&submitter)),
            Ok(())
        );
    }

    #[test]
    fn a_missing_message_answers_exactly_like_an_invisible_one() {
        let own = caller(AccessRole::Sender, "https://issuer-a.test", "principal-1");
        let operator = caller(AccessRole::Operator, "https://ops.test", "operator-1");
        let other = caller(AccessRole::Sender, "https://issuer-a.test", "principal-2");
        let submitter = identity("https://issuer-a.test", "principal-1");
        assert_eq!(
            check_message_visibility(&own, None),
            check_message_visibility(&other, Some(&submitter))
        );
        assert_eq!(
            check_message_visibility(&operator, None),
            Err(ProblemCode::MessageNotVisible)
        );
    }
}
