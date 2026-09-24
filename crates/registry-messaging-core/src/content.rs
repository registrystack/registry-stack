// SPDX-License-Identifier: Apache-2.0

//! A checked package and the content decisions over it.
//!
//! [`Package`] is the manifest plus every compiled template version and the
//! digest the runtime computed over the files they came from. Its methods
//! are the one path from a request to content a provider may carry:
//! authorize the caller, resolve the sender profile and template version,
//! validate the data, render, apply the channel's character and size rules,
//! and count SMS segments against the sender profile's `maximumSegments`.
//! The same checks apply to direct content, so a caller that opts out of
//! templates opts out of nothing else.
//!
//! Nothing here persists or sends. The runtime stores [`PreparedContent`]
//! as the message's payload, so a later package can never change bytes a
//! message was accepted with.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::access::{
    authorize_preview, authorize_submission, AccessProfiles, Caller, SubmissionRefusal,
    SubmissionScope,
};
use crate::package::{
    valid_package_digest, Channel, CheckedManifest, MessagingPackage, PackageError, SenderProfile,
    TemplateReference,
};
use crate::problem::ProblemCode;
use crate::render::{finish_part, PartKind, RenderFailure};
use crate::sms::{count_segments, SegmentCount};
use crate::template::{
    CompiledTemplate, DataDiagnostic, RenderRefusal, RenderedParts, TemplateSource,
};

/// A package whose manifest and templates passed every check.
#[derive(Clone, Debug)]
pub struct Package {
    manifest: CheckedManifest,
    templates: BTreeMap<TemplateReference, CompiledTemplate>,
    digest: String,
}

impl Package {
    /// Check `manifest`, compile every template in `sources`, and bind them
    /// to `digest`. The shipped template versions must be exactly the
    /// declared ones.
    pub fn assemble(
        manifest: &MessagingPackage,
        sources: Vec<TemplateSource>,
        digest: String,
    ) -> Result<Self, PackageError> {
        if !valid_package_digest(&digest) {
            return Err(PackageError::InvalidDigest);
        }
        let checked = manifest.check()?;
        let mut templates = BTreeMap::new();
        for source in sources {
            let reference = TemplateReference {
                id: source.id.clone(),
                version: source.version.clone(),
            };
            if !checked.templates.contains(&reference) {
                return Err(PackageError::UndeclaredTemplate {
                    id: reference.id,
                    version: reference.version,
                });
            }
            let compiled =
                CompiledTemplate::compile(source).map_err(|reason| PackageError::Template {
                    id: reference.id.clone(),
                    version: reference.version.clone(),
                    reason,
                })?;
            templates.insert(reference, compiled);
        }
        if let Some(missing) = checked
            .templates
            .iter()
            .find(|reference| !templates.contains_key(*reference))
        {
            return Err(PackageError::MissingTemplate {
                id: missing.id.clone(),
                version: missing.version.clone(),
            });
        }
        Ok(Self {
            manifest: checked,
            templates,
            digest,
        })
    }

    /// The package digest, `sha256:<hex>`.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn access_profiles(&self) -> &AccessProfiles {
        &self.manifest.access_profiles
    }

    #[must_use]
    pub fn sender_profile(&self, id: &str) -> Option<&SenderProfile> {
        self.manifest.sender_profiles.get(id)
    }

    #[must_use]
    pub fn template(&self, id: &str, version: &str) -> Option<&CompiledTemplate> {
        self.templates.get(&TemplateReference {
            id: id.to_owned(),
            version: version.to_owned(),
        })
    }

    pub fn templates(&self) -> impl Iterator<Item = &CompiledTemplate> {
        self.templates.values()
    }

    /// Render one template version for an author, with no caller: the
    /// operator CLI's preview. The runtime route authorizes first and then
    /// calls this, so both answer the same bytes.
    pub fn preview(
        &self,
        id: &str,
        version: &str,
        request: &TemplatePreviewRequest,
    ) -> Result<TemplatePreview, ContentRefusal> {
        let template = self
            .template(id, version)
            .ok_or(ContentRefusal::TemplateNotFound)?;
        let parts = render(template, &request.locale, &request.data)?;
        let sms = template.segments(&parts);
        Ok(TemplatePreview {
            template: TemplateReference {
                id: id.to_owned(),
                version: version.to_owned(),
            },
            locale: request.locale.clone(),
            channel: template.channel(),
            package_digest: self.digest.clone(),
            parts,
            sms,
        })
    }

    /// Authorize `caller` to preview the template, then [`Self::preview`].
    pub fn preview_for(
        &self,
        caller: &Caller,
        id: &str,
        version: &str,
        request: &TemplatePreviewRequest,
    ) -> Result<TemplatePreview, ContentRefusal> {
        authorize_preview(caller, id).map_err(ContentRefusal::NotAuthorized)?;
        self.preview(id, version, request)
    }

    /// Prepare a templated message for `caller`: authorize, validate, render,
    /// and check the result against the sender profile. This is the entry
    /// point a submission calls before it persists anything.
    pub fn prepare_template_message(
        &self,
        caller: &Caller,
        request: &TemplateMessageRequest,
    ) -> Result<PreparedContent, ContentRefusal> {
        authorize_submission(
            caller,
            &SubmissionScope {
                sender_profile: &request.sender_profile,
                template: Some(&request.template_id),
                direct_content: false,
            },
        )
        .map_err(ContentRefusal::NotAuthorized)?;
        let sender = self.authorized_sender(&request.sender_profile)?;
        let template = self
            .template(&request.template_id, &request.version)
            .ok_or(ContentRefusal::TemplateNotFound)?;
        if template.channel() != sender.channel {
            return Err(ContentRefusal::ChannelMismatch);
        }
        let parts = render(template, &request.locale, &request.data)?;
        self.prepared(
            sender,
            ContentSource::Template {
                id: request.template_id.clone(),
                version: request.version.clone(),
                locale: request.locale.clone(),
            },
            parts,
        )
    }

    /// Prepare direct content for `caller`. The profile must allow direct
    /// content, and the content meets every rule a rendered template meets:
    /// the channel's parts, the character rules, the size ceilings, and the
    /// segment limit. HTML is never accepted directly: only a reviewed
    /// template may carry markup.
    pub fn prepare_direct_message(
        &self,
        caller: &Caller,
        sender_profile: &str,
        content: &DirectContent,
    ) -> Result<PreparedContent, ContentRefusal> {
        authorize_submission(
            caller,
            &SubmissionScope {
                sender_profile,
                template: None,
                direct_content: true,
            },
        )
        .map_err(ContentRefusal::NotAuthorized)?;
        let sender = self.authorized_sender(sender_profile)?;
        let subject = match (sender.channel, &content.subject) {
            (Channel::Email, Some(subject)) => Some(finish_direct(PartKind::Subject, subject)?),
            (Channel::Sms, None) => None,
            _ => return Err(ContentRefusal::ChannelMismatch),
        };
        let parts = RenderedParts {
            subject,
            text: finish_direct(PartKind::Text, &content.text)?,
            html: None,
        };
        self.prepared(sender, ContentSource::Direct, parts)
    }

    fn authorized_sender(&self, id: &str) -> Result<&SenderProfile, ContentRefusal> {
        // The package check proved every sender profile an access profile
        // lists is declared, so an authorized name always resolves.
        self.sender_profile(id).ok_or(ContentRefusal::NotAuthorized(
            SubmissionRefusal::SenderProfile,
        ))
    }

    fn prepared(
        &self,
        sender: &SenderProfile,
        source: ContentSource,
        parts: RenderedParts,
    ) -> Result<PreparedContent, ContentRefusal> {
        if parts.text.trim().is_empty()
            || parts
                .subject
                .as_deref()
                .is_some_and(|subject| subject.trim().is_empty())
        {
            return Err(ContentRefusal::Empty);
        }
        let sms = match sender.channel {
            Channel::Email => None,
            Channel::Sms => {
                let count = count_segments(&parts.text);
                let maximum = usize::from(sender.maximum_segments.unwrap_or(1));
                if count.segments > maximum {
                    return Err(ContentRefusal::TooManySegments {
                        segments: count.segments,
                        maximum,
                    });
                }
                Some(count)
            }
        };
        Ok(PreparedContent {
            channel: sender.channel,
            sender_profile: sender.id.clone(),
            source,
            parts,
            package_digest: self.digest.clone(),
            sms,
        })
    }
}

fn render(
    template: &CompiledTemplate,
    locale: &str,
    data: &Value,
) -> Result<RenderedParts, ContentRefusal> {
    template
        .render(locale, data)
        .map_err(|refusal| match refusal {
            RenderRefusal::LocaleUnavailable => ContentRefusal::LocaleUnavailable,
            RenderRefusal::DataInvalid {
                diagnostics,
                truncated,
            } => ContentRefusal::DataInvalid {
                diagnostics,
                truncated,
            },
            RenderRefusal::Part {
                failure: RenderFailure::TooLarge,
                ..
            } => ContentRefusal::TooLarge,
            RenderRefusal::Part { part, failure } => ContentRefusal::Render { part, failure },
        })
}

fn finish_direct(kind: PartKind, text: &str) -> Result<String, ContentRefusal> {
    if text.len() > kind.ceiling() {
        return Err(ContentRefusal::TooLarge);
    }
    Ok(finish_part(kind, text))
}

/// What a templated submission asks for.
#[derive(Clone, Debug)]
pub struct TemplateMessageRequest {
    pub sender_profile: String,
    pub template_id: String,
    pub version: String,
    pub locale: String,
    pub data: Value,
}

/// Content a caller supplies instead of naming a template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectContent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub text: String,
}

/// Where accepted content came from, as the audit record names it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentSource {
    Template {
        id: String,
        version: String,
        locale: String,
    },
    Direct,
}

impl ContentSource {
    /// The audited `contentSource`: `template` or `direct`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Template { .. } => "template",
            Self::Direct => "direct",
        }
    }
}

/// Content ready to persist with an accepted message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedContent {
    pub channel: Channel,
    pub sender_profile: String,
    pub source: ContentSource,
    pub parts: RenderedParts,
    /// The package the content was prepared under.
    pub package_digest: String,
    /// The segment count, for SMS only.
    pub sms: Option<SegmentCount>,
}

/// The body of a preview request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplatePreviewRequest {
    pub locale: String,
    pub data: Value,
}

/// A rendered template version, as the preview route answers and
/// `messagingctl preview --format json` prints it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplatePreview {
    pub template: TemplateReference,
    pub locale: String,
    pub channel: Channel,
    pub package_digest: String,
    pub parts: RenderedParts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sms: Option<SegmentCount>,
}

/// Why content was refused. Each maps to one closed problem code; the data
/// diagnostics are for an author's tooling and never cross the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentRefusal {
    NotAuthorized(SubmissionRefusal),
    TemplateNotFound,
    LocaleUnavailable,
    DataInvalid {
        diagnostics: Vec<DataDiagnostic>,
        truncated: bool,
    },
    Render {
        part: PartKind,
        failure: RenderFailure,
    },
    /// The content's parts do not fit the sender profile's channel.
    ChannelMismatch,
    /// The text, or an email subject, is blank.
    Empty,
    TooLarge,
    TooManySegments {
        segments: usize,
        maximum: usize,
    },
}

impl ContentRefusal {
    #[must_use]
    pub const fn problem(&self) -> ProblemCode {
        match self {
            Self::NotAuthorized(refusal) => refusal.problem(),
            Self::TemplateNotFound => ProblemCode::TemplateNotFound,
            Self::LocaleUnavailable => ProblemCode::TemplateLocaleUnavailable,
            Self::DataInvalid { .. } => ProblemCode::TemplateDataInvalid,
            Self::Render { .. } => ProblemCode::TemplateRenderRefused,
            Self::ChannelMismatch | Self::Empty => ProblemCode::ContentInvalid,
            Self::TooLarge => ProblemCode::ContentTooLarge,
            Self::TooManySegments { .. } => ProblemCode::ContentTooManySegments,
        }
    }
}

impl std::fmt::Display for ContentRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthorized(refusal) => write!(formatter, "{refusal}"),
            Self::TemplateNotFound => {
                formatter.write_str("the package ships no such template version")
            }
            Self::LocaleUnavailable => {
                std::fmt::Display::fmt(&RenderRefusal::LocaleUnavailable, formatter)
            }
            Self::DataInvalid {
                diagnostics,
                truncated,
            } => std::fmt::Display::fmt(
                &RenderRefusal::DataInvalid {
                    diagnostics: diagnostics.clone(),
                    truncated: *truncated,
                },
                formatter,
            ),
            Self::Render { part, failure } => std::fmt::Display::fmt(
                &RenderRefusal::Part {
                    part: *part,
                    failure: *failure,
                },
                formatter,
            ),
            Self::ChannelMismatch => {
                formatter.write_str("the content does not fit the sender profile's channel")
            }
            Self::Empty => formatter.write_str("the text or subject is blank"),
            Self::TooLarge => formatter.write_str("a part exceeds its size ceiling"),
            Self::TooManySegments { segments, maximum } => write!(
                formatter,
                "the SMS needs {segments} segments; the sender profile allows {maximum}"
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::access::{AccessProfile, ActorKind};
    use crate::package::tests::valid;
    use crate::render::MAXIMUM_TEXT_BYTES;
    use crate::sms::SmsEncoding;
    use crate::template::tests::{email_source, sms_source};
    use crate::visibility::CallerIdentity;
    use serde_json::json;

    pub(crate) const DIGEST_V1: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    /// A manifest shipping `appointment-reminder` 1 and 2 (email) and
    /// `appointment-sms` 1, with one sender allowed both and direct content.
    pub(crate) fn manifest() -> MessagingPackage {
        let mut value = valid();
        value["templates"] = json!([
            {"id": "appointment-reminder", "version": "1"},
            {"id": "appointment-reminder", "version": "2"},
            {"id": "appointment-sms", "version": "1"}
        ]);
        value["accessProfiles"][0]["senderProfiles"] = json!(["transactional", "notices-sms"]);
        value["accessProfiles"][0]["templates"] =
            json!(["appointment-reminder", "appointment-sms"]);
        value["accessProfiles"][0]["allowDirectContent"] = json!(true);
        value["accessProfiles"].as_array_mut().unwrap().push(json!({
            "id": "operators",
            "principalClaim": "sub",
            "requesterClients": ["operator-console"],
            "role": "operator",
            "requestsPerMinute": 60,
            "burst": 10
        }));
        serde_json::from_value(value).unwrap()
    }

    pub(crate) fn package_with(sms_text: &str) -> Package {
        Package::assemble(
            &manifest(),
            vec![
                email_source("1"),
                email_source("2"),
                sms_source("1", sms_text),
            ],
            DIGEST_V1.to_owned(),
        )
        .unwrap()
    }

    fn package() -> Package {
        package_with("Reminder for {{ name }} on {{ day|date }}")
    }

    pub(crate) fn caller_for(profile: &AccessProfile) -> Caller {
        Caller {
            identity: CallerIdentity {
                issuer: "https://issuer.test".to_owned(),
                subject: "principal-1".to_owned(),
            },
            actor_kind: Some(ActorKind::Service),
            profile: profile.clone(),
        }
    }

    fn sender() -> Caller {
        caller_for(package().access_profiles().get("case-notices").unwrap())
    }

    fn request(sender_profile: &str, template: &str, version: &str) -> TemplateMessageRequest {
        TemplateMessageRequest {
            sender_profile: sender_profile.to_owned(),
            template_id: template.to_owned(),
            version: version.to_owned(),
            locale: "en".to_owned(),
            data: json!({"name": "Ada", "day": "2026-10-01"}),
        }
    }

    #[test]
    fn a_templated_message_is_prepared_with_its_source_and_digest() {
        let prepared = package()
            .prepare_template_message(
                &sender(),
                &request("transactional", "appointment-reminder", "2"),
            )
            .unwrap();
        assert_eq!(prepared.channel, Channel::Email);
        assert_eq!(prepared.source.as_str(), "template");
        assert_eq!(
            prepared.source,
            ContentSource::Template {
                id: "appointment-reminder".into(),
                version: "2".into(),
                locale: "en".into()
            }
        );
        assert_eq!(prepared.package_digest, DIGEST_V1);
        assert_eq!(
            prepared.parts.subject.as_deref(),
            Some("Appointment on 01/10/2026")
        );
        assert_eq!(prepared.sms, None);

        let sms = package()
            .prepare_template_message(&sender(), &request("notices-sms", "appointment-sms", "1"))
            .unwrap();
        assert_eq!(
            sms.sms,
            Some(SegmentCount {
                encoding: SmsEncoding::Gsm7,
                units: 30,
                segments: 1
            })
        );
    }

    #[test]
    fn authorization_precedes_every_lookup() {
        let package = package();
        let refusal = |request: TemplateMessageRequest| {
            package
                .prepare_template_message(&sender(), &request)
                .unwrap_err()
                .problem()
        };
        assert_eq!(
            refusal(request("transactional", "payment-notice", "1")),
            ProblemCode::ProfileNotAuthorized
        );
        assert_eq!(
            refusal(request("undeclared", "appointment-reminder", "1")),
            ProblemCode::ProfileNotAuthorized
        );
        assert_eq!(
            refusal(request("transactional", "appointment-reminder", "9")),
            ProblemCode::TemplateNotFound
        );
        let operator = caller_for(package.access_profiles().get("operators").unwrap());
        assert_eq!(
            package
                .prepare_template_message(
                    &operator,
                    &request("transactional", "appointment-reminder", "1")
                )
                .unwrap_err()
                .problem(),
            ProblemCode::OperationNotAuthorized
        );
    }

    #[test]
    fn template_refusals_map_to_their_problems() {
        let package = package();
        let refused = |edit: fn(&mut TemplateMessageRequest)| {
            let mut request = request("transactional", "appointment-reminder", "1");
            edit(&mut request);
            package
                .prepare_template_message(&sender(), &request)
                .unwrap_err()
                .problem()
        };
        assert_eq!(
            refused(|r| r.locale = "de".into()),
            ProblemCode::TemplateLocaleUnavailable
        );
        assert_eq!(
            refused(|r| r.data = json!({"name": "Ada"})),
            ProblemCode::TemplateDataInvalid
        );
        assert_eq!(
            refused(|r| r.sender_profile = "notices-sms".into()),
            ProblemCode::ContentInvalid
        );
        let long = package_with("{{ name }}");
        let mut request = request("notices-sms", "appointment-sms", "1");
        request.data = json!({"name": "x".repeat(80), "day": "2026-10-01"});
        assert!(long.prepare_template_message(&sender(), &request).is_ok());
        let fuel = package_with("{% for a in name %}{% for b in name %}{% for c in name %}{% endfor %}{% endfor %}{% endfor %}");
        assert_eq!(
            fuel.prepare_template_message(&sender(), &request)
                .unwrap_err()
                .problem(),
            ProblemCode::TemplateRenderRefused
        );
    }

    #[test]
    fn an_sms_beyond_the_sender_profiles_segments_is_refused() {
        // The fixture's SMS sender allows two segments.
        let package = package_with("{{ name }}");
        let mut request = request("notices-sms", "appointment-sms", "1");
        request.data = json!({"name": "a".repeat(306), "day": "2026-10-01"});
        assert_eq!(
            package
                .prepare_template_message(&sender(), &request)
                .unwrap()
                .sms
                .unwrap()
                .segments,
            2
        );
        request.data = json!({"name": "a".repeat(307), "day": "2026-10-01"});
        let refusal = package
            .prepare_template_message(&sender(), &request)
            .unwrap_err();
        assert_eq!(
            refusal,
            ContentRefusal::TooManySegments {
                segments: 3,
                maximum: 2
            }
        );
        assert_eq!(refusal.problem(), ProblemCode::ContentTooManySegments);
        let direct = package
            .prepare_direct_message(
                &sender(),
                "notices-sms",
                &DirectContent {
                    subject: None,
                    text: "ç".repeat(135),
                },
            )
            .unwrap_err();
        assert_eq!(direct.problem(), ProblemCode::ContentTooManySegments);
    }

    #[test]
    fn direct_content_meets_the_same_rules_as_a_template() {
        let package = package();
        let prepared = package
            .prepare_direct_message(
                &sender(),
                "transactional",
                &DirectContent {
                    subject: Some("Notice\r\nBcc: x@example.org".into()),
                    text: "Line one\u{7}\nLine two".into(),
                },
            )
            .unwrap();
        assert_eq!(prepared.source, ContentSource::Direct);
        assert_eq!(prepared.source.as_str(), "direct");
        assert_eq!(
            prepared.parts.subject.as_deref(),
            Some("NoticeBcc: x@example.org")
        );
        assert_eq!(prepared.parts.text, "Line one\nLine two");
        assert_eq!(prepared.parts.html, None);
        assert_eq!(prepared.package_digest, DIGEST_V1);

        let refused = |sender_profile: &str, subject: Option<&str>, text: String| {
            package
                .prepare_direct_message(
                    &sender(),
                    sender_profile,
                    &DirectContent {
                        subject: subject.map(str::to_owned),
                        text,
                    },
                )
                .unwrap_err()
                .problem()
        };
        assert_eq!(
            refused("transactional", None, "text".into()),
            ProblemCode::ContentInvalid
        );
        assert_eq!(
            refused("notices-sms", Some("subject"), "text".into()),
            ProblemCode::ContentInvalid
        );
        assert_eq!(
            refused("notices-sms", None, " \n\u{0}".into()),
            ProblemCode::ContentInvalid
        );
        assert_eq!(
            refused(
                "transactional",
                Some("s"),
                "x".repeat(MAXIMUM_TEXT_BYTES + 1)
            ),
            ProblemCode::ContentTooLarge
        );
        assert!(
            serde_json::from_value::<DirectContent>(json!({"text": "x", "html": "<b>x</b>"}))
                .is_err()
        );
    }

    #[test]
    fn direct_content_needs_the_profiles_opt_in() {
        let package = package();
        let mut profile = package
            .access_profiles()
            .get("case-notices")
            .unwrap()
            .clone();
        profile.allow_direct_content = false;
        let refusal = package
            .prepare_direct_message(
                &caller_for(&profile),
                "notices-sms",
                &DirectContent {
                    subject: None,
                    text: "hello".into(),
                },
            )
            .unwrap_err();
        assert_eq!(
            refusal,
            ContentRefusal::NotAuthorized(SubmissionRefusal::DirectContent)
        );
    }

    #[test]
    fn preview_renders_without_persisting_and_reports_segments() {
        let package = package();
        let preview = package
            .preview_for(
                &sender(),
                "appointment-sms",
                "1",
                &TemplatePreviewRequest {
                    locale: "en".into(),
                    data: json!({"name": "Ada", "day": "2026-10-01"}),
                },
            )
            .unwrap();
        assert_eq!(preview.channel, Channel::Sms);
        assert_eq!(preview.package_digest, DIGEST_V1);
        assert_eq!(preview.parts.text, "Reminder for Ada on 01/10/2026");
        assert_eq!(preview.sms.unwrap().segments, 1);
        let unauthorized = package.preview_for(
            &sender(),
            "payment-notice",
            "1",
            &TemplatePreviewRequest {
                locale: "en".into(),
                data: json!({}),
            },
        );
        assert_eq!(
            unauthorized.unwrap_err().problem(),
            ProblemCode::ProfileNotAuthorized
        );
    }

    #[test]
    fn the_package_ships_exactly_the_declared_templates() {
        let undeclared = Package::assemble(
            &manifest(),
            vec![
                email_source("1"),
                email_source("2"),
                email_source("3"),
                sms_source("1", "x"),
            ],
            DIGEST_V1.to_owned(),
        );
        assert!(matches!(
            undeclared,
            Err(PackageError::UndeclaredTemplate { .. })
        ));
        let missing = Package::assemble(
            &manifest(),
            vec![email_source("1"), sms_source("1", "x")],
            DIGEST_V1.to_owned(),
        );
        assert!(matches!(missing, Err(PackageError::MissingTemplate { .. })));
        let digest = Package::assemble(
            &manifest(),
            vec![email_source("1"), email_source("2"), sms_source("1", "x")],
            "sha256:short".to_owned(),
        );
        assert_eq!(digest.unwrap_err(), PackageError::InvalidDigest);
    }
}
