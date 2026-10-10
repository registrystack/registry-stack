// SPDX-License-Identifier: Apache-2.0

//! What a check of an authored Messaging file found beyond what its reader
//! refuses: references between declarations, rules that read two members
//! together, and what a template version ships beside its `template.yaml`.
//!
//! Each finding has a closed code `messaging.<area>.<reason>`, a JSON
//! Pointer, and a message and fix that never repeat a value the file holds
//! (CFG-SEC-3). The reader decides the position: a finding about a member is
//! placed in the document it names, and a finding about a file beside it,
//! such as a template part, names that file and, when known, the line.

use std::path::Path;

use registry_platform_yaml::{Diagnostic, Document, Report, Severity, Source};

use crate::naming::{MESSAGING_PROJECT_KIND, MESSAGING_PROVIDER_KIND, MESSAGING_TEMPLATE_KIND};
use crate::render::RenderFailure;

/// The authored format a finding is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingArea {
    /// `messaging.yaml`.
    Project,
    /// A template version: its `template.yaml` and the files beside it.
    Template,
    /// An HTTP provider's `provider.yaml` and the scripts it names.
    Provider,
}

impl FindingArea {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Template => "template",
            Self::Provider => "provider",
        }
    }

    /// The `kind` of the format, which names the diagnostic's artifact.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Project => MESSAGING_PROJECT_KIND,
            Self::Template => MESSAGING_TEMPLATE_KIND,
            Self::Provider => MESSAGING_PROVIDER_KIND,
        }
    }
}

/// Why a check reports a finding. The set is closed: each reason has one
/// code, one severity, and one value-free message and fix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingReason {
    /// A declaration list holds more entries than one project may declare.
    TooManyEntries,
    UnknownProvider,
    ProviderCannotCarryChannel,
    InvalidEmailSender,
    InvalidSmsSender,
    MissingMaximumSegments,
    EmailMaximumSegments,
    RetryDelayOrder,
    UncertainRetryDuplicates,
    IdempotentSmtp,
    UnknownSenderProfile,
    UnknownTemplate,
    SharedRequesterClient,
    SenderWithoutTargets,
    OperatorWithSendingPermissions,
    /// An allow-list item spelled `*` or `unrestricted` (CFG-EMPTY-2).
    WildcardSpelledItem,
    /// A declared template version the project does not ship.
    MissingTemplate,
    /// A shipped template version the project does not declare.
    UndeclaredTemplate,
    PartsDoNotFitChannel,
    TooManyLocales,
    MissingLocaleDirectory,
    UndeclaredLocaleDirectory,
    PartFilesMismatch,
    PartTooLarge,
    PartSyntax,
    /// schema.json is not JSON.
    SchemaSyntax,
    SchemaNotObject,
    SchemaRemoteReference,
    SchemaInvalid,
    /// sample.json is not JSON.
    SampleSyntax,
    SampleInvalid,
    SampleRenderFailed(RenderFailure),
    ReceiptScriptRequired,
    ReceiptScriptNotAllowed,
    ScriptDoesNotCompile,
    ScriptEntrypoint,
}

// The messages below state these bounds in static text.
const _: () = assert!(crate::package::MAXIMUM_PACKAGE_DECLARATIONS == 256);
const _: () = assert!(crate::template::MAXIMUM_TEMPLATE_LOCALES == 32);
const _: () = assert!(crate::template::MAXIMUM_TEMPLATE_SOURCE_BYTES == 64 * 1024);
const _: () = assert!(crate::sms::MAXIMUM_SMS_SEGMENTS == 10);

impl FindingReason {
    #[must_use]
    pub const fn area(self) -> FindingArea {
        match self {
            Self::TooManyEntries
            | Self::UnknownProvider
            | Self::ProviderCannotCarryChannel
            | Self::InvalidEmailSender
            | Self::InvalidSmsSender
            | Self::MissingMaximumSegments
            | Self::EmailMaximumSegments
            | Self::RetryDelayOrder
            | Self::UncertainRetryDuplicates
            | Self::IdempotentSmtp
            | Self::UnknownSenderProfile
            | Self::UnknownTemplate
            | Self::SharedRequesterClient
            | Self::SenderWithoutTargets
            | Self::OperatorWithSendingPermissions
            | Self::WildcardSpelledItem
            | Self::MissingTemplate => FindingArea::Project,
            Self::UndeclaredTemplate
            | Self::PartsDoNotFitChannel
            | Self::TooManyLocales
            | Self::MissingLocaleDirectory
            | Self::UndeclaredLocaleDirectory
            | Self::PartFilesMismatch
            | Self::PartTooLarge
            | Self::PartSyntax
            | Self::SchemaSyntax
            | Self::SchemaNotObject
            | Self::SchemaRemoteReference
            | Self::SchemaInvalid
            | Self::SampleSyntax
            | Self::SampleInvalid
            | Self::SampleRenderFailed(_) => FindingArea::Template,
            Self::ReceiptScriptRequired
            | Self::ReceiptScriptNotAllowed
            | Self::ScriptDoesNotCompile
            | Self::ScriptEntrypoint => FindingArea::Provider,
        }
    }

    /// The last segment of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooManyEntries => "too-many-entries",
            Self::UnknownProvider => "unknown-provider",
            Self::ProviderCannotCarryChannel => "provider-cannot-carry-channel",
            Self::InvalidEmailSender => "invalid-email-sender",
            Self::InvalidSmsSender => "invalid-sms-sender",
            Self::MissingMaximumSegments => "missing-maximum-segments",
            Self::EmailMaximumSegments => "email-maximum-segments",
            Self::RetryDelayOrder => "retry-delay-order",
            Self::UncertainRetryDuplicates => "uncertain-retry-duplicates",
            Self::IdempotentSmtp => "idempotent-smtp",
            Self::UnknownSenderProfile => "unknown-sender-profile",
            Self::UnknownTemplate => "unknown-template",
            Self::SharedRequesterClient => "shared-requester-client",
            Self::SenderWithoutTargets => "sender-without-targets",
            Self::OperatorWithSendingPermissions => "operator-with-sending-permissions",
            Self::WildcardSpelledItem => "wildcard-spelled-item",
            Self::MissingTemplate => "missing-template",
            Self::UndeclaredTemplate => "undeclared",
            Self::PartsDoNotFitChannel => "parts-do-not-fit-channel",
            Self::TooManyLocales => "too-many-locales",
            Self::MissingLocaleDirectory => "missing-locale-directory",
            Self::UndeclaredLocaleDirectory => "undeclared-locale-directory",
            Self::PartFilesMismatch => "part-files-mismatch",
            Self::PartTooLarge => "part-too-large",
            Self::PartSyntax => "part-syntax",
            Self::SchemaSyntax => "schema-syntax",
            Self::SchemaNotObject => "schema-not-object",
            Self::SchemaRemoteReference => "schema-remote-reference",
            Self::SchemaInvalid => "schema-invalid",
            Self::SampleSyntax => "sample-syntax",
            Self::SampleInvalid => "sample-invalid",
            Self::SampleRenderFailed(_) => "sample-render-failed",
            Self::ReceiptScriptRequired => "receipt-script-required",
            Self::ReceiptScriptNotAllowed => "receipt-script-not-allowed",
            Self::ScriptDoesNotCompile => "script-does-not-compile",
            Self::ScriptEntrypoint => "script-entrypoint",
        }
    }

    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::WildcardSpelledItem => Severity::Warning,
            _ => Severity::Error,
        }
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::TooManyEntries => {
                "The list holds more than 256 entries, the most one project declares."
            }
            Self::UnknownProvider => {
                "The sender profile names a provider the project does not declare."
            }
            Self::ProviderCannotCarryChannel => {
                "The sender profile routes its channel through a provider whose type cannot carry \
                 it: an smtp provider carries only email."
            }
            Self::InvalidEmailSender => {
                "An email sender is one address, local@domain, without a display name, angle \
                 brackets, or a second address."
            }
            Self::InvalidSmsSender => {
                "An SMS sender is an E.164 number, or 1 to 11 letters, digits, or inner spaces."
            }
            Self::MissingMaximumSegments => {
                "An SMS sender profile declares no maximumSegments, the most segments one message \
                 may use."
            }
            Self::EmailMaximumSegments => {
                "An email sender profile declares maximumSegments, which only an SMS profile reads."
            }
            Self::RetryDelayOrder => {
                "The retry's maximumDelaySeconds is shorter than its initialDelaySeconds."
            }
            Self::UncertainRetryDuplicates => {
                "onUncertain: retry may deliver a message twice: the provider does not declare \
                 idempotentSubmit and the profile does not set acceptDuplicates."
            }
            Self::IdempotentSmtp => {
                "An smtp provider cannot declare idempotentSubmit: an SMTP relay does not \
                 deduplicate on a key the runtime sends."
            }
            Self::UnknownSenderProfile => {
                "The access profile names a sender profile the project does not declare."
            }
            Self::UnknownTemplate => {
                "The access profile names a template the project does not declare."
            }
            Self::SharedRequesterClient => {
                "The client is a requester client of an earlier access profile too, and a token \
                 must resolve to one profile."
            }
            Self::SenderWithoutTargets => {
                "A sender access profile names no sender profile or no template, so it can send \
                 nothing."
            }
            Self::OperatorWithSendingPermissions => {
                "An operator access profile declares senderProfiles, templates, or \
                 allowDirectContent, which an operator never uses: it submits nothing."
            }
            Self::WildcardSpelledItem => {
                "The item is spelled like a wildcard but names one entry: `*` and `unrestricted` \
                 match nothing else in this list."
            }
            Self::MissingTemplate => {
                "The project declares a template version it does not ship under templates."
            }
            Self::UndeclaredTemplate => {
                "The project ships this template version without declaring it in messaging.yaml."
            }
            Self::PartsDoNotFitChannel => {
                "The parts do not fit the channel: an email template renders subject and text, \
                 and optionally html; an SMS template renders exactly one text part."
            }
            Self::TooManyLocales => "The template declares more than 32 locales.",
            Self::MissingLocaleDirectory => {
                "The template declares a locale it ships no directory for."
            }
            Self::UndeclaredLocaleDirectory => {
                "The template ships a locale directory its template.yaml does not declare."
            }
            Self::PartFilesMismatch => {
                "The locale directory does not hold exactly one file per declared part."
            }
            Self::PartTooLarge => "The template part exceeds 64 KiB.",
            Self::PartSyntax => "The template part does not parse.",
            Self::SchemaSyntax => "schema.json is not JSON.",
            Self::SchemaNotObject => "schema.json is not a JSON Schema object.",
            Self::SchemaRemoteReference => {
                "schema.json reaches outside itself: a reference that does not start with `#`, or \
                 an $id, which would rebase its references."
            }
            Self::SchemaInvalid => "schema.json is not a valid JSON Schema (draft 2020-12).",
            Self::SampleSyntax => "sample.json is not JSON.",
            Self::SampleInvalid => "sample.json does not satisfy the template's schema.json.",
            Self::SampleRenderFailed(RenderFailure::Undefined) => {
                "The part reads a value sample.json does not define."
            }
            Self::SampleRenderFailed(RenderFailure::FuelExhausted) => {
                "The part ran out of rendering budget with sample.json."
            }
            Self::SampleRenderFailed(RenderFailure::TooLarge) => {
                "The part renders larger than its channel allows with sample.json."
            }
            Self::SampleRenderFailed(RenderFailure::Failed) => {
                "The part fails to render with sample.json: a type error, a bad filter argument, \
                 or a value a formatting filter cannot format."
            }
            Self::ReceiptScriptRequired => {
                "capabilities.receipts is callback, so the provider needs a receiptScript."
            }
            Self::ReceiptScriptNotAllowed => {
                "A receiptScript is read only when capabilities.receipts is callback."
            }
            Self::ScriptDoesNotCompile => "The script does not compile.",
            Self::ScriptEntrypoint => {
                "The script does not define the function the runtime calls, with its parameters."
            }
        }
    }

    #[must_use]
    pub const fn suggested_action(self) -> &'static str {
        match self {
            Self::TooManyEntries => "Remove entries the deployment does not use.",
            Self::UnknownProvider => {
                "Declare the provider under providers, or name a declared one."
            }
            Self::ProviderCannotCarryChannel => {
                "Route the profile through an http provider, or change its channel to email."
            }
            Self::InvalidEmailSender => "Write one address, such as notices@example.org.",
            Self::InvalidSmsSender => {
                "Write an E.164 number such as +15551234567, or a sender of at most 11 letters and \
                 digits."
            }
            Self::MissingMaximumSegments => "Add maximumSegments, from 1 to 10.",
            Self::EmailMaximumSegments => "Remove maximumSegments from the email sender profile.",
            Self::RetryDelayOrder => "Make maximumDelaySeconds at least initialDelaySeconds.",
            Self::UncertainRetryDuplicates => {
                "Write onUncertain: hold, declare idempotentSubmit on a provider that \
                 deduplicates, or set acceptDuplicates: true to accept duplicates."
            }
            Self::IdempotentSmtp => "Remove idempotentSubmit from the smtp provider.",
            Self::UnknownSenderProfile => {
                "Declare the sender profile under senderProfiles, or name a declared one."
            }
            Self::UnknownTemplate => {
                "Declare a version of the template under templates, or name a declared one."
            }
            Self::SharedRequesterClient => "List the client in one access profile only.",
            Self::SenderWithoutTargets => {
                "List the senderProfiles and templates the profile may use, or make it an \
                 operator."
            }
            Self::OperatorWithSendingPermissions => {
                "Remove senderProfiles, templates, and allowDirectContent, or make the profile a \
                 sender."
            }
            Self::WildcardSpelledItem => "Name the entry the profile is for.",
            Self::MissingTemplate => {
                "Add templates/<id>/<version>/ with its template.yaml, or remove the declaration."
            }
            Self::UndeclaredTemplate => {
                "Declare the version under templates in messaging.yaml, or remove its directory."
            }
            Self::PartsDoNotFitChannel => "List the parts the channel renders.",
            Self::TooManyLocales => "Ship at most 32 locales in one template version.",
            Self::MissingLocaleDirectory => {
                "Add the locale's directory with its part files, or remove the locale."
            }
            Self::UndeclaredLocaleDirectory => {
                "Declare the locale under locales, or remove its directory."
            }
            Self::PartFilesMismatch => {
                "Ship one .j2 file per part template.yaml lists, and no other part."
            }
            Self::PartTooLarge => "Shorten the part, or split the message into templates.",
            Self::PartSyntax => "Fix the template syntax at the line named.",
            Self::SchemaSyntax => "Fix the JSON syntax of schema.json at the line named.",
            Self::SchemaNotObject => "Write schema.json as one JSON object.",
            Self::SchemaRemoteReference => {
                "Define the schema within schema.json under $defs and reference it with #/$defs/."
            }
            Self::SchemaInvalid => "Fix schema.json so it compiles as a draft 2020-12 schema.",
            Self::SampleSyntax => "Fix the JSON syntax of sample.json at the line named.",
            Self::SampleInvalid => "Make sample.json satisfy schema.json, or fix the schema.",
            Self::SampleRenderFailed(_) => {
                "Make the part render with sample.json, or make sample.json carry what the part \
                 reads."
            }
            Self::ReceiptScriptRequired => {
                "Add receiptScript, or set capabilities.receipts to none or reconcile."
            }
            Self::ReceiptScriptNotAllowed => {
                "Remove receiptScript, or set capabilities.receipts to callback."
            }
            Self::ScriptDoesNotCompile => "Fix the script so it compiles as Rhai.",
            Self::ScriptEntrypoint => {
                "Define the function the provider package documents for this script."
            }
        }
    }
}

/// One finding: why, where in the document, and, for a file beside the
/// document, which file, relative to the document's directory, and line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessagingFinding {
    pub reason: FindingReason,
    /// A JSON Pointer into the document, or into `file` when it is set.
    pub path: String,
    pub file: Option<String>,
    pub line: Option<usize>,
}

impl MessagingFinding {
    /// A finding about the member at `path` of the document checked.
    #[must_use]
    pub fn new(reason: FindingReason, path: impl Into<String>) -> Self {
        Self {
            reason,
            path: path.into(),
            file: None,
            line: None,
        }
    }

    /// A finding about `file`, beside the document checked.
    #[must_use]
    pub fn in_file(reason: FindingReason, file: impl Into<String>, line: Option<usize>) -> Self {
        Self {
            reason,
            path: String::new(),
            file: Some(file.into()),
            line,
        }
    }

    /// Set the JSON Pointer into `file`.
    #[must_use]
    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    #[must_use]
    pub fn severity(&self) -> Severity {
        self.reason.severity()
    }

    #[must_use]
    pub fn is_error(&self) -> bool {
        self.severity() == Severity::Error
    }

    /// `messaging.<area>.<reason>`.
    #[must_use]
    pub fn code(&self) -> String {
        format!(
            "messaging.{}.{}",
            self.reason.area().as_str(),
            self.reason.as_str()
        )
    }

    /// The diagnostic, placed in `document`: at the member `path` names,
    /// at its nearest written ancestor when the member is absent, or at
    /// the file beside `document` this finding names.
    #[must_use]
    pub fn to_diagnostic(&self, document: &Document) -> Diagnostic {
        let reason = self.reason;
        if let Some(file) = &self.file {
            let mut diagnostic = self.to_unplaced_diagnostic();
            let file = Path::new(document.file()).parent().map_or_else(
                || file.clone(),
                |parent| parent.join(file).display().to_string(),
            );
            diagnostic.source = Some(Source {
                file,
                line: self.line,
                column: None,
            });
            return diagnostic;
        }
        let code = self.code();
        if document.span_of(&self.path).is_some() {
            return document.diagnostic_at_value(
                reason.severity(),
                &code,
                &self.path,
                reason.message(),
                reason.suggested_action(),
            );
        }
        let mut ancestor = self.path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            ancestor = parent;
            if document.span_of(ancestor).is_some() {
                let mut diagnostic = document.diagnostic_at_key(
                    reason.severity(),
                    &code,
                    ancestor,
                    reason.message(),
                    reason.suggested_action(),
                );
                diagnostic.path.clone_from(&self.path);
                return diagnostic;
            }
        }
        document.diagnostic_at_value(
            reason.severity(),
            &code,
            &self.path,
            reason.message(),
            reason.suggested_action(),
        )
    }

    /// The diagnostic without a position, for a caller with no document.
    #[must_use]
    pub fn to_unplaced_diagnostic(&self) -> Diagnostic {
        let reason = self.reason;
        let mut diagnostic = match reason.severity() {
            Severity::Warning => Diagnostic::warning(
                self.code(),
                self.path.clone(),
                reason.message(),
                reason.suggested_action(),
            ),
            Severity::Error => Diagnostic::error(
                self.code(),
                self.path.clone(),
                reason.message(),
                reason.suggested_action(),
            ),
        };
        diagnostic.artifact = Some(reason.area().kind().to_owned());
        diagnostic
    }
}

/// The document's own warnings and every finding, placed in it.
#[must_use]
pub fn findings_report(document: &Document, findings: &[MessagingFinding]) -> Report {
    let mut report = document.warnings();
    for finding in findings {
        report.push(finding.to_diagnostic(document));
    }
    report
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use registry_platform_yaml::{read_document, EnvelopeRule, Expect, FormatSpec};

    use super::*;

    const ALL_REASONS: &[FindingReason] = &[
        FindingReason::TooManyEntries,
        FindingReason::UnknownProvider,
        FindingReason::ProviderCannotCarryChannel,
        FindingReason::InvalidEmailSender,
        FindingReason::InvalidSmsSender,
        FindingReason::MissingMaximumSegments,
        FindingReason::EmailMaximumSegments,
        FindingReason::RetryDelayOrder,
        FindingReason::UncertainRetryDuplicates,
        FindingReason::IdempotentSmtp,
        FindingReason::UnknownSenderProfile,
        FindingReason::UnknownTemplate,
        FindingReason::SharedRequesterClient,
        FindingReason::SenderWithoutTargets,
        FindingReason::OperatorWithSendingPermissions,
        FindingReason::WildcardSpelledItem,
        FindingReason::MissingTemplate,
        FindingReason::UndeclaredTemplate,
        FindingReason::PartsDoNotFitChannel,
        FindingReason::TooManyLocales,
        FindingReason::MissingLocaleDirectory,
        FindingReason::UndeclaredLocaleDirectory,
        FindingReason::PartFilesMismatch,
        FindingReason::PartTooLarge,
        FindingReason::PartSyntax,
        FindingReason::SchemaSyntax,
        FindingReason::SchemaNotObject,
        FindingReason::SchemaRemoteReference,
        FindingReason::SchemaInvalid,
        FindingReason::SampleSyntax,
        FindingReason::SampleInvalid,
        FindingReason::SampleRenderFailed(RenderFailure::Undefined),
        FindingReason::SampleRenderFailed(RenderFailure::FuelExhausted),
        FindingReason::SampleRenderFailed(RenderFailure::TooLarge),
        FindingReason::SampleRenderFailed(RenderFailure::Failed),
        FindingReason::ReceiptScriptRequired,
        FindingReason::ReceiptScriptNotAllowed,
        FindingReason::ScriptDoesNotCompile,
        FindingReason::ScriptEntrypoint,
    ];

    const TEST_FORMAT: FormatSpec<'static> = FormatSpec {
        kind: MESSAGING_PROJECT_KIND,
        envelope: EnvelopeRule::Exempt { reason: "test" },
        removed_keys: &[],
    };

    fn document(text: &str) -> Document {
        read_document(
            "project/messaging.yaml",
            text.as_bytes(),
            &Expect::one(&TEST_FORMAT),
        )
        .expect("the test document reads")
    }

    #[test]
    fn every_message_and_fix_is_a_sentence_and_every_code_is_distinct() {
        let mut codes = BTreeSet::new();
        for reason in ALL_REASONS {
            for text in [reason.message(), reason.suggested_action()] {
                assert!(
                    text.starts_with(|first: char| first.is_ascii_uppercase())
                        || text.starts_with("onUncertain")
                        || text.starts_with("capabilities")
                        || text.starts_with("schema.json")
                        || text.starts_with("sample.json"),
                    "{text}"
                );
                assert!(text.ends_with('.'), "{text}");
            }
            let finding = MessagingFinding::new(*reason, "");
            assert!(
                finding.code().starts_with("messaging."),
                "{}",
                finding.code()
            );
            if !matches!(reason, FindingReason::SampleRenderFailed(_)) {
                assert!(codes.insert(finding.code()), "{}", finding.code());
            }
        }
    }

    #[test]
    fn a_finding_is_placed_at_its_member_or_its_nearest_written_ancestor() {
        let document = document("senderProfiles:\n  - id: sms\n    channel: sms\n");
        let placed =
            MessagingFinding::new(FindingReason::InvalidSmsSender, "/senderProfiles/0/channel")
                .to_diagnostic(&document);
        assert_eq!(placed.code, "messaging.project.invalid-sms-sender");
        assert_eq!(placed.path, "/senderProfiles/0/channel");
        let source = placed.source.expect("placed");
        assert_eq!((source.line, source.column), (Some(3), Some(14)));

        let absent = MessagingFinding::new(
            FindingReason::MissingMaximumSegments,
            "/senderProfiles/0/maximumSegments",
        )
        .to_diagnostic(&document);
        assert_eq!(absent.path, "/senderProfiles/0/maximumSegments");
        assert_eq!(absent.source.expect("placed").line, Some(2));
        assert_eq!(absent.artifact.as_deref(), Some(MESSAGING_PROJECT_KIND));
    }

    #[test]
    fn a_finding_about_a_file_beside_the_document_names_that_file() {
        let document = document("channel: sms\n");
        let diagnostic =
            MessagingFinding::in_file(FindingReason::PartSyntax, "en/text.j2", Some(4))
                .to_diagnostic(&document);
        assert_eq!(diagnostic.code, "messaging.template.part-syntax");
        assert_eq!(
            diagnostic.artifact.as_deref(),
            Some(MESSAGING_TEMPLATE_KIND)
        );
        let source = diagnostic.source.expect("placed");
        assert_eq!(
            source.file,
            Path::new("project/en/text.j2").display().to_string()
        );
        assert_eq!((source.line, source.column), (Some(4), None));
    }

    #[test]
    fn a_wildcard_spelled_item_is_a_warning() {
        let report = findings_report(
            &document("accessProfiles: []\n"),
            &[MessagingFinding::new(
                FindingReason::WildcardSpelledItem,
                "/accessProfiles",
            )],
        );
        assert!(!report.has_errors());
        assert_eq!(report.warning_count(), 1);
    }
}
