// SPDX-License-Identifier: Apache-2.0
//! Styled plain-text rendering of the bregctl reports.
//!
//! This is the same rendering discipline `relayctl` applies in its own
//! `report` module: a lead sentence carrying the counts, aligned `label
//! value` detail, blank-line separated sections, and a closing count of what
//! the reader has to act on. It differs in two ways that this tooling needs.
//!
//! The first is grouping. A registry project applies one access rule across
//! every entity, so one authoring mistake reports the identical sentence
//! against six paths. Repeating the sentence six times buries the six paths
//! that actually differ, so a run of findings sharing a severity and a code
//! prints the sentence once and lists the paths under it.
//!
//! The second is styling. Every line is written with the ANSI attributes
//! `anstyle` names, and the caller decides whether they survive: `main_entry`
//! wraps the process streams in an `anstream::AutoStream`, which keeps the
//! attributes for a terminal and strips them for a pipe, a file, or a test
//! harness. So the bytes a tutorial captures stay the plain ASCII the tutorial
//! prints, and no renderer here has to know which it is writing to.
//!
//! Values that originate outside this tool are escaped before they are styled.
//! A path, a code, or a message can carry an authored identifier, and this
//! module is the boundary that stops one from forging a line or issuing an
//! instruction to the terminal.

use anstyle::{AnsiColor, Color, Style};

/// Ordinary detail indent, and the width of one nesting level.
pub(crate) const INDENT: &str = "  ";
/// Widest severity label, so a mixed list keeps one message column.
const SEVERITY_WIDTH: usize = 7;
/// Separator between the columns of one rendered line.
pub(crate) const GAP: &str = "  ";
/// Column the wrapped prose of a finding starts in.
const MESSAGE_INDENT: usize = INDENT.len() + SEVERITY_WIDTH + GAP.len();
/// Total width every wrapped paragraph is folded to.
///
/// A fixed width, not the terminal's. The same command has to produce the same
/// bytes for a reader, a tutorial, and a test, and a rendering that reflowed
/// with the window would make a captured transcript unreproducible.
const WRAP_WIDTH: usize = 88;

/// The lead sentence: what the command did.
const LEAD: Style = Style::new().bold();
/// A detail label, quieter than the value it introduces.
const LABEL: Style = Style::new().dimmed();
/// A section heading below the lead sentence.
const HEADING: Style = Style::new().bold();
/// A diagnostic code: the identifier a reader searches the documentation for.
const CODE: Style = Style::new().bold();
/// A path into the authored project: quieter than the sentence about it.
const PATH: Style = Style::new().dimmed();
/// How many findings one grouped code covers.
const COUNT: Style = Style::new().italic();
/// A finding that stopped the command.
const ERROR: Style = Style::new()
    .bold()
    .fg_color(Some(Color::Ansi(AnsiColor::Red)));
/// A finding the reader has to weigh but that did not stop the command.
const FINDING: Style = Style::new()
    .bold()
    .fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
/// A closing count with nothing in it to act on.
const CLEAN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
/// The ordinal of a next step.
const STEP: Style = Style::new().bold();

/// Wrap one already-escaped value in an ANSI attribute.
///
/// `anstyle` renders the attribute and its reset around the value, so a caller
/// composes a line out of styled fragments without tracking terminal state.
pub(crate) fn styled(style: Style, value: &str) -> String {
    format!("{style}{value}{style:#}")
}

/// Accumulates the lines of one report.
pub(crate) struct Lines {
    lines: Vec<String>,
}

impl Lines {
    pub(crate) fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Open the report with the sentence naming what the command did.
    pub(crate) fn lead(&mut self, sentence: &str) {
        self.lines.push(styled(LEAD, &escape_report_text(sentence)));
    }

    /// Open a later section of the report.
    pub(crate) fn heading(&mut self, heading: &str) {
        self.blank();
        self.lines
            .push(styled(HEADING, &escape_report_text(heading)));
    }

    /// Separate two sections. Repeated calls collapse, and a leading blank is
    /// dropped, so a caller adds one before a section without first checking
    /// whether the section above it rendered anything.
    pub(crate) fn blank(&mut self) {
        if !self.lines.is_empty() && !self.lines.last().is_some_and(String::is_empty) {
            self.lines.push(String::new());
        }
    }

    pub(crate) fn raw(&mut self, line: String) {
        self.lines.push(line);
    }

    /// Render aligned `label  value` detail lines under one lead sentence.
    pub(crate) fn pairs(&mut self, pairs: &[(&str, String)]) {
        self.pairs_at(1, pairs);
    }

    /// Render aligned detail nested `depth` levels under the lead sentence.
    ///
    /// One call aligns the list it is given and nothing else, so a nested
    /// group's labels line up with each other rather than with the wider
    /// group they sit under, and two groups at one depth keep their own
    /// value columns.
    pub(crate) fn pairs_at(&mut self, depth: usize, pairs: &[(&str, String)]) {
        // The label is escaped before it is measured, so an escape that
        // widens a label widens the column it is padded to with it.
        let labels: Vec<String> = pairs
            .iter()
            .map(|(label, _)| escape_report_text(label))
            .collect();
        let width = labels.iter().map(String::len).max().unwrap_or_default();
        let indent = INDENT.repeat(depth);
        for (label, (_, value)) in labels.iter().zip(pairs) {
            let padded = format!("{label:<width$}");
            self.lines.push(format!(
                "{indent}{}{GAP}{}",
                styled(LABEL, &padded),
                escape_report_text(value)
            ));
        }
    }

    /// List one value per line under the section above it.
    pub(crate) fn bullet(&mut self, value: &str) {
        self.lines
            .push(format!("{INDENT}{}", escape_report_text(value)));
    }

    /// Name a group that the detail below it belongs to.
    pub(crate) fn item(&mut self, value: &str) {
        self.item_at(1, value);
    }

    /// Name a group nested `depth` levels under the lead sentence.
    pub(crate) fn item_at(&mut self, depth: usize, value: &str) {
        let indent = INDENT.repeat(depth);
        self.lines.push(format!(
            "{indent}{}",
            styled(CODE, &escape_report_text(value))
        ));
    }

    /// Fold one paragraph to the report width at `depth`.
    pub(crate) fn prose(&mut self, depth: usize, text: &str) {
        let indent = INDENT.repeat(depth);
        for line in wrap(&escape_report_text(text), WRAP_WIDTH - indent.len()) {
            self.lines.push(format!("{indent}{line}"));
        }
    }

    /// Fold one sentence of a list of them, hanging its continuation.
    ///
    /// A list of sentences long enough to wrap reads as one paragraph without
    /// this, because nothing marks where one sentence ends and the next
    /// begins. The hanging indent is what `steps` uses for the same reason.
    pub(crate) fn listed(&mut self, depth: usize, text: &str) {
        let indent = INDENT.repeat(depth);
        let hanging = INDENT.repeat(depth + 1);
        let mut wrapped = wrap(&escape_report_text(text), WRAP_WIDTH - hanging.len()).into_iter();
        let Some(first) = wrapped.next() else {
            return;
        };
        self.lines.push(format!("{indent}{first}"));
        for continuation in wrapped {
            self.lines.push(format!("{hanging}{continuation}"));
        }
    }

    /// Open a section with the answer it exists to give.
    ///
    /// The answer carries the attribute rather than the heading, because a
    /// reader scanning for it should not have to read the heading to find it.
    /// A verdict that does not hold is not an error: a refusal can be the
    /// answer that was asked for.
    pub(crate) fn verdict(&mut self, heading: &str, verdict: &str, held: bool) {
        self.blank();
        let style = if held { CLEAN } else { FINDING };
        self.lines.push(format!(
            "{} {}",
            styled(HEADING, &escape_report_text(heading)),
            styled(style, &escape_report_text(verdict))
        ));
    }

    /// Number the steps the reader takes next, in the order they take them.
    pub(crate) fn steps(&mut self, steps: &[String]) {
        if steps.is_empty() {
            return;
        }
        self.heading("Next:");
        // One column for every ordinal, so the tenth step's text starts where
        // the first step's text starts instead of shifting the whole list.
        let ordinal_width = steps.len().to_string().len();
        let hanging = INDENT.len() + ordinal_width + ". ".len();
        for (index, step) in steps.iter().enumerate() {
            let ordinal = format!("{:>ordinal_width$}.", index + 1);
            let wrapped = wrap(&escape_report_text(step), WRAP_WIDTH - hanging);
            let mut wrapped = wrapped.into_iter();
            let first = wrapped.next().unwrap_or_default();
            self.lines
                .push(format!("{INDENT}{} {first}", styled(STEP, &ordinal)));
            for continuation in wrapped {
                self.lines
                    .push(format!("{}{continuation}", " ".repeat(hanging)));
            }
        }
    }

    /// Render every diagnostic, errors before findings, then the closing count.
    ///
    /// Findings sharing a severity and a code are one group: the sentence they
    /// share prints once and every path it was reported against is listed
    /// under it. A group of one keeps the ungrouped two-line shape, because
    /// there is no repetition to collapse and the path reads better on the
    /// line that names the code.
    pub(crate) fn findings(&mut self, findings: &[Finding<'_>]) {
        self.push_findings(findings, finding_summary);
    }

    /// Render the diagnostics of a report that refused, closing with what
    /// refused it.
    ///
    /// A refusal that carries no error is still a refusal: `--deny-findings`
    /// stops on findings alone, and closing that report with a count opening
    /// on `0 errors` would tell the reader the opposite of the exit status.
    pub(crate) fn refusal_findings(&mut self, findings: &[Finding<'_>]) {
        self.push_findings(findings, refusal_summary);
    }

    fn push_findings(&mut self, findings: &[Finding<'_>], summary: fn(&[Finding<'_>]) -> String) {
        if findings.is_empty() {
            return;
        }
        self.blank();
        for severity in [Severity::Error, Severity::Finding] {
            for group in group_by_code(findings, severity) {
                self.push_group(severity, &group);
            }
        }
        self.blank();
        self.raw(summary(findings));
    }

    fn push_group(&mut self, severity: Severity, group: &[&Finding<'_>]) {
        let label = format!("{:<SEVERITY_WIDTH$}", severity.label());
        let code = styled(CODE, &escape_report_text(group[0].code));
        let head = if let [only] = group {
            format!(
                "{code}{GAP}{}",
                styled(PATH, &escape_report_text(only.path))
            )
        } else {
            format!(
                "{code}{GAP}{}",
                styled(COUNT, &counted(group.len(), "path"))
            )
        };
        self.lines.push(format!(
            "{INDENT}{}{GAP}{head}",
            styled(severity.style(), &label)
        ));

        let message = escape_report_text(group[0].message);
        for line in wrap(&message, WRAP_WIDTH - MESSAGE_INDENT) {
            self.lines
                .push(format!("{}{line}", " ".repeat(MESSAGE_INDENT)));
        }
        if group.len() > 1 {
            for finding in group {
                self.lines.push(format!(
                    "{}{}",
                    " ".repeat(MESSAGE_INDENT + INDENT.len()),
                    styled(PATH, &escape_report_text(finding.path))
                ));
            }
        }
    }

    pub(crate) fn finish(self) -> String {
        let mut rendered = self.lines.join("\n");
        rendered.push('\n');
        rendered
    }
}

/// One finding, borrowed from whichever report carries it.
///
/// The renderer reads the severity, the code, the path, and the sentence, and
/// nothing else. A report that carries more keeps it for the JSON rendering.
pub(crate) struct Finding<'a> {
    pub(crate) severity: Severity,
    pub(crate) code: &'a str,
    pub(crate) path: &'a str,
    pub(crate) message: &'a str,
}

/// The two severities a bregctl diagnostic carries.
///
/// `finding` is the tool's own word, not a softer name for a warning: it is
/// what the JSON `severity` reports and what the documentation defines, so
/// the text rendering says the same thing and a reader moves between the two
/// without translating.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Severity {
    Error,
    Finding,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Finding => "finding",
        }
    }

    fn style(self) -> Style {
        match self {
            Self::Error => ERROR,
            Self::Finding => FINDING,
        }
    }
}

/// Collect the findings of one severity into runs that share a code, keeping
/// the order the report listed them in so a reader can follow the rendering
/// back to the JSON.
fn group_by_code<'report, 'a>(
    findings: &'report [Finding<'a>],
    severity: Severity,
) -> Vec<Vec<&'report Finding<'a>>> {
    let mut groups: Vec<Vec<&Finding<'a>>> = Vec::new();
    for finding in findings.iter().filter(|item| item.severity == severity) {
        match groups
            .iter_mut()
            .find(|group| group[0].code == finding.code)
        {
            Some(group) => group.push(finding),
            None => groups.push(vec![finding]),
        }
    }
    groups
}

/// Close a refusal with the diagnostics that produced it. Where an error
/// stopped the command the count of errors is what the reader acts on, and
/// where only findings did the sentence names them as the reason.
fn refusal_summary(findings: &[Finding<'_>]) -> String {
    if findings.iter().any(|item| item.severity == Severity::Error) {
        return finding_summary(findings);
    }
    styled(
        FINDING,
        &format!("refused on {}.", counted(findings.len(), "finding")),
    )
}

fn finding_summary(findings: &[Finding<'_>]) -> String {
    let errors = findings
        .iter()
        .filter(|item| item.severity == Severity::Error)
        .count();
    let findings = findings.len() - errors;
    let summary = format!(
        "{}, {}.",
        counted(errors, "error"),
        counted(findings, "finding")
    );
    if errors == 0 && findings == 0 {
        styled(CLEAN, &summary)
    } else if errors == 0 {
        styled(FINDING, &summary)
    } else {
        styled(ERROR, &summary)
    }
}

pub(crate) fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        return format!("{count} {noun}");
    }
    // Every noun a report counts is a regular English one, so a consonant
    // before a final `y` is the only irregularity the rule has to carry:
    // `delivery` becomes `deliveries` where `journey` stays `journeys`.
    let consonant_y = noun.ends_with('y')
        && noun
            .chars()
            .nth_back(1)
            .is_some_and(|letter| !"aeiou".contains(letter));
    if consonant_y {
        format!("{count} {}ies", &noun[..noun.len() - 1])
    } else {
        format!("{count} {noun}s")
    }
}

/// Render a count that reached the report as a stored total rather than the
/// length of a collection. A total wider than this platform's `usize` cannot
/// be counted into one, so it saturates rather than wrapping to a smaller
/// number that would read as a true count.
pub(crate) fn counted_total(count: u64, noun: &str) -> String {
    counted(usize::try_from(count).unwrap_or(usize::MAX), noun)
}

/// Fold one already-escaped sentence to a column, breaking only between words.
///
/// A word wider than the column is left whole on its own line. Breaking one
/// would split an identifier or a path a reader has to copy, and a wrapped
/// line that cannot be copied is worse than a long one.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Nothing restricts what an authored name may contain. A registry project's
/// entity, field, and profile identifiers reach a path unchanged, and an
/// authored name reaches a diagnostic sentence unchanged, so any of them can
/// carry a line break, a terminal escape sequence, or a Unicode bidirectional
/// override that would forge a report line or redraw the text around it. This
/// replaces each such character with a visible, all-ASCII escape, so the value
/// stays on the one line it was given and cannot issue an instruction to the
/// terminal or the reader. Ordinary printable Unicode, including non-English
/// identifiers, passes through unchanged, and text that is already escaped is
/// unchanged by a second pass.
///
/// Every value reaching a line goes through here before it is styled, so the
/// only escape sequences in a finished rendering are the ones this module
/// wrote itself.
pub(crate) fn escape_report_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if is_unsafe_for_a_report_line(character) {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// C0 and C1 control characters (including newline, carriage return, tab, and
/// escape) and DEL are unsafe for any terminal. The Unicode bidirectional
/// formatting and override characters are unsafe for the same reason `rustc`
/// denies them in a source literal: one of them can redraw the characters that
/// follow it, so a name carrying one can read as different text than the bytes
/// it is.
fn is_unsafe_for_a_report_line(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{200e}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a pipe, a file, or a test harness receives: `anstream` strips the
    /// attributes this module writes, leaving the plain text a tutorial prints.
    fn plain(rendered: &str) -> String {
        anstream::adapter::strip_str(rendered).to_string()
    }

    fn finding<'a>(
        severity: Severity,
        code: &'a str,
        path: &'a str,
        message: &'a str,
    ) -> Finding<'a> {
        Finding {
            severity,
            code,
            path,
            message,
        }
    }

    #[test]
    fn a_repeated_code_states_its_sentence_once_and_lists_every_path() {
        let mut lines = Lines::new();
        lines.lead("Initialized a registry project. 6 artifacts written.");
        lines.findings(&[
            finding(
                Severity::Finding,
                "access.profile.unrestricted_collection",
                "entities[id=household].accessProfiles[id=operator].rowBoundaries",
                "this profile can list all rows, subject only to query bounds",
            ),
            finding(
                Severity::Finding,
                "access.profile.unrestricted_collection",
                "entities[id=person].accessProfiles[id=operator].rowBoundaries",
                "this profile can list all rows, subject only to query bounds",
            ),
        ]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Initialized a registry project. 6 artifacts written.\n",
                "\n",
                "  finding  access.profile.unrestricted_collection  2 paths\n",
                "           this profile can list all rows, subject only to query bounds\n",
                "             entities[id=household].accessProfiles[id=operator].rowBoundaries\n",
                "             entities[id=person].accessProfiles[id=operator].rowBoundaries\n",
                "\n",
                "0 errors, 2 findings.\n",
            )
        );
    }

    #[test]
    fn a_single_finding_keeps_the_path_on_the_line_that_names_the_code() {
        let mut lines = Lines::new();
        lines.lead("Authoring check passed.");
        lines.findings(&[finding(
            Severity::Finding,
            "access.profile.higher_classification",
            "entities[id=person].accessProfiles[id=operator]",
            "this field is more sensitive than its entity's classification",
        )]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Authoring check passed.\n",
                "\n",
                "  finding  access.profile.higher_classification  entities[id=person].accessProfiles[id=operator]\n",
                "           this field is more sensitive than its entity's classification\n",
                "\n",
                "0 errors, 1 finding.\n",
            )
        );
    }

    #[test]
    fn errors_group_ahead_of_findings() {
        let mut lines = Lines::new();
        lines.lead("Production check refused.");
        lines.findings(&[
            finding(Severity::Finding, "b.code", "b", "the finding sentence"),
            finding(Severity::Error, "a.code", "a", "the error sentence"),
        ]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Production check refused.\n",
                "\n",
                "  error    a.code  a\n",
                "           the error sentence\n",
                "  finding  b.code  b\n",
                "           the finding sentence\n",
                "\n",
                "1 error, 1 finding.\n",
            )
        );
    }

    #[test]
    fn a_long_sentence_folds_under_the_column_it_started_in() {
        let mut lines = Lines::new();
        lines.lead("Authoring check passed.");
        lines.findings(&[finding(
            Severity::Finding,
            "access.profile.unrestricted_collection",
            "entities[id=person]",
            "this profile can list all rows, subject only to query bounds; caller filters are not authorization. Add a claim-bound row restriction or review this registry-wide access",
        )]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Authoring check passed.\n",
                "\n",
                "  finding  access.profile.unrestricted_collection  entities[id=person]\n",
                "           this profile can list all rows, subject only to query bounds; caller filters\n",
                "           are not authorization. Add a claim-bound row restriction or review this\n",
                "           registry-wide access\n",
                "\n",
                "0 errors, 1 finding.\n",
            )
        );
    }

    #[test]
    fn next_steps_are_numbered_and_hang_under_their_own_text() {
        let mut lines = Lines::new();
        lines.lead("Initialized a registry project.");
        lines.steps(&[
            "read household/README.md, then run 'bregctl check household'".to_owned(),
            "replace canonicalBaseIri in household/registry.yaml before you build a production package; the derived value is a reserved .invalid name that never resolves".to_owned(),
        ]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Initialized a registry project.\n",
                "\n",
                "Next:\n",
                "  1. read household/README.md, then run 'bregctl check household'\n",
                "  2. replace canonicalBaseIri in household/registry.yaml before you build a production\n",
                "     package; the derived value is a reserved .invalid name that never resolves\n",
            )
        );
    }

    #[test]
    fn detail_pairs_share_one_value_column() {
        let mut lines = Lines::new();
        lines.lead("Sealed a deployment package.");
        lines.pairs(&[
            ("revision", "sha256:aaaa".to_owned()),
            ("package revision", "sha256:bbbb".to_owned()),
        ]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Sealed a deployment package.\n",
                "  revision          sha256:aaaa\n",
                "  package revision  sha256:bbbb\n",
            )
        );
    }

    #[test]
    fn a_clean_report_renders_no_finding_section() {
        let mut lines = Lines::new();
        lines.lead("Authoring check passed.");
        lines.findings(&[]);
        assert_eq!(plain(&lines.finish()), "Authoring check passed.\n");
    }

    #[test]
    fn an_authored_name_cannot_forge_a_line_or_reach_the_terminal() {
        let hostile = "entities[id=\u{1b}[31mred\n  error  forged.code  forged]";
        let mut lines = Lines::new();
        lines.lead("Authoring check passed.");
        lines.findings(&[finding(
            Severity::Finding,
            "a.code",
            hostile,
            "the sentence",
        )]);
        let rendered = plain(&lines.finish());
        assert_eq!(
            rendered.lines().count(),
            6,
            "an authored name added a line: {rendered}"
        );
        assert!(
            !rendered.contains('\u{1b}'),
            "an authored escape survived: {rendered}"
        );
        assert!(rendered.contains("\\u{1b}[31mred\\n  error  forged.code  forged]"));
    }

    #[test]
    fn a_terminal_receives_the_attributes_a_pipe_does_not() {
        let mut lines = Lines::new();
        lines.lead("Authoring check passed.");
        lines.findings(&[finding(Severity::Error, "a.code", "a", "the sentence")]);
        let rendered = lines.finish();
        assert!(
            rendered.contains('\u{1b}'),
            "the rendering carried no attributes: {rendered}"
        );
        assert!(
            plain(&rendered).len() < rendered.len(),
            "stripping the attributes changed nothing"
        );
    }

    #[test]
    fn a_refusal_built_only_from_findings_names_what_refused_it() {
        let mut lines = Lines::new();
        lines.lead("bregctl check refused.");
        lines.refusal_findings(&[
            finding(Severity::Finding, "a.code", "a", "the first sentence"),
            finding(Severity::Finding, "b.code", "b", "the second sentence"),
        ]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "bregctl check refused.\n",
                "\n",
                "  finding  a.code  a\n",
                "           the first sentence\n",
                "  finding  b.code  b\n",
                "           the second sentence\n",
                "\n",
                "refused on 2 findings.\n",
            )
        );
    }

    #[test]
    fn a_refusal_carrying_an_error_closes_with_the_count_that_stopped_it() {
        let mut lines = Lines::new();
        lines.lead("bregctl check refused.");
        lines.refusal_findings(&[
            finding(Severity::Error, "a.code", "a", "the error sentence"),
            finding(Severity::Finding, "b.code", "b", "the finding sentence"),
        ]);
        assert!(plain(&lines.finish()).ends_with("\n1 error, 1 finding.\n"));
    }

    #[test]
    fn an_authored_label_is_escaped_and_still_holds_its_column() {
        let mut lines = Lines::new();
        lines.lead("Explained the compiled inventory.");
        lines.pairs(&[
            ("entity\n  error  forged.code", "record".to_owned()),
            ("route", "records".to_owned()),
        ]);
        let rendered = plain(&lines.finish());
        assert_eq!(
            rendered,
            concat!(
                "Explained the compiled inventory.\n",
                "  entity\\n  error  forged.code  record\n",
                "  route                         records\n",
            )
        );
    }

    #[test]
    fn two_lists_at_one_depth_each_align_on_their_own_widest_label() {
        let mut lines = Lines::new();
        lines.lead("Explained the compiled inventory.");
        lines.pairs(&[("entity", "record".to_owned())]);
        lines.blank();
        lines.pairs(&[("access entries", "2".to_owned())]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Explained the compiled inventory.\n",
                "  entity  record\n",
                "\n",
                "  access entries  2\n",
            )
        );
    }

    #[test]
    fn a_counted_noun_is_pluralized_the_way_english_pluralizes_it() {
        assert_eq!(counted(1, "delivery"), "1 delivery");
        assert_eq!(counted(0, "delivery"), "0 deliveries");
        assert_eq!(counted(2, "dependency check"), "2 dependency checks");
        // A vowel before the final `y` keeps the plain `s`.
        assert_eq!(counted(3, "journey"), "3 journeys");
        assert_eq!(counted(4, "artifact"), "4 artifacts");
    }

    #[test]
    fn a_count_wider_than_the_platform_saturates_rather_than_wrapping() {
        assert_eq!(counted_total(1, "record"), "1 record");
        assert_eq!(
            counted_total(u64::MAX, "record"),
            format!("{} records", usize::MAX)
        );
    }

    #[test]
    fn a_listed_sentence_hangs_its_continuation_below_its_first_line() {
        let mut lines = Lines::new();
        lines.heading("Access:");
        lines.listed(1, "all required scopes must be present");
        lines.listed(
            1,
            "all claim-bound row predicates must hold; explicit empty boundaries mean no \
             claim-bound row restriction",
        );
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Access:\n",
                "  all required scopes must be present\n",
                "  all claim-bound row predicates must hold; explicit empty boundaries mean no\n",
                "    claim-bound row restriction\n",
            )
        );
    }

    #[test]
    fn a_verdict_carries_the_attribute_the_heading_beside_it_does_not() {
        let mut lines = Lines::new();
        lines.verdict("Synthetic profile admission:", "allowed", true);
        let allowed = lines.finish();
        let mut lines = Lines::new();
        lines.verdict("Synthetic profile admission:", "refused", false);
        let refused = lines.finish();
        assert_eq!(plain(&allowed), "Synthetic profile admission: allowed\n");
        assert_eq!(plain(&refused), "Synthetic profile admission: refused\n");
        // A refusal is an answer, not an error, so the two verdicts differ in
        // their attributes rather than one of them reading as a failure.
        assert_ne!(allowed, refused);
    }

    #[test]
    fn nested_detail_aligns_within_its_own_group_not_the_group_above_it() {
        let mut lines = Lines::new();
        lines.lead("Explained the migration plan. 1 change, 1 reviewed migration.");
        lines.pairs(&[("generated statement count", "3".to_owned())]);
        lines.blank();
        lines.item("reviewed migration 1");
        lines.pairs_at(2, &[("recovery", "exact_target_resume".to_owned())]);
        assert_eq!(
            plain(&lines.finish()),
            concat!(
                "Explained the migration plan. 1 change, 1 reviewed migration.\n",
                "  generated statement count  3\n",
                "\n",
                "  reviewed migration 1\n",
                "    recovery  exact_target_resume\n",
            )
        );
    }

    #[test]
    fn every_rendered_line_is_plain_and_free_of_trailing_space() {
        let mut lines = Lines::new();
        lines.lead("Initialized a registry project. 2 artifacts written.");
        lines.pairs(&[("revision", "sha256:aaaa".to_owned())]);
        lines.findings(&[finding(Severity::Finding, "a.code", "a", "the sentence")]);
        lines.steps(&["run 'bregctl check household'".to_owned()]);
        let rendered = plain(&lines.finish());
        assert!(rendered.is_ascii(), "rendering left ASCII: {rendered}");
        assert!(
            rendered.ends_with('\n'),
            "rendering lacks a trailing newline"
        );
        assert!(
            !rendered.ends_with("\n\n"),
            "rendering ends with a blank line"
        );
        for line in rendered.lines() {
            assert_eq!(line.trim_end(), line, "line has trailing space: {line:?}");
        }
    }
}
