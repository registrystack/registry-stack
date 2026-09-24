// SPDX-License-Identifier: Apache-2.0

//! The template renderer.
//!
//! Every part renders in its own `minijinja` environment built from
//! [`Environment::empty`]: no loader, no includes or macros, no built-in
//! filters, tests, or globals. The only names a template can reach are the
//! data it is given, the tests `defined`, `undefined`, and `none`, and the
//! closed formatting filters `date` and `number`, which read the locale the
//! caller asked for. Nothing in the environment can reach a network, a file,
//! or a clock.
//!
//! Each render is bounded three ways: strict undefined turns a missing value
//! into a refusal instead of an empty string, a fuel budget stops runaway
//! loops, and an output ceiling per part stops the write the moment the part
//! outgrows its channel.
//!
//! Escaping follows the part. An HTML part escapes every interpolated value,
//! whatever the template says: the formatter ignores the template's own
//! `autoescape` blocks, and no filter can mark a value safe. A text or SMS
//! part is not escaped, and control characters other than newline are
//! stripped from the rendered output; a subject loses newlines as well, so
//! no rendered value can open a new header line.

use minijinja::value::{Value, ValueKind};
use minijinja::{Environment, Error, ErrorKind, HtmlEscape, UndefinedBehavior};
use serde::{Deserialize, Serialize};

/// Instructions one part may execute.
pub const RENDER_FUEL: u64 = 100_000;

/// Nesting depth of template blocks and data one render may reach.
pub const RENDER_RECURSION_LIMIT: usize = 64;

/// The largest rendered subject.
pub const MAXIMUM_SUBJECT_BYTES: usize = 512;
/// The largest rendered text part, email or SMS.
pub const MAXIMUM_TEXT_BYTES: usize = 64 * 1024;
/// The largest rendered HTML part.
pub const MAXIMUM_HTML_BYTES: usize = 256 * 1024;

/// A part of a message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartKind {
    Subject,
    Text,
    Html,
}

impl PartKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Text => "text",
            Self::Html => "html",
        }
    }

    /// The template file holding this part in a locale directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Subject => "subject.j2",
            Self::Text => "text.j2",
            Self::Html => "html.j2",
        }
    }

    /// The rendered byte ceiling.
    #[must_use]
    pub const fn ceiling(self) -> usize {
        match self {
            Self::Subject => MAXIMUM_SUBJECT_BYTES,
            Self::Text => MAXIMUM_TEXT_BYTES,
            Self::Html => MAXIMUM_HTML_BYTES,
        }
    }
}

/// Why one part could not be rendered. The engine's own message is kept out:
/// it can quote template source and data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderFailure {
    /// The template read a value the data does not define.
    Undefined,
    /// The template ran out of fuel.
    FuelExhausted,
    /// The rendered part outgrew its ceiling.
    TooLarge,
    /// Any other evaluation failure: a type error, a bad filter argument, a
    /// formatting filter given a value it cannot format.
    Failed,
}

impl RenderFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undefined => "undefined-value",
            Self::FuelExhausted => "fuel-exhausted",
            Self::TooLarge => "output-too-large",
            Self::Failed => "evaluation-failed",
        }
    }
}

/// Check that `source` parses as a template. The engine's message names the
/// line of an author's own file, which is safe to report to that author.
pub fn check_syntax(source: &str) -> Result<(), String> {
    let environment = environment(PartKind::Text, LocaleStyle::Iso);
    environment
        .template_from_str(source)
        .map(|_| ())
        .map_err(|error| {
            let line = error
                .line()
                .map_or_else(String::new, |line| format!(" at line {line}"));
            format!("{}{line}", error.kind())
        })
}

/// Render one part with `data` as the root context, in `locale`.
pub fn render_part(
    kind: PartKind,
    source: &str,
    data: &serde_json::Value,
    locale: &str,
) -> Result<String, RenderFailure> {
    let environment = environment(kind, LocaleStyle::for_locale(locale));
    let template = environment
        .template_from_str(source)
        .map_err(|_| RenderFailure::Failed)?;
    let mut output = BoundedOutput::new(kind.ceiling());
    let rendered = template.render_captured_to(Value::from_serialize(data), &mut output);
    if output.exceeded {
        return Err(RenderFailure::TooLarge);
    }
    if let Err(error) = rendered {
        return Err(match error.kind() {
            ErrorKind::UndefinedError => RenderFailure::Undefined,
            ErrorKind::OutOfFuel => RenderFailure::FuelExhausted,
            _ => RenderFailure::Failed,
        });
    }
    let text = String::from_utf8(output.bytes).map_err(|_| RenderFailure::Failed)?;
    Ok(finish_part(kind, &text))
}

/// Apply the part's character rule to finished content, rendered or direct.
#[must_use]
pub fn finish_part(kind: PartKind, text: &str) -> String {
    match kind {
        PartKind::Html => text.to_owned(),
        PartKind::Text => text
            .chars()
            .filter(|character| *character == '\n' || !character.is_control())
            .collect(),
        PartKind::Subject => text
            .chars()
            .filter(|character| !character.is_control())
            .collect(),
    }
}

fn environment(kind: PartKind, style: LocaleStyle) -> Environment<'static> {
    let mut environment = Environment::empty();
    environment.set_undefined_behavior(UndefinedBehavior::Strict);
    environment.set_fuel(Some(RENDER_FUEL));
    environment.set_recursion_limit(RENDER_RECURSION_LIMIT);
    environment.add_test("defined", minijinja::tests::is_defined);
    environment.add_test("undefined", minijinja::tests::is_undefined);
    environment.add_test("none", minijinja::tests::is_none);
    environment.add_filter("date", move |value: Value| format_date(&value, style));
    environment.add_filter("number", move |value: Value, decimals: Option<u8>| {
        format_number(&value, decimals.unwrap_or(0), style)
    });
    // The formatter owns escaping, so an `autoescape` block in a template
    // cannot turn it off for an HTML part.
    let escape = kind == PartKind::Html;
    environment.set_formatter(move |output, _state, value| {
        // A null prints nothing a reader could want, so it is refused like
        // an undefined value instead of printing `none`.
        if value.is_none() {
            return Err(Error::new(
                ErrorKind::UndefinedError,
                "a null value cannot be printed",
            ));
        }
        if escape {
            write!(output, "{}", HtmlEscape(&value.to_string())).map_err(Error::from)
        } else {
            write!(output, "{value}").map_err(Error::from)
        }
    });
    environment
}

/// A writer that refuses to grow past its ceiling.
struct BoundedOutput {
    bytes: Vec<u8>,
    ceiling: usize,
    exceeded: bool,
}

impl BoundedOutput {
    fn new(ceiling: usize) -> Self {
        Self {
            bytes: Vec::new(),
            ceiling,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + buffer.len() > self.ceiling {
            self.exceeded = true;
            return Err(std::io::Error::other("the part exceeds its ceiling"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How the closed formatting filters write dates and numbers for a locale.
/// The table is deliberately small: a locale it does not name formats
/// dates as ISO 8601 and numbers without grouping, which is unambiguous in
/// every language.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocaleStyle {
    /// `2026-09-24`, `1234567.5`.
    Iso,
    /// `09/24/2026`, `1,234,567.5` (`en-US`).
    UnitedStates,
    /// `24/09/2026`, `1,234,567.5` (other `en`).
    English,
    /// `24/09/2026`, `1 234 567,5` with narrow no-break spaces (`fr`).
    French,
    /// `24.09.2026`, `1.234.567,5` (`de`).
    German,
    /// `24/09/2026`, `1.234.567,5` (`es`, `it`, `pt`).
    Romance,
}

impl LocaleStyle {
    #[must_use]
    pub fn for_locale(locale: &str) -> Self {
        let mut subtags = locale.split('-');
        let language = subtags.next().unwrap_or_default();
        let region = subtags.find(|subtag| subtag.len() == 2 || subtag.len() == 3);
        match (language, region) {
            ("en", Some("US")) => Self::UnitedStates,
            ("en", _) => Self::English,
            ("fr", _) => Self::French,
            ("de", _) => Self::German,
            ("es" | "it" | "pt", _) => Self::Romance,
            _ => Self::Iso,
        }
    }

    const fn separators(self) -> (Option<char>, char) {
        match self {
            Self::Iso => (None, '.'),
            Self::UnitedStates | Self::English => (Some(','), '.'),
            Self::French => (Some('\u{202f}'), ','),
            Self::German | Self::Romance => (Some('.'), ','),
        }
    }
}

fn formatting_error(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message)
}

/// Format a calendar date written `YYYY-MM-DD`. A date-time is refused: the
/// filter never converts time zones, so it formats only what it cannot
/// misread.
fn format_date(value: &Value, style: LocaleStyle) -> Result<String, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| formatting_error("date expects a YYYY-MM-DD string"))?;
    let (year, month, day) =
        parse_date(text).ok_or_else(|| formatting_error("date expects a YYYY-MM-DD string"))?;
    Ok(match style {
        LocaleStyle::Iso => format!("{year:04}-{month:02}-{day:02}"),
        LocaleStyle::UnitedStates => format!("{month:02}/{day:02}/{year:04}"),
        LocaleStyle::English | LocaleStyle::French | LocaleStyle::Romance => {
            format!("{day:02}/{month:02}/{year:04}")
        }
        LocaleStyle::German => format!("{day:02}.{month:02}.{year:04}"),
    })
}

fn parse_date(text: &str) -> Option<(u16, u8, u8)> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u16> {
        let digits = &text[range];
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let year = number(0..4)?;
    let month = u8::try_from(number(5..7)?).ok()?;
    let day = u8::try_from(number(8..10)?).ok()?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (1..=days).contains(&day).then_some((year, month, day))
}

/// The most fraction digits `number` writes.
pub const MAXIMUM_NUMBER_DECIMALS: u8 = 6;

/// Format a number with the locale's grouping and decimal separators.
/// Integers print exactly; a fractional value is rounded to `decimals`.
fn format_number(value: &Value, decimals: u8, style: LocaleStyle) -> Result<String, Error> {
    if decimals > MAXIMUM_NUMBER_DECIMALS {
        return Err(formatting_error("number accepts at most 6 decimals"));
    }
    if value.kind() != ValueKind::Number {
        return Err(formatting_error("number expects a number"));
    }
    let plain = if let Ok(integer) = i64::try_from(value.clone()) {
        if decimals == 0 {
            integer.to_string()
        } else {
            format!("{integer}.{}", "0".repeat(usize::from(decimals)))
        }
    } else {
        let float = f64::try_from(value.clone())
            .map_err(|_| formatting_error("number expects a number"))?;
        if !float.is_finite() {
            return Err(formatting_error("number expects a finite number"));
        }
        format!("{float:.*}", usize::from(decimals))
    };
    let (group, decimal) = style.separators();
    let (sign, unsigned) = plain
        .strip_prefix('-')
        .map_or(("", plain.as_str()), |rest| ("-", rest));
    let (whole, fraction) = unsigned
        .split_once('.')
        .map_or((unsigned, None), |(whole, fraction)| {
            (whole, Some(fraction))
        });
    let mut formatted = String::from(sign);
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            if let Some(group) = group {
                formatted.push(group);
            }
        }
        formatted.push(digit);
    }
    if let Some(fraction) = fraction {
        formatted.push(decimal);
        formatted.push_str(fraction);
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(
        kind: PartKind,
        source: &str,
        data: serde_json::Value,
    ) -> Result<String, RenderFailure> {
        render_part(kind, source, &data, "en")
    }

    #[test]
    fn data_renders_into_the_template() {
        assert_eq!(
            render(
                PartKind::Text,
                "Hello {{ name }}, {% for item in items %}{{ item }};{% endfor %}",
                json!({"name": "Ada", "items": [1, 2]})
            ),
            Ok("Hello Ada, 1;2;".to_owned())
        );
    }

    #[test]
    fn an_undefined_value_is_refused_not_rendered_empty() {
        assert_eq!(
            render(PartKind::Text, "Hello {{ nmae }}", json!({"name": "Ada"})),
            Err(RenderFailure::Undefined)
        );
        assert_eq!(
            render(
                PartKind::Text,
                "{{ person.missing }}",
                json!({"person": {}})
            ),
            Err(RenderFailure::Undefined)
        );
        assert_eq!(
            render(
                PartKind::Text,
                "{% if nickname is defined %}{{ nickname }}{% else %}friend{% endif %}",
                json!({})
            ),
            Ok("friend".to_owned())
        );
    }

    #[test]
    fn a_runaway_template_runs_out_of_fuel() {
        let items: Vec<u32> = (0..1000).collect();
        assert_eq!(
            render(
                PartKind::Text,
                "{% for a in items %}{% for b in items %}{% endfor %}{% endfor %}",
                json!({"items": items})
            ),
            Err(RenderFailure::FuelExhausted)
        );
    }

    #[test]
    fn a_part_that_outgrows_its_ceiling_is_refused() {
        let long = "x".repeat(MAXIMUM_SUBJECT_BYTES + 1);
        assert_eq!(
            render(PartKind::Subject, "{{ value }}", json!({"value": long})),
            Err(RenderFailure::TooLarge)
        );
        let fits = "x".repeat(MAXIMUM_SUBJECT_BYTES);
        assert_eq!(
            render(
                PartKind::Subject,
                "{{ value }}",
                json!({"value": fits.clone()})
            ),
            Ok(fits)
        );
        let items: Vec<u32> = (0..300).collect();
        assert_eq!(
            render(
                PartKind::Text,
                &format!("{{% for i in items %}}{}{{% endfor %}}", "y".repeat(256)),
                json!({"items": items})
            ),
            Err(RenderFailure::TooLarge)
        );
    }

    #[test]
    fn html_parts_escape_every_value_and_cannot_opt_out() {
        let data = json!({"name": "<script>alert(\"x\")</script>&'"});
        let escaped = "&lt;script&gt;alert(&quot;x&quot;)&lt;&#x2f;script&gt;&amp;&#x27;";
        assert_eq!(
            render(PartKind::Html, "<p>{{ name }}</p>", data.clone()),
            Ok(format!("<p>{escaped}</p>"))
        );
        assert_eq!(
            render(
                PartKind::Html,
                "{% autoescape false %}{{ name }}{% endautoescape %}",
                data.clone()
            ),
            Ok(escaped.to_owned())
        );
        assert_eq!(
            render(PartKind::Html, "{{ name|safe }}", data.clone()),
            Err(RenderFailure::Failed)
        );
        assert_eq!(
            render(PartKind::Html, "{{ name|e }}", data.clone()),
            Err(RenderFailure::Failed)
        );
        // Text parts do not escape.
        assert_eq!(
            render(PartKind::Text, "{{ name }}", data),
            Ok("<script>alert(\"x\")</script>&'".to_owned())
        );
    }

    #[test]
    fn text_parts_strip_control_characters_but_keep_newlines() {
        let data = json!({"value": "a\u{0}b\u{7}c\td\re\u{1b}[31m\nf\u{85}g"});
        assert_eq!(
            render(PartKind::Text, "{{ value }}\nend", data.clone()),
            Ok("abcde[31m\nfg\nend".to_owned())
        );
        assert_eq!(
            render(PartKind::Subject, "Re: {{ value }}", data),
            Ok("Re: abcde[31mfg".to_owned())
        );
        assert_eq!(
            render(
                PartKind::Subject,
                "Hello {{ name }}",
                json!({"name": "x\r\nBcc: victim@example.org"})
            ),
            Ok("Hello xBcc: victim@example.org".to_owned())
        );
    }

    #[test]
    fn the_environment_offers_no_loader_function_or_builtin_filter() {
        for source in [
            "{% include 'other.j2' %}",
            "{% extends 'base.j2' %}",
            "{% import 'macros.j2' as m %}",
            "{% macro x() %}{% endmacro %}",
            "{{ range(10) }}",
            "{{ debug() }}",
            "{{ name|upper }}",
            "{{ name|default('x') }}",
            "{% filter upper %}x{% endfilter %}",
        ] {
            let outcome = render(PartKind::Text, source, json!({"name": "Ada"}));
            assert!(outcome.is_err(), "{source}: {outcome:?}");
        }
    }

    #[test]
    fn a_null_value_is_refused_like_an_undefined_one() {
        assert_eq!(
            render(PartKind::Text, "Hello {{ name }}", json!({"name": null})),
            Err(RenderFailure::Undefined)
        );
        assert_eq!(
            render(
                PartKind::Text,
                "{% if name is none %}friend{% endif %}",
                json!({"name": null})
            ),
            Ok("friend".to_owned())
        );
    }

    #[test]
    fn syntax_errors_are_reported_with_their_line() {
        assert_eq!(check_syntax("Hello {{ name }}"), Ok(()));
        let error = check_syntax("line one\n{% if %}").unwrap_err();
        assert!(error.contains("line 2"), "{error}");
    }

    #[test]
    fn the_date_filter_formats_calendar_dates_for_the_locale() {
        let data = json!({"day": "2026-09-04"});
        for (locale, expected) in [
            ("en-US", "09/04/2026"),
            ("en", "04/09/2026"),
            ("en-GB", "04/09/2026"),
            ("fr", "04/09/2026"),
            ("de-CH", "04.09.2026"),
            ("pt-BR", "04/09/2026"),
            ("sw", "2026-09-04"),
        ] {
            assert_eq!(
                render_part(PartKind::Text, "{{ day|date }}", &data, locale),
                Ok(expected.to_owned()),
                "{locale}"
            );
        }
        for refused in [
            json!("2026-02-30"),
            json!("2026-13-01"),
            json!("2026-09-04T10:00:00Z"),
            json!("04/09/2026"),
            json!(20260904),
        ] {
            assert_eq!(
                render(PartKind::Text, "{{ day|date }}", json!({"day": refused})),
                Err(RenderFailure::Failed)
            );
        }
        assert_eq!(
            render(
                PartKind::Text,
                "{{ day|date }}",
                json!({"day": "2024-02-29"})
            ),
            Ok("29/02/2024".to_owned())
        );
    }

    #[test]
    fn the_number_filter_groups_and_rounds_for_the_locale() {
        let data = json!({"count": 1_234_567, "amount": -1234.565, "small": 12});
        for (locale, source, expected) in [
            ("en", "{{ count|number }}", "1,234,567"),
            ("en", "{{ count|number(2) }}", "1,234,567.00"),
            ("en", "{{ small|number }}", "12"),
            ("fr", "{{ count|number }}", "1\u{202f}234\u{202f}567"),
            ("de", "{{ amount|number(1) }}", "-1.234,6"),
            ("es", "{{ count|number }}", "1.234.567"),
            ("sw", "{{ count|number }}", "1234567"),
            ("en-US", "{{ amount|number(2) }}", "-1,234.57"),
        ] {
            assert_eq!(
                render_part(PartKind::Text, source, &data, locale),
                Ok(expected.to_owned()),
                "{locale} {source}"
            );
        }
        for source in [
            "{{ 'x'|number }}",
            "{{ true|number }}",
            "{{ small|number(7) }}",
        ] {
            assert_eq!(
                render(PartKind::Text, source, data.clone()),
                Err(RenderFailure::Failed),
                "{source}"
            );
        }
    }
}
