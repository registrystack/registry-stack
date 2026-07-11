//! Bounded input-pattern automata and shared stable-text validation.

use super::*;
#[derive(Clone)]
pub(in super::super) struct BoundedInputPattern {
    atoms: Box<[InputPatternAtom]>,
}

#[derive(Clone)]
struct InputPatternAtom {
    matcher: InputAtomMatcher,
    repetition: InputAtomRepetition,
}

#[derive(Clone, Copy)]
enum InputAtomRepetition {
    Once,
    Optional,
    OneOrMore,
}

#[derive(Clone)]
enum InputAtomMatcher {
    Literal(u8),
    Digit,
    Word,
    Class {
        negated: bool,
        ranges: Box<[(u8, u8)]>,
    },
}

impl BoundedInputPattern {
    pub(in super::super) fn is_match(&self, value: &str) -> bool {
        if !value.is_ascii() || value.len() > usize::from(MAX_INPUT_BYTES) {
            return false;
        }
        let bytes = value.as_bytes();
        let mut positions = vec![false; bytes.len() + 1];
        positions[0] = true;
        for atom in &self.atoms {
            let mut next = vec![false; bytes.len() + 1];
            for (position, reachable) in positions.iter().copied().enumerate() {
                if !reachable {
                    continue;
                }
                match atom.repetition {
                    InputAtomRepetition::Once => {
                        if position < bytes.len() && atom.matcher.matches(bytes[position]) {
                            next[position + 1] = true;
                        }
                    }
                    InputAtomRepetition::Optional => {
                        next[position] = true;
                        if position < bytes.len() && atom.matcher.matches(bytes[position]) {
                            next[position + 1] = true;
                        }
                    }
                    InputAtomRepetition::OneOrMore => {
                        let mut cursor = position;
                        while cursor < bytes.len() && atom.matcher.matches(bytes[cursor]) {
                            cursor += 1;
                            next[cursor] = true;
                        }
                    }
                }
            }
            positions = next;
        }
        positions[bytes.len()]
    }

    pub(in super::super) fn atom_count(&self) -> usize {
        self.atoms.len()
    }
}

impl InputAtomMatcher {
    fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Literal(expected) => byte == *expected,
            Self::Digit => byte.is_ascii_digit(),
            Self::Word => byte.is_ascii_alphanumeric() || byte == b'_',
            Self::Class { negated, ranges } => {
                let contained = ranges
                    .iter()
                    .any(|(from, to)| (*from..=*to).contains(&byte));
                contained != *negated
            }
        }
    }
}

pub(super) fn validate_input_pattern(pattern: &str) -> Result<(), SourcePlanArtifactError> {
    parse_input_pattern(pattern).map(|_| ())
}

pub(in super::super) fn parse_input_pattern(
    pattern: &str,
) -> Result<BoundedInputPattern, SourcePlanArtifactError> {
    let Some(inner) = pattern
        .strip_prefix('^')
        .and_then(|value| value.strip_suffix('$'))
    else {
        return Err(SourcePlanArtifactError::InvalidExpression);
    };
    if inner.is_empty() || !inner.is_ascii() {
        return Err(SourcePlanArtifactError::InvalidExpression);
    }

    let bytes = inner.as_bytes();
    let mut index = 0_usize;
    let mut atoms = Vec::new();
    let mut can_quantify = false;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => {
                let matcher = parse_input_class(bytes, &mut index)?;
                atoms.push(InputPatternAtom {
                    matcher,
                    repetition: InputAtomRepetition::Once,
                });
                can_quantify = true;
            }
            b'\\' => {
                index += 1;
                if index == bytes.len()
                    || !matches!(
                        bytes[index],
                        b'd' | b'w' | b'-' | b'.' | b'_' | b':' | b'\\'
                    )
                {
                    return Err(SourcePlanArtifactError::InvalidExpression);
                }
                let matcher = match bytes[index] {
                    b'd' => InputAtomMatcher::Digit,
                    b'w' => InputAtomMatcher::Word,
                    literal => InputAtomMatcher::Literal(literal),
                };
                index += 1;
                atoms.push(InputPatternAtom {
                    matcher,
                    repetition: InputAtomRepetition::Once,
                });
                can_quantify = true;
            }
            b'+' | b'?' if can_quantify => {
                let atom = atoms
                    .last_mut()
                    .ok_or(SourcePlanArtifactError::InvalidExpression)?;
                atom.repetition = if bytes[index] == b'+' {
                    InputAtomRepetition::OneOrMore
                } else {
                    InputAtomRepetition::Optional
                };
                index += 1;
                can_quantify = false;
            }
            b'*' | b'|' | b'(' | b')' | b'{' | b'}' | b'^' | b'$' | b']' => {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            byte if byte.is_ascii_control() => {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            literal => {
                index += 1;
                atoms.push(InputPatternAtom {
                    matcher: InputAtomMatcher::Literal(literal),
                    repetition: InputAtomRepetition::Once,
                });
                can_quantify = true;
            }
        }
        if atoms.len() > MAX_INPUT_PATTERN_ATOMS {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
    }
    if atoms.is_empty() {
        return Err(SourcePlanArtifactError::InvalidExpression);
    }
    Ok(BoundedInputPattern {
        atoms: atoms.into_boxed_slice(),
    })
}

fn parse_input_class(
    pattern: &[u8],
    index: &mut usize,
) -> Result<InputAtomMatcher, SourcePlanArtifactError> {
    *index += 1;
    let negated = pattern.get(*index) == Some(&b'^');
    *index += usize::from(negated);
    let mut ranges = Vec::new();
    while pattern.get(*index).is_some_and(|byte| *byte != b']') {
        let ParsedInputClassUnit {
            ranges: mut unit_ranges,
            single,
        } = parse_input_class_unit(pattern, index)?;
        if single.is_some()
            && pattern.get(*index) == Some(&b'-')
            && pattern.get(*index + 1).is_some_and(|byte| *byte != b']')
        {
            let from = single.ok_or(SourcePlanArtifactError::InvalidExpression)?;
            *index += 1;
            let ParsedInputClassUnit {
                ranges: to_ranges,
                single: to_single,
            } = parse_input_class_unit(pattern, index)?;
            let to = to_single.ok_or(SourcePlanArtifactError::InvalidExpression)?;
            if !unit_ranges.is_empty() || !to_ranges.is_empty() || from > to {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            ranges.push((from, to));
        } else if let Some(byte) = single {
            ranges.push((byte, byte));
        } else {
            ranges.append(&mut unit_ranges);
        }
        if ranges.len() > MAX_INPUT_CLASS_RANGES {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
    }
    if pattern.get(*index) != Some(&b']') || ranges.is_empty() {
        return Err(SourcePlanArtifactError::InvalidExpression);
    }
    *index += 1;
    ranges.sort_unstable();
    Ok(InputAtomMatcher::Class {
        negated,
        ranges: ranges.into_boxed_slice(),
    })
}

struct ParsedInputClassUnit {
    ranges: Vec<(u8, u8)>,
    single: Option<u8>,
}

fn parse_input_class_unit(
    pattern: &[u8],
    index: &mut usize,
) -> Result<ParsedInputClassUnit, SourcePlanArtifactError> {
    let byte = *pattern
        .get(*index)
        .ok_or(SourcePlanArtifactError::InvalidExpression)?;
    if byte == b'\\' {
        *index += 1;
        let escaped = *pattern
            .get(*index)
            .ok_or(SourcePlanArtifactError::InvalidExpression)?;
        *index += 1;
        return match escaped {
            b'd' => Ok(ParsedInputClassUnit {
                ranges: vec![(b'0', b'9')],
                single: None,
            }),
            b'w' => Ok(ParsedInputClassUnit {
                ranges: vec![(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')],
                single: None,
            }),
            b'-' | b'.' | b'_' | b':' | b'\\' | b']' => Ok(ParsedInputClassUnit {
                ranges: Vec::new(),
                single: Some(escaped),
            }),
            _ => Err(SourcePlanArtifactError::InvalidExpression),
        };
    }
    if byte.is_ascii_control() || matches!(byte, b'[' | b'^') {
        return Err(SourcePlanArtifactError::InvalidExpression);
    }
    *index += 1;
    Ok(ParsedInputClassUnit {
        ranges: Vec::new(),
        single: Some(byte),
    })
}

pub(super) fn validate_stable_text(value: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = value.bytes();
    let valid = matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'
            )
        });
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_query_name(value: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = value.bytes();
    let valid = matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z'))
        && value.len() <= 96
        && bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'-'
            )
        });
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
) -> Result<(), SourcePlanArtifactError> {
    let valid =
        !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control);
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_token(value: &str, max_bytes: usize) -> Result<(), SourcePlanArtifactError> {
    let valid = !value.is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "token",
        "credential",
        "private_key",
        "api_key",
        "authorization",
    ]
    .iter()
    .any(|sensitive| name.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_name_grammar_preserves_colons_and_accepts_product_camel_case() {
        for valid in [
            "orgUnitMode",
            "pageSize",
            "trackedEntity",
            "selector:subject",
            "XTrace",
        ] {
            assert_eq!(validate_query_name(valid), Ok(()), "rejected {valid:?}");
        }
        assert_eq!(validate_query_name(&"a".repeat(96)), Ok(()));
    }

    #[test]
    fn query_name_grammar_rejects_delimiters_controls_and_oversized_names() {
        for invalid in ["", "a&b", "a=b", "a%b", "a\n", "a\0"] {
            assert_eq!(
                validate_query_name(invalid),
                Err(SourcePlanArtifactError::InvalidText),
                "accepted {invalid:?}"
            );
        }
        assert_eq!(
            validate_query_name(&"a".repeat(97)),
            Err(SourcePlanArtifactError::InvalidText)
        );
    }
}
