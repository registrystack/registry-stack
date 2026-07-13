// SPDX-License-Identifier: Apache-2.0
//! Bounded automaton for Relay consultation-v1 input patterns.

use thiserror::Error;

/// Maximum encoded pattern size accepted by consultation v1.
pub const MAX_BOUNDED_INPUT_PATTERN_BYTES: usize = 1_024;
/// Maximum input size accepted by consultation v1.
pub const MAX_BOUNDED_INPUT_BYTES: u32 = 65_536;
const MAX_INPUT_PATTERN_ATOMS: usize = 128;
const MAX_INPUT_CLASS_RANGES: usize = 64;

/// A compiled, allocation-bounded consultation input matcher.
#[derive(Clone)]
pub struct BoundedInputPattern {
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

/// Value-free bounded-pattern compilation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BoundedInputPatternError {
    /// The pattern is outside the consultation-v1 grammar.
    #[error("bounded input pattern has an invalid expression")]
    InvalidExpression,
    /// The pattern exceeds a consultation-v1 complexity ceiling.
    #[error("bounded input pattern exceeds a complexity limit")]
    LimitExceeded,
}

impl BoundedInputPattern {
    /// Compile the exact anchored consultation-v1 grammar.
    pub fn compile(pattern: &str) -> Result<Self, BoundedInputPatternError> {
        if pattern.len() > MAX_BOUNDED_INPUT_PATTERN_BYTES {
            return Err(BoundedInputPatternError::LimitExceeded);
        }
        let Some(inner) = pattern
            .strip_prefix('^')
            .and_then(|value| value.strip_suffix('$'))
        else {
            return Err(BoundedInputPatternError::InvalidExpression);
        };
        if inner.is_empty() || !inner.is_ascii() {
            return Err(BoundedInputPatternError::InvalidExpression);
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
                        return Err(BoundedInputPatternError::InvalidExpression);
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
                        .ok_or(BoundedInputPatternError::InvalidExpression)?;
                    atom.repetition = if bytes[index] == b'+' {
                        InputAtomRepetition::OneOrMore
                    } else {
                        InputAtomRepetition::Optional
                    };
                    index += 1;
                    can_quantify = false;
                }
                b'*' | b'|' | b'(' | b')' | b'{' | b'}' | b'^' | b'$' | b']' => {
                    return Err(BoundedInputPatternError::InvalidExpression);
                }
                byte if byte.is_ascii_control() => {
                    return Err(BoundedInputPatternError::InvalidExpression);
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
                return Err(BoundedInputPatternError::LimitExceeded);
            }
        }
        if atoms.is_empty() {
            return Err(BoundedInputPatternError::InvalidExpression);
        }
        Ok(Self {
            atoms: atoms.into_boxed_slice(),
        })
    }

    /// Match one complete ASCII input without backtracking.
    #[must_use]
    pub fn is_match(&self, value: &str) -> bool {
        if !value.is_ascii() || value.len() > MAX_BOUNDED_INPUT_BYTES as usize {
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

    /// Number of compiled automaton atoms, excluding anchors.
    #[must_use]
    pub fn atom_count(&self) -> usize {
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

fn parse_input_class(
    pattern: &[u8],
    index: &mut usize,
) -> Result<InputAtomMatcher, BoundedInputPatternError> {
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
            let from = single.ok_or(BoundedInputPatternError::InvalidExpression)?;
            *index += 1;
            let ParsedInputClassUnit {
                ranges: to_ranges,
                single: to_single,
            } = parse_input_class_unit(pattern, index)?;
            let to = to_single.ok_or(BoundedInputPatternError::InvalidExpression)?;
            if !unit_ranges.is_empty() || !to_ranges.is_empty() || from > to {
                return Err(BoundedInputPatternError::InvalidExpression);
            }
            ranges.push((from, to));
        } else if let Some(byte) = single {
            ranges.push((byte, byte));
        } else {
            ranges.append(&mut unit_ranges);
        }
        if ranges.len() > MAX_INPUT_CLASS_RANGES {
            return Err(BoundedInputPatternError::LimitExceeded);
        }
    }
    if pattern.get(*index) != Some(&b']') || ranges.is_empty() {
        return Err(BoundedInputPatternError::InvalidExpression);
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
) -> Result<ParsedInputClassUnit, BoundedInputPatternError> {
    let byte = *pattern
        .get(*index)
        .ok_or(BoundedInputPatternError::InvalidExpression)?;
    if byte == b'\\' {
        *index += 1;
        let escaped = *pattern
            .get(*index)
            .ok_or(BoundedInputPatternError::InvalidExpression)?;
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
            _ => Err(BoundedInputPatternError::InvalidExpression),
        };
    }
    if byte.is_ascii_control() || matches!(byte, b'[' | b'^') {
        return Err(BoundedInputPatternError::InvalidExpression);
    }
    *index += 1;
    Ok(ParsedInputClassUnit {
        ranges: Vec::new(),
        single: Some(byte),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consultation_v1_pattern_semantics_are_exact() {
        let pattern =
            BoundedInputPattern::compile(r"^[A-Z]?\d+[._:-]$").expect("bounded pattern compiles");
        assert_eq!(pattern.atom_count(), 3);
        for matching in ["A12_", "12-", "Z0:"] {
            assert!(pattern.is_match(matching));
        }
        for rejected in ["a12_", "A_", "12", "A12__", "é12_"] {
            assert!(!pattern.is_match(rejected));
        }
    }

    #[test]
    fn consultation_v1_pattern_rejects_unbounded_or_unsupported_grammar() {
        for invalid in ["a", "^$", "^a*$", "^(a+)+$", "^a|b$"] {
            assert_eq!(
                BoundedInputPattern::compile(invalid).err(),
                Some(BoundedInputPatternError::InvalidExpression)
            );
        }
        assert_eq!(
            BoundedInputPattern::compile(&format!("^{}$", "a".repeat(129))).err(),
            Some(BoundedInputPatternError::LimitExceeded)
        );
    }

    #[test]
    fn patterned_input_accepts_the_authored_max_length_ceiling() {
        let pattern = BoundedInputPattern::compile("^a+$").expect("bounded pattern compiles");
        assert!(pattern.is_match(&"a".repeat(16_384)));
        assert!(!pattern.is_match(&"a".repeat(MAX_BOUNDED_INPUT_BYTES as usize + 1)));
    }
}
