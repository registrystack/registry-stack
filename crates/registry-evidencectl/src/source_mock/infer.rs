// SPDX-License-Identifier: Apache-2.0
//! Conservative, versioned generator inference from OpenAPI property names.

use serde_json::{Map, Value};

pub(crate) const INFERENCE_REGISTRY_ID: &str = "field-inference-v1";
const LEAF_SCORE: u8 = 100;
const CONTEXT_SCORE: u8 = 80;
const MINIMUM_SCORE: u8 = 80;

/// A closed inferred recipe. These identifiers are owned by evidencectl rather
/// than reflected from `fake-rs` symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InferredRecipe {
    Faker(&'static str),
    Format(&'static str),
    Age { min: u16, max: u16 },
}

impl InferredRecipe {
    #[must_use]
    pub(crate) fn id(self) -> String {
        match self {
            Self::Faker(kind) => format!("faker:{kind}"),
            Self::Format(kind) => format!("format:{kind}"),
            Self::Age { min, max } => format!("distribution:age:{min}:{max}"),
        }
    }
}

/// Why field-name inference deliberately selected the generic fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InferenceFallback {
    NonAsciiProperty,
    NoWholeTokenRule,
    IncompatibleSchema,
    AmbiguousHighestScore,
    GeneratorCouldNotSatisfySchema,
}

impl InferenceFallback {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NonAsciiProperty => "non-ascii-property",
            Self::NoWholeTokenRule => "no-whole-token-rule",
            Self::IncompatibleSchema => "incompatible-schema",
            Self::AmbiguousHighestScore => "ambiguous-highest-score",
            Self::GeneratorCouldNotSatisfySchema => "generator-could-not-satisfy-schema",
        }
    }
}

/// A value-free explanation of one inference decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferenceDecision {
    pub(crate) property_key: String,
    pub(crate) rule_id: Option<&'static str>,
    pub(crate) score: Option<u8>,
    pub(crate) recipe: Option<InferredRecipe>,
    pub(crate) fallback: Option<InferenceFallback>,
}

impl InferenceDecision {
    #[must_use]
    pub(crate) fn selected(&self) -> bool {
        self.recipe.is_some()
    }

    #[must_use]
    pub(crate) fn seed_identifier(&self) -> Option<String> {
        Some(format!(
            "inferred:{INFERENCE_REGISTRY_ID}:{}:{}",
            self.rule_id?,
            self.recipe?.id()
        ))
    }

    pub(crate) fn record_generator_fallback(&mut self) {
        self.fallback = Some(InferenceFallback::GeneratorCouldNotSatisfySchema);
    }

    fn fallback(property_key: &str, reason: InferenceFallback) -> Self {
        Self {
            property_key: property_key.to_owned(),
            rule_id: None,
            score: None,
            recipe: None,
            fallback: Some(reason),
        }
    }
}

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    aliases: &'static [&'static str],
    context: Context,
    recipe: InferredRecipe,
    accepted_formats: &'static [&'static str],
    score: u8,
}

#[derive(Clone, Copy)]
enum Context {
    Any,
    Parent(&'static [&'static str]),
}

const NO_FORMAT: &[&str] = &[];
const EMAIL_FORMAT: &[&str] = &["email"];
const DATE_FORMAT: &[&str] = &["date"];
const DATE_TIME_FORMAT: &[&str] = &["date-time"];
const URI_FORMAT: &[&str] = &["uri", "url"];
const HOSTNAME_FORMAT: &[&str] = &["hostname"];
const IPV4_FORMAT: &[&str] = &["ipv4"];
const IPV6_FORMAT: &[&str] = &["ipv6"];

const PERSON_PARENTS: &[&str] = &["person", "user", "applicant", "member", "contact"];
const COMPANY_PARENTS: &[&str] = &["company", "organization", "organisation", "employer"];

const RULES: &[Rule] = &[
    Rule {
        id: "field.first-name.v1",
        aliases: &[
            "first name",
            "firstname",
            "given name",
            "givenname",
            "forename",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Faker("person.firstName"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.last-name.v1",
        aliases: &[
            "last name",
            "lastname",
            "family name",
            "familyname",
            "surname",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Faker("person.lastName"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.full-name.v1",
        aliases: &["full name", "fullname"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("person.fullName"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.email.v1",
        aliases: &["email", "e mail", "email address", "emailaddress"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("internet.safeEmail"),
        accepted_formats: EMAIL_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.username.v1",
        aliases: &["username", "user name"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("internet.username"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.phone.v1",
        aliases: &[
            "phone",
            "phone number",
            "phone no",
            "phonenumber",
            "mobile",
            "mobile number",
            "mobile no",
            "telephone",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Faker("phone.number"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.city.v1",
        aliases: &["city", "city name", "cityname"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("address.city"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.postal-code.v1",
        aliases: &[
            "postal code",
            "postalcode",
            "post code",
            "postcode",
            "zip code",
            "zipcode",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Faker("address.postalCode"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.country-name.v1",
        aliases: &["country", "country name", "countryname"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("address.countryName"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.country-code.v1",
        aliases: &["country code", "countrycode", "iso country code"],
        context: Context::Any,
        recipe: InferredRecipe::Faker("address.countryCode"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.company-name.v1",
        aliases: &[
            "company name",
            "companyname",
            "organization name",
            "organisation name",
            "employer name",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Faker("company.name"),
        accepted_formats: NO_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.birth-date.v1",
        aliases: &[
            "date of birth",
            "dateofbirth",
            "birth date",
            "birthdate",
            "dob",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Age { min: 0, max: 100 },
        accepted_formats: DATE_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.date-time.v1",
        aliases: &[
            "created at",
            "createdat",
            "updated at",
            "updatedat",
            "modified at",
            "modifiedat",
            "timestamp",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Format("date-time"),
        accepted_formats: DATE_TIME_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.url.v1",
        aliases: &[
            "url",
            "uri",
            "website",
            "website url",
            "homepage",
            "homepage url",
        ],
        context: Context::Any,
        recipe: InferredRecipe::Format("uri"),
        accepted_formats: URI_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.hostname.v1",
        aliases: &["hostname", "host name"],
        context: Context::Any,
        recipe: InferredRecipe::Format("hostname"),
        accepted_formats: HOSTNAME_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.ipv4.v1",
        aliases: &["ipv4", "ipv4 address"],
        context: Context::Any,
        recipe: InferredRecipe::Format("ipv4"),
        accepted_formats: IPV4_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "field.ipv6.v1",
        aliases: &["ipv6", "ipv6 address"],
        context: Context::Any,
        recipe: InferredRecipe::Format("ipv6"),
        accepted_formats: IPV6_FORMAT,
        score: LEAF_SCORE,
    },
    Rule {
        id: "context.person-name.v1",
        aliases: &["name"],
        context: Context::Parent(PERSON_PARENTS),
        recipe: InferredRecipe::Faker("person.fullName"),
        accepted_formats: NO_FORMAT,
        score: CONTEXT_SCORE,
    },
    Rule {
        id: "context.company-name.v1",
        aliases: &["name"],
        context: Context::Parent(COMPANY_PARENTS),
        recipe: InferredRecipe::Faker("company.name"),
        accepted_formats: NO_FORMAT,
        score: CONTEXT_SCORE,
    },
];

/// Infer one closed recipe from an object-edge property key.
#[must_use]
pub(crate) fn infer(
    property_key: &str,
    parent_property: Option<&str>,
    schema: &Value,
) -> InferenceDecision {
    let Some(normalized) = normalize(property_key) else {
        return InferenceDecision::fallback(property_key, InferenceFallback::NonAsciiProperty);
    };
    let normalized_parent = parent_property.and_then(normalize);
    let matching: Vec<&Rule> = RULES
        .iter()
        .filter(|rule| rule.aliases.contains(&normalized.as_str()))
        .filter(|rule| context_matches(rule.context, normalized_parent.as_deref()))
        .collect();
    if matching.is_empty() {
        return InferenceDecision::fallback(property_key, InferenceFallback::NoWholeTokenRule);
    }

    let compatible: Vec<&Rule> = matching
        .into_iter()
        .filter(|rule| schema_is_string_compatible(schema, rule.accepted_formats))
        .collect();
    if compatible.is_empty() {
        return InferenceDecision::fallback(property_key, InferenceFallback::IncompatibleSchema);
    }
    let highest = compatible.iter().map(|rule| rule.score).max().unwrap_or(0);
    let winners: Vec<&Rule> = compatible
        .into_iter()
        .filter(|rule| rule.score == highest)
        .collect();
    if highest < MINIMUM_SCORE || winners.len() != 1 {
        return InferenceDecision::fallback(property_key, InferenceFallback::AmbiguousHighestScore);
    }
    let winner = winners[0];
    InferenceDecision {
        property_key: property_key.to_owned(),
        rule_id: Some(winner.id),
        score: Some(winner.score),
        recipe: Some(winner.recipe),
        fallback: None,
    }
}

fn context_matches(context: Context, parent: Option<&str>) -> bool {
    match context {
        Context::Any => true,
        Context::Parent(accepted) => parent.is_some_and(|parent| accepted.contains(&parent)),
    }
}

fn schema_is_string_compatible(schema: &Value, accepted_formats: &[&str]) -> bool {
    let Some(node) = schema.as_object() else {
        return false;
    };
    if has_stronger_intent(node) || has_non_string_constraints(node) {
        return false;
    }
    let string_type = match node.get("type") {
        None => true,
        Some(Value::String(kind)) => kind == "string",
        Some(Value::Array(kinds)) => {
            kinds.len() == 2
                && kinds.iter().any(|kind| kind.as_str() == Some("string"))
                && kinds.iter().any(|kind| kind.as_str() == Some("null"))
        }
        Some(_) => false,
    };
    if !string_type {
        return false;
    }
    match node.get("format") {
        None => true,
        Some(Value::String(format)) => accepted_formats.contains(&format.as_str()),
        Some(_) => false,
    }
}

fn has_stronger_intent(node: &Map<String, Value>) -> bool {
    node.contains_key("const")
        || node.contains_key("enum")
        || node.contains_key("x-evidencectl-mock")
}

fn has_non_string_constraints(node: &Map<String, Value>) -> bool {
    const CONTRADICTORY: &[&str] = &[
        "properties",
        "additionalProperties",
        "minProperties",
        "maxProperties",
        "items",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
    ];
    CONTRADICTORY.iter().any(|key| node.contains_key(*key))
}

fn normalize(value: &str) -> Option<String> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    let mut tokens = Vec::<String>::new();
    let mut current = String::new();
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(byte, b'_' | b'-' | b'.') || byte.is_ascii_whitespace() {
            push_token(&mut tokens, &mut current);
            continue;
        }
        if !byte.is_ascii_alphanumeric() {
            return None;
        }
        let previous = index.checked_sub(1).and_then(|i| bytes.get(i)).copied();
        let next = bytes.get(index + 1).copied();
        let camel_boundary = byte.is_ascii_uppercase()
            && !current.is_empty()
            && (previous.is_some_and(|value| value.is_ascii_lowercase())
                || next.is_some_and(|value| value.is_ascii_lowercase()));
        if camel_boundary {
            push_token(&mut tokens, &mut current);
        }
        current.push((byte as char).to_ascii_lowercase());
    }
    push_token(&mut tokens, &mut current);
    for index in 0..tokens.len().saturating_sub(1) {
        if tokens[index] == "i" && matches!(tokens[index + 1].as_str(), "pv4" | "pv6") {
            let suffix = tokens.remove(index + 1);
            tokens[index].push_str(&suffix);
            break;
        }
    }
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

fn push_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_aliases_cover_camel_acronym_and_separators() {
        for key in ["firstName", "first_name", "first-name", "first.name"] {
            let decision = infer(key, None, &json!({"type": "string"}));
            assert_eq!(decision.rule_id, Some("field.first-name.v1"), "{key}");
        }
        assert_eq!(
            infer(
                "dateOfBirth",
                None,
                &json!({"type": "string", "format": "date"})
            )
            .rule_id,
            Some("field.birth-date.v1")
        );
        assert_eq!(
            infer("DOB", None, &json!({"type": "string"})).rule_id,
            Some("field.birth-date.v1")
        );
        assert_eq!(
            infer("IPv4Address", None, &json!({"type": "string"})).rule_id,
            Some("field.ipv4.v1")
        );
    }

    #[test]
    fn substring_false_friends_do_not_infer_name() {
        for key in ["campaign", "filename", "hostNameSuffix"] {
            let decision = infer(key, None, &json!({"type": "string"}));
            assert_eq!(decision.fallback, Some(InferenceFallback::NoWholeTokenRule));
        }
        assert_eq!(
            infer("username", None, &json!({"type": "string"})).rule_id,
            Some("field.username.v1")
        );
    }

    #[test]
    fn context_name_requires_an_exact_approved_parent() {
        let schema = json!({"type": "string"});
        assert_eq!(
            infer("name", Some("Person"), &schema).rule_id,
            Some("context.person-name.v1")
        );
        assert_eq!(
            infer("name", Some("company_profile"), &schema).fallback,
            Some(InferenceFallback::NoWholeTokenRule)
        );
        assert_eq!(
            infer("name", None, &schema).fallback,
            Some(InferenceFallback::NoWholeTokenRule)
        );
    }

    #[test]
    fn untyped_and_nullable_string_leaves_are_compatible() {
        assert!(infer("email", None, &json!({})).selected());
        assert!(infer("email", None, &json!({"type": ["string", "null"]})).selected());
        assert_eq!(
            infer("email", None, &json!({"type": "integer"})).fallback,
            Some(InferenceFallback::IncompatibleSchema)
        );
        assert_eq!(
            infer("email", None, &json!({"minimum": 1})).fallback,
            Some(InferenceFallback::IncompatibleSchema)
        );
    }

    #[test]
    fn format_and_stronger_intent_filter_candidates() {
        assert!(infer("email", None, &json!({"type": "string", "format": "email"})).selected());
        assert_eq!(
            infer("email", None, &json!({"type": "string", "format": "uuid"})).fallback,
            Some(InferenceFallback::IncompatibleSchema)
        );
        assert_eq!(
            infer("email", None, &json!({"enum": ["a@example.invalid"]})).fallback,
            Some(InferenceFallback::IncompatibleSchema)
        );
    }

    #[test]
    fn mixed_script_keys_are_value_free_fallbacks() {
        let decision = infer("еmail", None, &json!({"type": "string"}));
        assert_eq!(decision.rule_id, None);
        assert_eq!(decision.recipe, None);
        assert_eq!(decision.fallback, Some(InferenceFallback::NonAsciiProperty));
    }

    #[test]
    fn stable_seed_identifier_names_registry_rule_and_recipe() {
        let decision = infer("countryCode", None, &json!({"type": "string"}));
        assert_eq!(
            decision.seed_identifier().as_deref(),
            Some("inferred:field-inference-v1:field.country-code.v1:faker:address.countryCode")
        );
    }
}
