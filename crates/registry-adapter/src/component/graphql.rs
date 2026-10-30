// SPDX-License-Identifier: Apache-2.0

//! The `graphql` producer (`products/adapter/CONCEPT.md` section 8.8):
//! Camel's `camel-graphql` shape over the same transport as `http`. One
//! endpoint carries one digest-pinned `queryFile`, one `operationName`,
//! and one `variables` expression; a send posts the query text with the
//! operation name and the evaluated variables, the reply's `data` member
//! becomes the exchange body, and a GraphQL `errors` array fails the
//! exchange (`upstream.http`, with the declared detail only).
//!
//! The full document parse stays with `adapterctl verify`, which names
//! the operations the file declares; the engine holds the same line at
//! load with a bounded scan, so no runtime dependency is added for it.

use std::path::Path;

use registry_adapter_core::{AdapterPack, Endpoint, Expression};
use registry_platform_config::sha256_uri;
use thiserror::Error;

/// The largest query file the engine reads, the script profile's source
/// ceiling (`crate::scripts::SCRIPT_PROFILE`): a reviewed pack holds
/// documents well under it, and nothing larger is read into memory.
pub(crate) const MAXIMUM_QUERY_FILE_BYTES: usize = 65_536;

/// Why a graphql endpoint's query could not be loaded. Every text is
/// fixed and value-free apart from the file path the pack itself names.
#[derive(Debug, Error)]
pub enum GraphQlLoadError {
    #[error("the query file {0} is not in the pack's digest-pinned inventory")]
    NotInventoried(String),
    #[error("the query file {0} could not be read")]
    Unreadable(String),
    #[error("the query file {0} is over the engine's bound")]
    TooLarge(String),
    #[error("the query file {0} does not match its pinned digest")]
    DigestMismatch(String),
    #[error("the query file {0} is not valid UTF-8")]
    NotText(String),
    #[error("the query file {0} declares no operation named {1}")]
    UnknownOperation(String, String),
}

/// The GraphQL query one endpoint pins: the file's text, the operation
/// the endpoint names, and the variables expression evaluated per send.
#[derive(Debug)]
pub struct GraphQlQuery {
    /// The query file's text, sent verbatim as the request's `query`
    /// member.
    pub text: String,
    /// The named operation, sent as the request's `operationName`
    /// member; `None` sends no name and the document's anonymous
    /// selection set stands.
    pub operation: Option<String>,
    /// The endpoint's `variables` expression; a send's own body member
    /// overrides it for that send.
    pub variables: Option<Expression>,
}

impl GraphQlQuery {
    /// Load one endpoint's pinned query: the file must sit in the pack's
    /// digest-pinned inventory, match its digest, and declare the named
    /// operation when the endpoint names one. The pack check holds the
    /// same requirements at authoring; this holds them at load.
    pub fn load(
        pack: &AdapterPack,
        pack_directory: &Path,
        endpoint: &Endpoint,
    ) -> Result<Self, GraphQlLoadError> {
        let path = endpoint.query_file.as_deref().ok_or_else(|| {
            GraphQlLoadError::NotInventoried("the endpoint names no query file".to_owned())
        })?;
        let pinned = pack
            .pinned_file(path)
            .ok_or_else(|| GraphQlLoadError::NotInventoried(path.to_owned()))?;
        let bytes = std::fs::read(pack_directory.join(path))
            .map_err(|_| GraphQlLoadError::Unreadable(path.to_owned()))?;
        if bytes.len() > MAXIMUM_QUERY_FILE_BYTES {
            return Err(GraphQlLoadError::TooLarge(path.to_owned()));
        }
        if sha256_uri(&bytes) != pinned.as_str() {
            return Err(GraphQlLoadError::DigestMismatch(path.to_owned()));
        }
        let text =
            String::from_utf8(bytes).map_err(|_| GraphQlLoadError::NotText(path.to_owned()))?;
        let operation = endpoint.operation_name.clone();
        if let Some(name) = &operation {
            if !declares_operation(&text, name) {
                return Err(GraphQlLoadError::UnknownOperation(
                    path.to_owned(),
                    name.clone(),
                ));
            }
        }
        Ok(Self {
            text,
            operation,
            variables: endpoint.variables.clone(),
        })
    }
}

/// Whether a GraphQL document declares a named operation of that exact
/// name. A bounded scan, not a parse: the full grammar stays with
/// `adapterctl verify`; this names the same operations for the load-time
/// line, so the runtime adds no GraphQL dependency.
#[must_use]
pub(crate) fn declares_operation(source: &str, name: &str) -> bool {
    named_operations(source)
        .iter()
        .any(|(operation, _)| operation == name)
}

/// The named operations a document declares, with their kind: `query
/// Name`, `mutation Name`, `subscription Name`, in order of declaration.
/// The name is the token directly after the operation keyword; `{`, `@`
/// or `(` after the keyword marks the anonymous form. Comments, strings
/// and block strings are skipped, and a fragment definition never
/// matches, because `fragment` is no operation keyword.
fn named_operations(source: &str) -> Vec<(String, String)> {
    const KEYWORDS: [&str; 3] = ["query", "mutation", "subscription"];
    let tokens = scan(source);
    let mut declared = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Name(word) = token else {
            continue;
        };
        let Some(kind) = KEYWORDS.iter().find(|keyword| **keyword == word.as_str()) else {
            continue;
        };
        if let Some(Token::Name(operation)) = tokens.get(index + 1) {
            declared.push((operation.clone(), (*kind).to_owned()));
        }
    }
    declared
}

/// One lexical signal the operation scan needs: name tokens, and the
/// three punctuation marks that can follow an operation keyword in the
/// anonymous form. Every other character emits no token, so a name after
/// it is never mistaken for an operation name.
#[derive(Debug, PartialEq)]
enum Token {
    Name(String),
    OpenBrace,
    At,
    Paren,
}

/// Scan a GraphQL document into the signals above, skipping line
/// comments, strings and block strings, with string escapes honored.
fn scan(source: &str) -> Vec<Token> {
    let characters: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        match character {
            '#' => {
                while index < characters.len() && characters[index] != '\n' {
                    index += 1;
                }
            }
            '"' => {
                index += 1;
                // A block string ends on its own triple quote; a normal
                // string on an unescaped quote.
                if index + 1 < characters.len()
                    && characters[index] == '"'
                    && characters[index + 1] == '"'
                {
                    index += 2;
                    while index + 2 < characters.len()
                        && !(characters[index] == '"'
                            && characters[index + 1] == '"'
                            && characters[index + 2] == '"')
                    {
                        index += 1;
                    }
                    index = (index + 3).min(characters.len());
                } else {
                    while index < characters.len()
                        && (characters[index] != '"' || is_escaped(&characters, index))
                    {
                        index += 1;
                    }
                    index = (index + 1).min(characters.len());
                }
            }
            '{' => {
                tokens.push(Token::OpenBrace);
                index += 1;
            }
            '@' => {
                tokens.push(Token::At);
                index += 1;
            }
            '(' => {
                tokens.push(Token::Paren);
                index += 1;
            }
            _ if is_name_start(character) => {
                let start = index;
                while index < characters.len() && is_name_continue(characters[index]) {
                    index += 1;
                }
                tokens.push(Token::Name(characters[start..index].iter().collect()));
            }
            _ => {
                index += 1;
            }
        }
    }
    tokens
}

/// GraphQL name-start characters: letters and underscore (the spec's
/// `NameStart` without the non-ASCII ranges, which a reviewed pack does
/// not need named).
fn is_name_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

/// GraphQL name-continue characters: letters, digits and underscore.
fn is_name_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// Whether the quote at `index` is escaped by an odd run of backslashes.
fn is_escaped(characters: &[char], index: usize) -> bool {
    let mut slashes = 0;
    let mut cursor = index;
    while cursor > 0 && characters[cursor - 1] == '\\' {
        slashes += 1;
        cursor -= 1;
    }
    slashes % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(String, String)> {
        named_operations(source)
    }

    #[test]
    fn a_named_query_and_mutation_are_declared_with_their_kinds() {
        let source = "query FindCases($limit: Int) { cases(first: $limit) { id } }\n\
                      mutation CloseCase($id: ID!) { close(id: $id) { ok } }";
        assert_eq!(
            kinds(source),
            vec![
                ("FindCases".to_owned(), "query".to_owned()),
                ("CloseCase".to_owned(), "mutation".to_owned()),
            ]
        );
    }

    #[test]
    fn a_named_subscription_is_declared() {
        assert_eq!(
            kinds("subscription CaseEvents { caseOpened { id } }"),
            vec![("CaseEvents".to_owned(), "subscription".to_owned())],
        );
    }

    #[test]
    fn an_anonymous_selection_set_declares_no_operation() {
        assert!(kinds("query { cases { id } }").is_empty());
        // The anonymous forms with directives or variable definitions.
        assert!(kinds("query @cached { cases { id } }").is_empty());
        assert!(kinds("query ($limit: Int) { cases(first: $limit) { id } }").is_empty());
    }

    #[test]
    fn a_fragment_definition_never_matches() {
        let source = "query FindCases { ...CaseFields }\n\
                      fragment CaseFields on Case { id name }";
        assert_eq!(
            kinds(source),
            vec![("FindCases".to_owned(), "query".to_owned())],
            "the fragment's own name is not a declared operation"
        );
        assert!(!declares_operation(source, "CaseFields"));
    }

    #[test]
    fn comments_and_strings_do_not_declare_operations() {
        let source = "# query NotAReal One\n\
                      query FindCases { name(value: \"mutation Fake Two\") id }";
        assert_eq!(
            kinds(source),
            vec![("FindCases".to_owned(), "query".to_owned())],
        );
        assert!(!declares_operation(source, "NotAReal"));
        assert!(!declares_operation(source, "Fake"));
    }

    #[test]
    fn block_strings_do_not_declare_operations() {
        let source =
            "query FindCases {\n  note: field(block: \"\"\"an inner\nquery Fake { x }\n\"\"\")\n}";
        assert_eq!(
            kinds(source),
            vec![("FindCases".to_owned(), "query".to_owned())],
        );
        assert!(!declares_operation(source, "Fake"));
    }

    #[test]
    fn a_directive_between_keyword_and_brace_still_names_the_operation() {
        // `query Name @directive { ... }` keeps Name as the operation.
        assert_eq!(
            kinds("query FindCases @cached { cases { id } }"),
            vec![("FindCases".to_owned(), "query".to_owned())],
        );
    }

    #[test]
    fn an_escaped_quote_does_not_end_the_string() {
        let source = "query FindCases { name(value: \"a \\\" mutation Fake\") }";
        assert_eq!(
            kinds(source),
            vec![("FindCases".to_owned(), "query".to_owned())],
        );
        assert!(!declares_operation(source, "Fake"));
    }

    #[test]
    fn declares_operation_matches_the_exact_name_only() {
        let source = "query FindCases { cases { id } }";
        assert!(declares_operation(source, "FindCases"));
        assert!(!declares_operation(source, "FindCase"));
        assert!(!declares_operation(source, "findcases"));
    }
}
