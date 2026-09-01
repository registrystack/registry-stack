// SPDX-License-Identifier: Apache-2.0

//! Strict syntactic parsing for the Registry REST read query profile.
//!
//! This module deliberately stops at syntax. It preserves caller-facing field
//! identifiers and literal token kinds for the later authorization and planning
//! stages, but it does not resolve fields, infer types, or render SQL.

use std::collections::BTreeSet;
use std::fmt;

pub const MAX_QUERY_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_FILTER_DEPTH: usize = 16;
pub const MAX_FILTER_NODES: usize = 128;
pub const MAX_FILTER_PREDICATES: usize = 32;
pub const MAX_IN_VALUES: usize = 100;
pub const MAX_SELECTED_FIELDS: usize = 128;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_LITERAL_BYTES: usize = 1024;
pub const MAX_OPAQUE_VALUE_BYTES: usize = 4096;
pub const MAX_TOP: u32 = 100;

#[derive(Clone, Eq, PartialEq)]
pub struct ParsedReadQuery {
    pub access_profile: Option<String>,
    pub as_of: Option<String>,
    pub mode: ParsedReadQueryMode,
}

/// Snapshot parameters are a separate grammar from live `asOf` reads. The
/// reference is resolved and the validity value is typed only after access is
/// authorized against the active compiled operation.
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedSnapshotQuery {
    pub access_profile: Option<String>,
    pub snapshot: Option<String>,
    pub valid_at: Option<String>,
    pub mode: ParsedReadQueryMode,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ParsedReadQueryMode {
    Query(ReadQueryOptions),
    SkipToken { token: String },
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct ReadQueryOptions {
    pub select: Option<SelectClause>,
    pub filter: Option<FilterExpr>,
    pub orderby: Option<OrderByClause>,
    pub top: Option<u32>,
    pub count: Option<bool>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SelectClause {
    fields: Vec<ApiIdentifier>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OrderByClause {
    pub field: ApiIdentifier,
    pub direction: OrderDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderDirection {
    Asc,
    Desc,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ApiIdentifier(String);

#[derive(Clone, Eq, PartialEq)]
pub enum FilterExpr {
    Binary {
        op: LogicalOp,
        left: Box<FilterExpr>,
        right: Box<FilterExpr>,
    },
    Not(Box<FilterExpr>),
    Group(Box<FilterExpr>),
    Predicate(FilterPredicate),
}

#[derive(Clone, Eq, PartialEq)]
pub enum FilterPredicate {
    Compare {
        field: ApiIdentifier,
        op: ComparisonOp,
        literal: Literal,
    },
    In {
        field: ApiIdentifier,
        values: Vec<Literal>,
    },
    Function {
        function: StringFunction,
        field: ApiIdentifier,
        literal: Literal,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalOp {
    And,
    Or,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StringFunction {
    StartsWith,
    Contains,
}

#[derive(Clone, Eq, PartialEq)]
pub enum Literal {
    String(String),
    Integer(String),
    Decimal(String),
    Boolean(bool),
    Null,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryParseError {
    PayloadTooLarge,
    UnknownOption,
    DisallowedOption,
    DuplicateOption,
    ConflictingOptions,
    InvalidValue,
    InvalidFilterSyntax,
    QueryTooComplex,
}

impl fmt::Display for QueryParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            QueryParseError::PayloadTooLarge => "query payload is too large",
            QueryParseError::UnknownOption => "query option is not recognized",
            QueryParseError::DisallowedOption => "query option is not allowed",
            QueryParseError::DuplicateOption => "query option is duplicated",
            QueryParseError::ConflictingOptions => "query options conflict",
            QueryParseError::InvalidValue => "query option value is invalid",
            QueryParseError::InvalidFilterSyntax => "query filter syntax is invalid",
            QueryParseError::QueryTooComplex => "query is too complex",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for QueryParseError {}

impl fmt::Debug for ParsedReadQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedReadQuery")
            .field(
                "access_profile",
                &self.access_profile.as_ref().map(|_| "<redacted>"),
            )
            .field("as_of", &self.as_of.as_ref().map(|_| "<redacted>"))
            .field("mode", &self.mode)
            .finish()
    }
}

impl fmt::Debug for ParsedReadQueryMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedReadQueryMode::Query(options) => {
                formatter.debug_tuple("Query").field(options).finish()
            }
            ParsedReadQueryMode::SkipToken { token: _ } => formatter
                .debug_struct("SkipToken")
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Debug for ParsedSnapshotQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedSnapshotQuery")
            .field(
                "access_profile",
                &self.access_profile.as_ref().map(|_| "<redacted>"),
            )
            .field("snapshot", &self.snapshot.as_ref().map(|_| "<redacted>"))
            .field("valid_at", &self.valid_at.as_ref().map(|_| "<redacted>"))
            .field("mode", &self.mode)
            .finish()
    }
}

impl fmt::Debug for ReadQueryOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadQueryOptions")
            .field("select", &self.select)
            .field("filter", &self.filter)
            .field("orderby", &self.orderby)
            .field("top", &self.top)
            .field("count", &self.count)
            .finish()
    }
}

impl fmt::Debug for SelectClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectClause")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

impl fmt::Debug for OrderByClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrderByClause")
            .field("field", &"<redacted>")
            .field("direction", &self.direction)
            .finish()
    }
}

impl fmt::Debug for ApiIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiIdentifier(<redacted>)")
    }
}

impl fmt::Debug for FilterExpr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterExpr::Binary { op, left, right } => formatter
                .debug_struct("Binary")
                .field("op", op)
                .field("left", left)
                .field("right", right)
                .finish(),
            FilterExpr::Not(expr) => formatter.debug_tuple("Not").field(expr).finish(),
            FilterExpr::Group(expr) => formatter.debug_tuple("Group").field(expr).finish(),
            FilterExpr::Predicate(predicate) => {
                formatter.debug_tuple("Predicate").field(predicate).finish()
            }
        }
    }
}

impl fmt::Debug for FilterPredicate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterPredicate::Compare { field, op, literal } => formatter
                .debug_struct("Compare")
                .field("field", field)
                .field("op", op)
                .field("literal", literal)
                .finish(),
            FilterPredicate::In { field, values } => formatter
                .debug_struct("In")
                .field("field", field)
                .field("values", values)
                .finish(),
            FilterPredicate::Function {
                function,
                field,
                literal,
            } => formatter
                .debug_struct("Function")
                .field("function", function)
                .field("field", field)
                .field("literal", literal)
                .finish(),
        }
    }
}

impl fmt::Debug for Literal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Literal::String(_) => formatter.write_str("String(<redacted>)"),
            Literal::Integer(_) => formatter.write_str("Integer(<redacted>)"),
            Literal::Decimal(_) => formatter.write_str("Decimal(<redacted>)"),
            Literal::Boolean(_) => formatter.write_str("Boolean(<redacted>)"),
            Literal::Null => formatter.write_str("Null"),
        }
    }
}

impl ParsedReadQuery {
    pub fn canonical(&self) -> String {
        let mut output = String::from("registry-read-query:v2;");
        push_optional_atom(&mut output, "accessProfile", self.access_profile.as_deref());
        output.push(';');
        push_optional_atom(&mut output, "asOf", self.as_of.as_deref());
        output.push(';');
        match &self.mode {
            ParsedReadQueryMode::SkipToken { token } => {
                output.push_str("mode=skiptoken;");
                push_atom(&mut output, "token", token);
            }
            ParsedReadQueryMode::Query(options) => {
                output.push_str("mode=query;");
                options.push_canonical(&mut output);
            }
        }
        output
    }
}

impl ReadQueryOptions {
    fn has_any_option(&self) -> bool {
        self.select.is_some()
            || self.filter.is_some()
            || self.orderby.is_some()
            || self.top.is_some()
            || self.count.is_some()
    }

    fn push_canonical(&self, output: &mut String) {
        output.push_str("select=");
        match &self.select {
            Some(select) => select.push_canonical(output),
            None => output.push_str("none"),
        }
        output.push_str(";filter=");
        match &self.filter {
            Some(filter) => filter.push_canonical(output),
            None => output.push_str("none"),
        }
        output.push_str(";orderby=");
        match &self.orderby {
            Some(orderby) => orderby.push_canonical(output),
            None => output.push_str("none"),
        }
        output.push_str(";top=");
        match self.top {
            Some(top) => output.push_str(&top.to_string()),
            None => output.push_str("none"),
        }
        output.push_str(";count=");
        match self.count {
            Some(count) => output.push_str(if count { "true" } else { "false" }),
            None => output.push_str("none"),
        }
    }
}

impl SelectClause {
    pub fn fields(&self) -> &[ApiIdentifier] {
        &self.fields
    }

    fn push_canonical(&self, output: &mut String) {
        output.push('[');
        for (index, field) in self.fields.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            field.push_canonical(output);
        }
        output.push(']');
    }
}

impl ApiIdentifier {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(value: &str) -> Result<Self, QueryParseError> {
        if valid_identifier(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(QueryParseError::InvalidValue)
        }
    }

    fn push_canonical(&self, output: &mut String) {
        push_atom(output, "id", &self.0);
    }
}

impl OrderByClause {
    fn push_canonical(&self, output: &mut String) {
        output.push('(');
        self.field.push_canonical(output);
        output.push(',');
        output.push_str(match self.direction {
            OrderDirection::Asc => "asc",
            OrderDirection::Desc => "desc",
        });
        output.push(')');
    }
}

impl FilterExpr {
    fn push_canonical(&self, output: &mut String) {
        match self {
            FilterExpr::Binary { op, left, right } => {
                output.push_str(match op {
                    LogicalOp::And => "and(",
                    LogicalOp::Or => "or(",
                });
                left.push_canonical(output);
                output.push(',');
                right.push_canonical(output);
                output.push(')');
            }
            FilterExpr::Not(expr) => {
                output.push_str("not(");
                expr.push_canonical(output);
                output.push(')');
            }
            FilterExpr::Group(expr) => {
                output.push_str("group(");
                expr.push_canonical(output);
                output.push(')');
            }
            FilterExpr::Predicate(predicate) => predicate.push_canonical(output),
        }
    }
}

impl FilterPredicate {
    fn push_canonical(&self, output: &mut String) {
        match self {
            FilterPredicate::Compare { field, op, literal } => {
                output.push_str(match op {
                    ComparisonOp::Eq => "eq(",
                    ComparisonOp::Ne => "ne(",
                    ComparisonOp::Lt => "lt(",
                    ComparisonOp::Le => "le(",
                    ComparisonOp::Gt => "gt(",
                    ComparisonOp::Ge => "ge(",
                });
                field.push_canonical(output);
                output.push(',');
                literal.push_canonical(output);
                output.push(')');
            }
            FilterPredicate::In { field, values } => {
                output.push_str("in(");
                field.push_canonical(output);
                output.push_str(",[");
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    value.push_canonical(output);
                }
                output.push_str("])");
            }
            FilterPredicate::Function {
                function,
                field,
                literal,
            } => {
                output.push_str(match function {
                    StringFunction::StartsWith => "startswith(",
                    StringFunction::Contains => "contains(",
                });
                field.push_canonical(output);
                output.push(',');
                literal.push_canonical(output);
                output.push(')');
            }
        }
    }
}

impl Literal {
    fn push_canonical(&self, output: &mut String) {
        match self {
            Literal::String(value) => push_atom(output, "str", value),
            Literal::Integer(value) => push_atom(output, "int", value),
            Literal::Decimal(value) => push_atom(output, "dec", value),
            Literal::Boolean(true) => output.push_str("bool(true)"),
            Literal::Boolean(false) => output.push_str("bool(false)"),
            Literal::Null => output.push_str("null"),
        }
    }
}

pub fn parse_read_query<I, K, V>(pairs: I) -> Result<ParsedReadQuery, QueryParseError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut builder = QueryBuilder::default();
    let mut payload_bytes = 0_usize;

    for (key, value) in pairs {
        let key = key.as_ref();
        let value = value.as_ref();
        payload_bytes = payload_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(QueryParseError::PayloadTooLarge)?;
        if payload_bytes > MAX_QUERY_PAYLOAD_BYTES {
            return Err(QueryParseError::PayloadTooLarge);
        }
        builder.apply(key, value)?;
    }

    builder.finish()
}

pub fn parse_filter(value: &str) -> Result<FilterExpr, QueryParseError> {
    if value.is_empty() || value.len() > MAX_QUERY_PAYLOAD_BYTES {
        return Err(QueryParseError::InvalidFilterSyntax);
    }
    let tokens = Lexer::new(value).lex()?;
    let mut parser = FilterParser::new(tokens);
    let filter = parser.parse_or(0)?;
    parser.expect_end()?;
    validate_filter_depth(&filter, 1)?;
    Ok(filter)
}

pub fn parse_snapshot_query<I, K, V>(pairs: I) -> Result<ParsedSnapshotQuery, QueryParseError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut builder = QueryBuilder::default();
    let mut snapshot = None;
    let mut valid_at = None;
    let mut payload_bytes = 0_usize;
    for (key, value) in pairs {
        let key = key.as_ref();
        let value = value.as_ref();
        payload_bytes = payload_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(QueryParseError::PayloadTooLarge)?;
        if payload_bytes > MAX_QUERY_PAYLOAD_BYTES {
            return Err(QueryParseError::PayloadTooLarge);
        }
        match key {
            "snapshot" => {
                ensure_absent(snapshot.is_none())?;
                snapshot = Some(parse_opaque_value(value)?);
            }
            "validAt" => {
                ensure_absent(valid_at.is_none())?;
                valid_at = Some(parse_bounded_scalar(value)?);
            }
            "asOf" | "recordedAsOf" => return Err(QueryParseError::DisallowedOption),
            _ => builder.apply(key, value)?,
        }
    }
    let parsed = builder.finish()?;
    // Continuations carry the already selected snapshot and validity value.
    // Accepting a second value would make one request describe two queries.
    if matches!(parsed.mode, ParsedReadQueryMode::SkipToken { .. })
        && (snapshot.is_some() || valid_at.is_some())
    {
        return Err(QueryParseError::ConflictingOptions);
    }
    Ok(ParsedSnapshotQuery {
        access_profile: parsed.access_profile,
        snapshot,
        valid_at,
        mode: parsed.mode,
    })
}

#[derive(Default)]
struct QueryBuilder {
    access_profile: Option<String>,
    as_of: Option<String>,
    select: Option<SelectClause>,
    filter: Option<FilterExpr>,
    orderby: Option<OrderByClause>,
    top: Option<u32>,
    count: Option<bool>,
    skiptoken: Option<String>,
}

impl QueryBuilder {
    fn apply(&mut self, key: &str, value: &str) -> Result<(), QueryParseError> {
        match key {
            "accessProfile" => {
                ensure_absent(self.access_profile.is_none())?;
                if !valid_config_identifier(value) {
                    return Err(QueryParseError::InvalidValue);
                }
                self.access_profile = Some(value.to_owned());
            }
            "asOf" => {
                ensure_absent(self.as_of.is_none())?;
                self.as_of = Some(parse_bounded_scalar(value)?);
            }
            "$select" => {
                ensure_absent(self.select.is_none())?;
                self.select = Some(parse_select(value)?);
            }
            "$filter" => {
                ensure_absent(self.filter.is_none())?;
                self.filter = Some(parse_filter(value)?);
            }
            "$orderby" => {
                ensure_absent(self.orderby.is_none())?;
                self.orderby = Some(parse_orderby(value)?);
            }
            "$top" => {
                ensure_absent(self.top.is_none())?;
                self.top = Some(parse_top(value)?);
            }
            "$count" => {
                ensure_absent(self.count.is_none())?;
                self.count = Some(parse_count(value)?);
            }
            "$skiptoken" => {
                ensure_absent(self.skiptoken.is_none())?;
                self.skiptoken = Some(parse_opaque_value(value)?);
            }
            "fields" | "filter" | "sort" | "pageSize" | "cursor" | "$skip" | "$apply"
            | "$expand" | "$batch" => return Err(QueryParseError::DisallowedOption),
            "$query" | "query" | "sql" | "statement" => {
                return Err(QueryParseError::DisallowedOption);
            }
            _ => return Err(QueryParseError::UnknownOption),
        }
        Ok(())
    }

    fn finish(self) -> Result<ParsedReadQuery, QueryParseError> {
        let options = ReadQueryOptions {
            select: self.select,
            filter: self.filter,
            orderby: self.orderby,
            top: self.top,
            count: self.count,
        };
        let mode = match self.skiptoken {
            Some(token) => {
                if self.as_of.is_some() || options.has_any_option() {
                    return Err(QueryParseError::ConflictingOptions);
                }
                ParsedReadQueryMode::SkipToken { token }
            }
            None => ParsedReadQueryMode::Query(options),
        };
        Ok(ParsedReadQuery {
            access_profile: self.access_profile,
            as_of: self.as_of,
            mode,
        })
    }
}

fn ensure_absent(absent: bool) -> Result<(), QueryParseError> {
    if absent {
        Ok(())
    } else {
        Err(QueryParseError::DuplicateOption)
    }
}

fn parse_select(value: &str) -> Result<SelectClause, QueryParseError> {
    if value.is_empty() {
        return Err(QueryParseError::InvalidValue);
    }
    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();
    for field in value.split(',') {
        if fields.len() >= MAX_SELECTED_FIELDS {
            return Err(QueryParseError::QueryTooComplex);
        }
        let field = ApiIdentifier::parse(field)?;
        if !seen.insert(field.clone()) {
            return Err(QueryParseError::DuplicateOption);
        }
        fields.push(field);
    }
    Ok(SelectClause { fields })
}

fn parse_orderby(value: &str) -> Result<OrderByClause, QueryParseError> {
    if value.contains(',') {
        return Err(QueryParseError::InvalidValue);
    }
    let mut pieces = value.split_ascii_whitespace();
    let field = pieces.next().ok_or(QueryParseError::InvalidValue)?;
    let direction = match pieces.next() {
        None => OrderDirection::Asc,
        Some("asc") => OrderDirection::Asc,
        Some("desc") => OrderDirection::Desc,
        Some(_) => return Err(QueryParseError::InvalidValue),
    };
    if pieces.next().is_some() {
        return Err(QueryParseError::InvalidValue);
    }
    Ok(OrderByClause {
        field: ApiIdentifier::parse(field)?,
        direction,
    })
}

fn parse_top(value: &str) -> Result<u32, QueryParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QueryParseError::InvalidValue);
    }
    let top = value
        .parse::<u32>()
        .map_err(|_| QueryParseError::InvalidValue)?;
    if top == 0 || top > MAX_TOP {
        return Err(QueryParseError::InvalidValue);
    }
    Ok(top)
}

fn parse_count(value: &str) -> Result<bool, QueryParseError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(QueryParseError::InvalidValue),
    }
}

fn parse_bounded_scalar(value: &str) -> Result<String, QueryParseError> {
    if value.is_empty()
        || value.len() > MAX_LITERAL_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(QueryParseError::InvalidValue);
    }
    Ok(value.to_owned())
}

fn parse_opaque_value(value: &str) -> Result<String, QueryParseError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_VALUE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(QueryParseError::InvalidValue);
    }
    Ok(value.to_owned())
}

fn valid_config_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn push_optional_atom(output: &mut String, name: &str, value: Option<&str>) {
    output.push_str(name);
    output.push('=');
    match value {
        Some(value) => push_atom(output, "s", value),
        None => output.push_str("none"),
    }
}

fn push_atom(output: &mut String, kind: &str, value: &str) {
    output.push_str(kind);
    output.push('(');
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
    output.push(')');
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Ident(String),
    String(String),
    Integer(String),
    Decimal(String),
    Boolean(bool),
    Null,
    LParen,
    RParen,
    Comma,
    End,
}

struct Lexer<'a> {
    input: &'a str,
    index: usize,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            index: 0,
            tokens: Vec::new(),
        }
    }

    fn lex(mut self) -> Result<Vec<Token>, QueryParseError> {
        while self.index < self.input.len() {
            let byte = self.input.as_bytes()[self.index];
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => self.index += 1,
                b'(' => {
                    self.tokens.push(Token::LParen);
                    self.index += 1;
                }
                b')' => {
                    self.tokens.push(Token::RParen);
                    self.index += 1;
                }
                b',' => {
                    self.tokens.push(Token::Comma);
                    self.index += 1;
                }
                b'\'' => self.lex_string()?,
                b'-' | b'0'..=b'9' => self.lex_number()?,
                b'a'..=b'z' | b'_' => self.lex_identifier()?,
                _ => return Err(QueryParseError::InvalidFilterSyntax),
            }
        }
        self.tokens.push(Token::End);
        Ok(self.tokens)
    }

    fn lex_string(&mut self) -> Result<(), QueryParseError> {
        self.index += 1;
        let mut value = String::new();
        while self.index < self.input.len() {
            let byte = self.input.as_bytes()[self.index];
            if byte == b'\'' {
                if self.index + 1 < self.input.len()
                    && self.input.as_bytes()[self.index + 1] == b'\''
                {
                    if value.len() + 1 > MAX_LITERAL_BYTES {
                        return Err(QueryParseError::InvalidValue);
                    }
                    value.push('\'');
                    self.index += 2;
                    continue;
                }
                self.index += 1;
                self.tokens.push(Token::String(value));
                return Ok(());
            }
            let ch = self.input[self.index..]
                .chars()
                .next()
                .ok_or(QueryParseError::InvalidFilterSyntax)?;
            if ch.is_control() {
                return Err(QueryParseError::InvalidValue);
            }
            if value.len() + ch.len_utf8() > MAX_LITERAL_BYTES {
                return Err(QueryParseError::InvalidValue);
            }
            value.push(ch);
            self.index += ch.len_utf8();
        }
        Err(QueryParseError::InvalidFilterSyntax)
    }

    fn lex_number(&mut self) -> Result<(), QueryParseError> {
        let start = self.index;
        if self.input.as_bytes()[self.index] == b'-' {
            self.index += 1;
            if self.index >= self.input.len() || !self.input.as_bytes()[self.index].is_ascii_digit()
            {
                return Err(QueryParseError::InvalidFilterSyntax);
            }
        }
        self.consume_digits();
        let mut decimal = false;
        if self.index < self.input.len() && self.input.as_bytes()[self.index] == b'.' {
            decimal = true;
            self.index += 1;
            if self.index >= self.input.len() || !self.input.as_bytes()[self.index].is_ascii_digit()
            {
                return Err(QueryParseError::InvalidFilterSyntax);
            }
            self.consume_digits();
        }
        let value = &self.input[start..self.index];
        if value.len() > MAX_LITERAL_BYTES {
            return Err(QueryParseError::InvalidValue);
        }
        if decimal {
            self.tokens.push(Token::Decimal(value.to_owned()));
        } else {
            self.tokens.push(Token::Integer(value.to_owned()));
        }
        Ok(())
    }

    fn consume_digits(&mut self) {
        while self.index < self.input.len() && self.input.as_bytes()[self.index].is_ascii_digit() {
            self.index += 1;
        }
    }

    fn lex_identifier(&mut self) -> Result<(), QueryParseError> {
        let start = self.index;
        self.index += 1;
        while self.index < self.input.len() {
            let byte = self.input.as_bytes()[self.index];
            if byte.is_ascii_alphabetic()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.')
            {
                self.index += 1;
            } else {
                break;
            }
        }
        let value = &self.input[start..self.index];
        if value.len() > MAX_IDENTIFIER_BYTES {
            return Err(QueryParseError::InvalidValue);
        }
        match value {
            "true" => self.tokens.push(Token::Boolean(true)),
            "false" => self.tokens.push(Token::Boolean(false)),
            "null" => self.tokens.push(Token::Null),
            _ => self.tokens.push(Token::Ident(value.to_owned())),
        }
        Ok(())
    }
}

#[derive(Default)]
struct FilterBudget {
    nodes: usize,
    predicates: usize,
    in_values: usize,
}

impl FilterBudget {
    fn node(&mut self) -> Result<(), QueryParseError> {
        self.nodes += 1;
        if self.nodes > MAX_FILTER_NODES {
            return Err(QueryParseError::QueryTooComplex);
        }
        Ok(())
    }

    fn predicate(&mut self) -> Result<(), QueryParseError> {
        self.predicates += 1;
        if self.predicates > MAX_FILTER_PREDICATES {
            return Err(QueryParseError::QueryTooComplex);
        }
        Ok(())
    }

    fn in_value(&mut self) -> Result<(), QueryParseError> {
        self.in_values += 1;
        if self.in_values > MAX_IN_VALUES {
            return Err(QueryParseError::QueryTooComplex);
        }
        Ok(())
    }
}

struct FilterParser {
    tokens: Vec<Token>,
    index: usize,
    budget: FilterBudget,
}

impl FilterParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            index: 0,
            budget: FilterBudget::default(),
        }
    }

    fn parse_or(&mut self, group_depth: usize) -> Result<FilterExpr, QueryParseError> {
        let mut expr = self.parse_and(group_depth)?;
        while self.consume_keyword("or") {
            let right = self.parse_and(group_depth)?;
            self.budget.node()?;
            expr = FilterExpr::Binary {
                op: LogicalOp::Or,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_and(&mut self, group_depth: usize) -> Result<FilterExpr, QueryParseError> {
        let mut expr = self.parse_unary(group_depth)?;
        while self.consume_keyword("and") {
            let right = self.parse_unary(group_depth)?;
            self.budget.node()?;
            expr = FilterExpr::Binary {
                op: LogicalOp::And,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_unary(&mut self, group_depth: usize) -> Result<FilterExpr, QueryParseError> {
        if self.consume_keyword("not") {
            let expr = self.parse_unary(group_depth)?;
            self.budget.node()?;
            return Ok(FilterExpr::Not(Box::new(expr)));
        }
        self.parse_primary(group_depth)
    }

    fn parse_primary(&mut self, group_depth: usize) -> Result<FilterExpr, QueryParseError> {
        if self.consume_lparen() {
            if group_depth >= MAX_FILTER_DEPTH {
                return Err(QueryParseError::QueryTooComplex);
            }
            let expr = self.parse_or(group_depth + 1)?;
            self.expect_rparen()?;
            self.budget.node()?;
            return Ok(FilterExpr::Group(Box::new(expr)));
        }

        let field_or_function = self.expect_identifier()?;
        match self.peek() {
            Token::LParen => self.parse_function(field_or_function),
            Token::Ident(operator) if is_comparison_operator(operator) || operator == "in" => {
                self.parse_field_predicate(field_or_function)
            }
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn parse_function(&mut self, name: ApiIdentifier) -> Result<FilterExpr, QueryParseError> {
        let function = match name.as_str() {
            "startswith" => StringFunction::StartsWith,
            "contains" => StringFunction::Contains,
            _ => return Err(QueryParseError::InvalidFilterSyntax),
        };
        self.expect_lparen()?;
        let field = self.expect_identifier()?;
        self.expect_comma()?;
        let literal = self.expect_literal(false)?;
        self.expect_rparen()?;
        self.budget.predicate()?;
        self.budget.node()?;
        Ok(FilterExpr::Predicate(FilterPredicate::Function {
            function,
            field,
            literal,
        }))
    }

    fn parse_field_predicate(
        &mut self,
        field: ApiIdentifier,
    ) -> Result<FilterExpr, QueryParseError> {
        let operator = self.expect_identifier()?;
        let predicate = if operator.as_str() == "in" {
            self.parse_in_predicate(field)?
        } else {
            let op = comparison_operator(operator.as_str())?;
            let literal = self.expect_literal(true)?;
            if matches!(literal, Literal::Null)
                && !matches!(op, ComparisonOp::Eq | ComparisonOp::Ne)
            {
                return Err(QueryParseError::InvalidFilterSyntax);
            }
            FilterPredicate::Compare { field, op, literal }
        };
        self.budget.predicate()?;
        self.budget.node()?;
        Ok(FilterExpr::Predicate(predicate))
    }

    fn parse_in_predicate(
        &mut self,
        field: ApiIdentifier,
    ) -> Result<FilterPredicate, QueryParseError> {
        self.expect_lparen()?;
        let mut values = Vec::new();
        loop {
            values.push(self.expect_literal(false)?);
            self.budget.in_value()?;
            if self.consume_comma() {
                continue;
            }
            self.expect_rparen()?;
            break;
        }
        Ok(FilterPredicate::In { field, values })
    }

    fn expect_literal(&mut self, allow_null: bool) -> Result<Literal, QueryParseError> {
        let literal = match self.next() {
            Token::String(value) => Literal::String(value),
            Token::Integer(value) => Literal::Integer(value),
            Token::Decimal(value) => Literal::Decimal(value),
            Token::Boolean(value) => Literal::Boolean(value),
            Token::Null if allow_null => Literal::Null,
            _ => return Err(QueryParseError::InvalidFilterSyntax),
        };
        Ok(literal)
    }

    fn expect_identifier(&mut self) -> Result<ApiIdentifier, QueryParseError> {
        match self.next() {
            Token::Ident(value) => Ok(ApiIdentifier(value)),
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        match self.peek() {
            Token::Ident(value) if value == keyword => {
                self.index += 1;
                true
            }
            _ => false,
        }
    }

    fn consume_lparen(&mut self) -> bool {
        if matches!(self.peek(), Token::LParen) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn consume_comma(&mut self) -> bool {
        if matches!(self.peek(), Token::Comma) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_lparen(&mut self) -> Result<(), QueryParseError> {
        match self.next() {
            Token::LParen => Ok(()),
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn expect_rparen(&mut self) -> Result<(), QueryParseError> {
        match self.next() {
            Token::RParen => Ok(()),
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn expect_comma(&mut self) -> Result<(), QueryParseError> {
        match self.next() {
            Token::Comma => Ok(()),
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn expect_end(&mut self) -> Result<(), QueryParseError> {
        match self.next() {
            Token::End => Ok(()),
            _ => Err(QueryParseError::InvalidFilterSyntax),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.index).unwrap_or(&Token::End)
    }

    fn next(&mut self) -> Token {
        let token = self.tokens.get(self.index).cloned().unwrap_or(Token::End);
        self.index += 1;
        token
    }
}

fn is_comparison_operator(value: &str) -> bool {
    matches!(value, "eq" | "ne" | "lt" | "le" | "gt" | "ge")
}

fn comparison_operator(value: &str) -> Result<ComparisonOp, QueryParseError> {
    match value {
        "eq" => Ok(ComparisonOp::Eq),
        "ne" => Ok(ComparisonOp::Ne),
        "lt" => Ok(ComparisonOp::Lt),
        "le" => Ok(ComparisonOp::Le),
        "gt" => Ok(ComparisonOp::Gt),
        "ge" => Ok(ComparisonOp::Ge),
        _ => Err(QueryParseError::InvalidFilterSyntax),
    }
}

fn validate_filter_depth(expr: &FilterExpr, depth: usize) -> Result<(), QueryParseError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(QueryParseError::QueryTooComplex);
    }
    match expr {
        FilterExpr::Binary { left, right, .. } => {
            validate_filter_depth(left, depth + 1)?;
            validate_filter_depth(right, depth + 1)
        }
        FilterExpr::Not(expr) | FilterExpr::Group(expr) => validate_filter_depth(expr, depth + 1),
        FilterExpr::Predicate(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<const N: usize>(
        pairs: [(&'static str, &'static str); N],
    ) -> Result<ParsedReadQuery, QueryParseError> {
        parse_read_query(pairs)
    }

    fn filter(value: &str) -> FilterExpr {
        parse_filter(value).expect("filter parses")
    }

    #[test]
    fn parses_native_read_query_surface() {
        let query = parse([
            ("accessProfile", "caseworker"),
            ("asOf", "2026-08-30T00:00:00Z"),
            ("$select", "case-code,status"),
            ("$filter", "status eq 'open'"),
            ("$orderby", "opened-on desc"),
            ("$top", "50"),
            ("$count", "false"),
        ])
        .expect("query parses");

        assert_eq!(query.access_profile.as_deref(), Some("caseworker"));
        assert_eq!(query.as_of.as_deref(), Some("2026-08-30T00:00:00Z"));
        let ParsedReadQueryMode::Query(options) = query.mode else {
            panic!("expected query mode");
        };
        assert_eq!(options.select.unwrap().fields()[0].as_str(), "case-code");
        assert_eq!(options.orderby.unwrap().direction, OrderDirection::Desc);
        assert_eq!(options.top, Some(50));
        assert_eq!(options.count, Some(false));
    }

    #[test]
    fn governed_lower_camel_api_names_parse_without_widening_identifier_grammar() {
        let query = parse([
            ("$select", "householdCode,householdKind"),
            ("$filter", "householdKind eq 'single'"),
            ("$orderby", "householdCode"),
        ])
        .expect("governed lower-camel API property names parse");
        let ParsedReadQueryMode::Query(options) = query.mode else {
            panic!("expected query mode");
        };
        assert_eq!(
            options
                .select
                .expect("selection exists")
                .fields()
                .iter()
                .map(ApiIdentifier::as_str)
                .collect::<Vec<_>>(),
            ["householdCode", "householdKind"]
        );
        assert_eq!(
            options.orderby.expect("ordering exists").field.as_str(),
            "householdCode"
        );

        for value in [
            "HouseholdCode",
            "householdCode/person",
            "householdCode;drop",
            "householdCode%",
        ] {
            assert_eq!(
                parse_read_query([("$select", value)]),
                Err(QueryParseError::InvalidValue),
                "identifier grammar remains closed for {value}"
            );
        }
        assert_eq!(
            parse([("$select", "householdCode,householdCode")]),
            Err(QueryParseError::DuplicateOption)
        );
        assert_eq!(
            parse([("accessProfile", "caseWorker")]),
            Err(QueryParseError::InvalidValue),
            "config identifiers retain their lowercase-only grammar"
        );
    }

    #[test]
    fn rejects_unknown_disallowed_and_duplicate_options() {
        assert_eq!(
            parse([("limit", "10")]),
            Err(QueryParseError::UnknownOption)
        );
        for key in [
            "fields", "filter", "sort", "pageSize", "cursor", "$skip", "$apply", "$expand",
            "$batch", "sql",
        ] {
            assert_eq!(
                parse([(key, "value")]),
                Err(QueryParseError::DisallowedOption)
            );
        }
        assert_eq!(
            parse([("$top", "10"), ("$top", "11")]),
            Err(QueryParseError::DuplicateOption)
        );
    }

    #[test]
    fn skiptoken_only_allows_access_profile() {
        let query = parse([("accessProfile", "reader"), ("$skiptoken", "opaque-token")])
            .expect("skiptoken query parses");
        assert!(matches!(query.mode, ParsedReadQueryMode::SkipToken { .. }));

        for pair in [
            ("asOf", "2026-08-30T00:00:00Z"),
            ("$select", "field"),
            ("$filter", "field eq 'value'"),
            ("$orderby", "field"),
            ("$top", "10"),
            ("$count", "true"),
        ] {
            assert_eq!(
                parse([("$skiptoken", "opaque-token"), pair]),
                Err(QueryParseError::ConflictingOptions)
            );
        }
    }

    #[test]
    fn top_and_count_are_strict() {
        assert!(parse([("$top", "1")])
            .unwrap()
            .canonical()
            .contains("top=1"));
        assert!(parse([("$top", "100")])
            .unwrap()
            .canonical()
            .contains("top=100"));
        for value in ["", "0", "101", "-1", "1.0", "+1", "true"] {
            assert_eq!(parse([("$top", value)]), Err(QueryParseError::InvalidValue));
        }
        assert!(parse([("$count", "true")])
            .unwrap()
            .canonical()
            .contains("count=true"));
        assert!(parse([("$count", "false")])
            .unwrap()
            .canonical()
            .contains("count=false"));
        for value in ["", "True", "1", "yes"] {
            assert_eq!(
                parse([("$count", value)]),
                Err(QueryParseError::InvalidValue)
            );
        }
    }

    #[test]
    fn orderby_accepts_one_field_and_optional_direction() {
        let asc = parse([("$orderby", "opened-on")]).expect("orderby parses");
        assert!(asc.canonical().contains("orderby=(id(9:opened-on),asc)"));
        let desc = parse([("$orderby", "opened-on desc")]).expect("desc parses");
        assert!(desc.canonical().contains("orderby=(id(9:opened-on),desc)"));
        for value in ["opened-on DESC", "opened-on asc extra", "one,two", ""] {
            assert_eq!(
                parse([("$orderby", value)]),
                Err(QueryParseError::InvalidValue)
            );
        }
    }

    #[test]
    fn select_is_bounded_and_duplicate_free() {
        let camel = parse([("$select", "childUnder5Count")]).expect("lower camel API name parses");
        assert!(camel.canonical().contains("id(16:childUnder5Count)"));
        assert_eq!(
            parse([("$select", "case-code,case-code")]),
            Err(QueryParseError::DuplicateOption)
        );
        assert_eq!(parse([("$select", "")]), Err(QueryParseError::InvalidValue));
        assert_eq!(
            parse([("$select", "case-code/person")]),
            Err(QueryParseError::InvalidValue)
        );

        let many = (0..=MAX_SELECTED_FIELDS)
            .map(|index| format!("field-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_read_query([("$select", many.as_str())]),
            Err(QueryParseError::QueryTooComplex)
        );
    }

    #[test]
    fn filter_precedence_and_grouping_are_preserved() {
        let parsed = filter("a eq 1 or b eq 2 and not c eq 3");
        assert_eq!(
            parsed_canonical(&parsed),
            "or(eq(id(1:a),int(1:1)),and(eq(id(1:b),int(1:2)),not(eq(id(1:c),int(1:3)))))"
        );

        let grouped = filter("(a eq 1 or b eq 2) and c eq 3");
        assert_eq!(
            parsed_canonical(&grouped),
            "and(group(or(eq(id(1:a),int(1:1)),eq(id(1:b),int(1:2)))),eq(id(1:c),int(1:3)))"
        );
    }

    #[test]
    fn filter_comparison_operators_parse() {
        for (source, canonical) in [
            ("a eq 1", "eq(id(1:a),int(1:1))"),
            ("a ne 1", "ne(id(1:a),int(1:1))"),
            ("a lt 1", "lt(id(1:a),int(1:1))"),
            ("a le 1", "le(id(1:a),int(1:1))"),
            ("a gt 1", "gt(id(1:a),int(1:1))"),
            ("a ge 1", "ge(id(1:a),int(1:1))"),
        ] {
            assert_eq!(parsed_canonical(&filter(source)), canonical);
        }
        assert_eq!(
            parsed_canonical(&filter("childUnder5Count gt 0")),
            "gt(id(16:childUnder5Count),int(1:0))"
        );
    }

    #[test]
    fn filter_literals_and_null_tests_parse() {
        assert_eq!(
            parsed_canonical(&filter("name eq 'O''Brien'")),
            "eq(id(4:name),str(7:O'Brien))"
        );
        assert_eq!(
            parsed_canonical(&filter("score eq -10.5")),
            "eq(id(5:score),dec(5:-10.5))"
        );
        assert_eq!(
            parsed_canonical(&filter("active eq true")),
            "eq(id(6:active),bool(true))"
        );
        assert_eq!(
            parsed_canonical(&filter("closed-on eq null")),
            "eq(id(9:closed-on),null)"
        );
        assert_eq!(
            parsed_canonical(&filter("closed-on ne null")),
            "ne(id(9:closed-on),null)"
        );
        assert_eq!(
            parse_filter("closed-on lt null"),
            Err(QueryParseError::InvalidFilterSyntax)
        );
    }

    #[test]
    fn filter_in_and_functions_parse() {
        assert_eq!(
            parsed_canonical(&filter("status in ('open','held','closed')")),
            "in(id(6:status),[str(4:open),str(4:held),str(6:closed)])"
        );
        assert_eq!(
            parsed_canonical(&filter("startswith(name,'Jo')")),
            "startswith(id(4:name),str(2:Jo))"
        );
        assert_eq!(
            parsed_canonical(&filter("contains(note,'review')")),
            "contains(id(4:note),str(6:review))"
        );
        assert_eq!(
            parse_filter("endswith(name,'n')"),
            Err(QueryParseError::InvalidFilterSyntax)
        );
        assert_eq!(
            parse_filter("startswith(parent/name,'Jo')"),
            Err(QueryParseError::InvalidFilterSyntax)
        );
    }

    #[test]
    fn filter_bounds_are_enforced() {
        let too_many_in_values = format!(
            "status in ({})",
            (0..=MAX_IN_VALUES)
                .map(|index| format!("'{index}'"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            parse_filter(&too_many_in_values),
            Err(QueryParseError::QueryTooComplex)
        );

        let too_many_predicates = (0..=MAX_FILTER_PREDICATES)
            .map(|index| format!("f{index} eq {index}"))
            .collect::<Vec<_>>()
            .join(" and ");
        assert_eq!(
            parse_filter(&too_many_predicates),
            Err(QueryParseError::QueryTooComplex)
        );

        let too_deep = format!(
            "{}a eq 1{}",
            "(".repeat(MAX_FILTER_DEPTH),
            ")".repeat(MAX_FILTER_DEPTH)
        );
        assert_eq!(
            parse_filter(&too_deep),
            Err(QueryParseError::QueryTooComplex)
        );

        let too_long_literal = format!("name eq '{}'", "a".repeat(MAX_LITERAL_BYTES + 1));
        assert_eq!(
            parse_filter(&too_long_literal),
            Err(QueryParseError::InvalidValue)
        );
    }

    #[test]
    fn payload_and_opaque_values_are_bounded() {
        let large = "a".repeat(MAX_QUERY_PAYLOAD_BYTES + 1);
        assert_eq!(
            parse_read_query([("accessProfile", large.as_str())]),
            Err(QueryParseError::PayloadTooLarge)
        );

        let large_token = "a".repeat(MAX_OPAQUE_VALUE_BYTES + 1);
        assert_eq!(
            parse_read_query([("$skiptoken", large_token.as_str())]),
            Err(QueryParseError::InvalidValue)
        );
    }

    #[test]
    fn canonicalization_is_stable_and_preserves_grouping() {
        let ungrouped = parse([("$filter", "a eq 1 and b eq 2")])
            .expect("query parses")
            .canonical();
        let grouped = parse([("$filter", "(a eq 1) and b eq 2")])
            .expect("query parses")
            .canonical();

        assert_ne!(ungrouped, grouped);
        assert!(ungrouped.contains("filter=and(eq(id(1:a),int(1:1)),eq(id(1:b),int(1:2)))"));
        assert!(grouped.contains("filter=and(group(eq(id(1:a),int(1:1))),eq(id(1:b),int(1:2)))"));
    }

    #[test]
    fn errors_are_value_free_in_debug_and_display() {
        let debug = format!("{:?}", QueryParseError::InvalidFilterSyntax);
        let display = QueryParseError::InvalidFilterSyntax.to_string();
        assert_eq!(debug, "InvalidFilterSyntax");
        assert_eq!(display, "query filter syntax is invalid");
        assert!(!debug.contains("secret"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn snapshot_grammar_preserves_options_without_widening_live_reads() {
        let parsed = parse_snapshot_query([
            ("accessProfile", "caseworker"),
            ("snapshot", "snapshot-canary"),
            ("validAt", "2026-06-05"),
            ("$select", "household_id,valid_from"),
            ("$filter", "status eq 'active'"),
            ("$orderby", "valid_from"),
            ("$top", "20"),
            ("$count", "true"),
        ])
        .expect("snapshot query syntax");
        assert_eq!(parsed.snapshot.as_deref(), Some("snapshot-canary"));
        assert_eq!(parsed.valid_at.as_deref(), Some("2026-06-05"));
        let ParsedReadQueryMode::Query(options) = parsed.mode else {
            panic!("first page expected");
        };
        assert_eq!(options.top, Some(20));
        assert_eq!(options.count, Some(true));
        for key in ["snapshot", "validAt", "recordedAsOf"] {
            assert!(parse_read_query([(key, "value")]).is_err());
        }
        for key in ["asOf", "recordedAsOf", "$expand", "sql"] {
            assert_eq!(
                parse_snapshot_query([(key, "value")]),
                Err(QueryParseError::DisallowedOption)
            );
        }
        let empty = parse_snapshot_query(std::iter::empty::<(&str, &str)>()).unwrap();
        assert_eq!(empty.snapshot, None);
        assert_eq!(empty.valid_at, None);
    }

    #[test]
    fn snapshot_continuations_cannot_override_the_bound_query() {
        assert!(parse_snapshot_query([
            ("accessProfile", "caseworker"),
            ("$skiptoken", "cursor-canary"),
        ])
        .is_ok());
        for key in [
            "snapshot", "validAt", "$select", "$filter", "$orderby", "$top", "$count",
        ] {
            let value = match key {
                "$filter" => "field eq 'value'",
                "$top" => "10",
                "$count" => "true",
                _ => "value",
            };
            assert_eq!(
                parse_snapshot_query([("$skiptoken", "cursor-canary"), (key, value)]),
                Err(QueryParseError::ConflictingOptions)
            );
        }
    }

    #[test]
    fn snapshot_parameters_are_unique_bounded_and_redacted() {
        for key in ["snapshot", "validAt"] {
            assert_eq!(
                parse_snapshot_query([(key, "one"), (key, "two")]),
                Err(QueryParseError::DuplicateOption)
            );
            for value in ["", "canary\n"] {
                assert_eq!(
                    parse_snapshot_query([(key, value)]),
                    Err(QueryParseError::InvalidValue)
                );
            }
        }
        assert_eq!(
            parse_snapshot_query([("snapshot", "x".repeat(MAX_OPAQUE_VALUE_BYTES + 1))]),
            Err(QueryParseError::InvalidValue)
        );
        assert_eq!(
            parse_snapshot_query([("validAt", "x".repeat(MAX_LITERAL_BYTES + 1))]),
            Err(QueryParseError::InvalidValue)
        );
        assert_eq!(
            parse_snapshot_query([("snapshot", "x".repeat(MAX_QUERY_PAYLOAD_BYTES))]),
            Err(QueryParseError::PayloadTooLarge)
        );
        let parsed = parse_snapshot_query([
            ("snapshot", "snapshot-canary"),
            ("validAt", "validity-canary"),
            ("accessProfile", "profile-canary"),
            ("$filter", "field eq 'filter-canary'"),
        ])
        .unwrap();
        assert!(!format!("{parsed:?}").contains("canary"));
    }

    #[test]
    fn parsed_query_debug_redacts_identifiers_literals_and_tokens() {
        let query = parse([
            ("accessProfile", "caseworker-canary"),
            ("$filter", "secret eq 'literal-canary'"),
        ])
        .expect("query parses");
        let debug = format!("{query:?}");
        assert!(!debug.contains("caseworker-canary"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("literal-canary"));

        let cursor = parse([("$skiptoken", "cursor-canary")]).expect("cursor query parses");
        assert!(!format!("{cursor:?}").contains("cursor-canary"));
    }

    fn parsed_canonical(filter: &FilterExpr) -> String {
        let mut output = String::new();
        filter.push_canonical(&mut output);
        output
    }
}
