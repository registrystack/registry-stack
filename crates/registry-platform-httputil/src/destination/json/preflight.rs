// SPDX-License-Identifier: Apache-2.0
//! Allocation-free lexical and structural bounds checked before JSON parsing.
//!
//! One token is counted for every value, including each object or array, and
//! one additional token is counted for every object key. String contents are
//! scanned as a single token, so escaped quotes and structural characters
//! cannot create an undercount.

use super::MAX_CLOSED_JSON_ENCODED_BODY_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JsonPreflightError {
    InvalidJson,
    ContractLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct JsonPreflightStats {
    pub(super) tokens: usize,
    pub(super) maximum_depth: usize,
}

pub(super) fn preflight_json(
    bytes: &[u8],
    token_limit: usize,
    depth_limit: usize,
) -> Result<JsonPreflightStats, JsonPreflightError> {
    if bytes.len() > MAX_CLOSED_JSON_ENCODED_BODY_BYTES {
        return Err(JsonPreflightError::ContractLimitExceeded);
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(JsonPreflightError::InvalidJson);
    }

    let mut scanner = Scanner {
        bytes,
        index: 0,
        tokens: 0,
        maximum_depth: 0,
        token_limit,
        depth_limit,
    };
    scanner.skip_whitespace();
    scanner.scan_value(1)?;
    scanner.skip_whitespace();
    if scanner.index != bytes.len() {
        return Err(JsonPreflightError::InvalidJson);
    }
    Ok(JsonPreflightStats {
        tokens: scanner.tokens,
        maximum_depth: scanner.maximum_depth,
    })
}

struct Scanner<'bytes> {
    bytes: &'bytes [u8],
    index: usize,
    tokens: usize,
    maximum_depth: usize,
    token_limit: usize,
    depth_limit: usize,
}

impl Scanner<'_> {
    fn scan_value(&mut self, depth: usize) -> Result<(), JsonPreflightError> {
        self.count_token()?;
        if depth > self.depth_limit {
            return Err(JsonPreflightError::ContractLimitExceeded);
        }
        self.maximum_depth = self.maximum_depth.max(depth);

        match self.peek() {
            Some(b'{') => self.scan_object(depth),
            Some(b'[') => self.scan_array(depth),
            Some(b'"') => self.scan_string(),
            Some(b't') => self.scan_literal(b"true"),
            Some(b'f') => self.scan_literal(b"false"),
            Some(b'n') => self.scan_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.scan_number(),
            _ => Err(JsonPreflightError::InvalidJson),
        }
    }

    fn scan_object(&mut self, depth: usize) -> Result<(), JsonPreflightError> {
        self.index += 1;
        self.skip_whitespace();
        if self.take(b'}') {
            return Ok(());
        }

        loop {
            if self.peek() != Some(b'"') {
                return Err(JsonPreflightError::InvalidJson);
            }
            // Object keys allocate independently from their associated values,
            // so each key consumes its own preflight token.
            self.count_token()?;
            self.scan_string()?;
            self.skip_whitespace();
            if !self.take(b':') {
                return Err(JsonPreflightError::InvalidJson);
            }
            self.skip_whitespace();
            self.scan_value(depth + 1)?;
            self.skip_whitespace();
            if self.take(b'}') {
                return Ok(());
            }
            if !self.take(b',') {
                return Err(JsonPreflightError::InvalidJson);
            }
            self.skip_whitespace();
        }
    }

    fn scan_array(&mut self, depth: usize) -> Result<(), JsonPreflightError> {
        self.index += 1;
        self.skip_whitespace();
        if self.take(b']') {
            return Ok(());
        }

        loop {
            self.scan_value(depth + 1)?;
            self.skip_whitespace();
            if self.take(b']') {
                return Ok(());
            }
            if !self.take(b',') {
                return Err(JsonPreflightError::InvalidJson);
            }
            self.skip_whitespace();
        }
    }

    fn scan_string(&mut self) -> Result<(), JsonPreflightError> {
        if !self.take(b'"') {
            return Err(JsonPreflightError::InvalidJson);
        }
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.index += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.index += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.index += 1;
                        }
                        Some(b'u') => {
                            self.index += 1;
                            let code_unit = self.scan_hex_quad()?;
                            if (0xd800..=0xdbff).contains(&code_unit) {
                                if !self.take(b'\\') || !self.take(b'u') {
                                    return Err(JsonPreflightError::InvalidJson);
                                }
                                let trailing = self.scan_hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&trailing) {
                                    return Err(JsonPreflightError::InvalidJson);
                                }
                            } else if (0xdc00..=0xdfff).contains(&code_unit) {
                                return Err(JsonPreflightError::InvalidJson);
                            }
                        }
                        _ => return Err(JsonPreflightError::InvalidJson),
                    }
                }
                0x00..=0x1f => return Err(JsonPreflightError::InvalidJson),
                _ => self.index += 1,
            }
        }
        Err(JsonPreflightError::InvalidJson)
    }

    fn scan_hex_quad(&mut self) -> Result<u16, JsonPreflightError> {
        let end = self
            .index
            .checked_add(4)
            .ok_or(JsonPreflightError::InvalidJson)?;
        let escape = self
            .bytes
            .get(self.index..end)
            .ok_or(JsonPreflightError::InvalidJson)?;
        let mut value = 0_u16;
        for &byte in escape {
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(JsonPreflightError::InvalidJson),
            };
            value = value * 16 + digit;
        }
        self.index = end;
        Ok(value)
    }

    fn scan_literal(&mut self, literal: &[u8]) -> Result<(), JsonPreflightError> {
        if self.bytes.get(self.index..self.index + literal.len()) != Some(literal) {
            return Err(JsonPreflightError::InvalidJson);
        }
        self.index += literal.len();
        Ok(())
    }

    fn scan_number(&mut self) -> Result<(), JsonPreflightError> {
        if self.take(b'-') && self.peek().is_none() {
            return Err(JsonPreflightError::InvalidJson);
        }

        match self.peek() {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.index += 1;
                }
            }
            _ => return Err(JsonPreflightError::InvalidJson),
        }

        if self.take(b'.') {
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(JsonPreflightError::InvalidJson);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.index += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(JsonPreflightError::InvalidJson);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.index += 1;
            }
        }
        Ok(())
    }

    fn count_token(&mut self) -> Result<(), JsonPreflightError> {
        self.tokens = self
            .tokens
            .checked_add(1)
            .ok_or(JsonPreflightError::ContractLimitExceeded)?;
        if self.tokens > self.token_limit {
            return Err(JsonPreflightError::ContractLimitExceeded);
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn take(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }
}
