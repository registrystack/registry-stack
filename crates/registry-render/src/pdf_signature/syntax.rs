//! Byte-level reading of the few PDF structures the signature update copies
//! or replaces: the last cross-reference table and its trailer, and the
//! top-level entries of a dictionary.
//!
//! Objects are read with `hayro-syntax`. This code exists because a parsed
//! object model cannot give back the original bytes of an entry, and the
//! update copies every entry it does not replace byte for byte. Callers
//! cross-check the keys found here against `hayro-syntax`. Reading the
//! revision also walks every object in use with a nesting bound, and the
//! page tree with a depth bound and each node once, because `hayro-syntax`
//! recurses through both without one and a stack overflow aborts.
//!
//! The reader accepts only files whose cross-reference table, trailer and
//! objects `hayro-syntax` 0.7.2 reads as written. When it cannot, it
//! rebuilds the table by scanning every byte of the file and reading what
//! follows each `N G obj` without a depth bound, stream data included, so
//! each rule here that is stricter than PDF needs says which reading of
//! `hayro-syntax` it mirrors. The workspace pins that version: a new one
//! has to be read again against these rules.

use std::ops::Range;

use super::PdfSignatureError;

/// Nesting bound for arrays and dictionaries inside a value; deeper input is
/// refused rather than recursed into.
const MAX_DEPTH: usize = 32;

fn malformed(reason: &'static str) -> PdfSignatureError {
    PdfSignatureError::Malformed(reason)
}

/// White-space characters (ISO 32000-2 7.2.3, Table 1).
fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// Delimiter characters (ISO 32000-2 7.2.3, Table 2).
fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(byte: u8) -> bool {
    !is_whitespace(byte) && !is_delimiter(byte)
}

/// Skip white-space and comments starting at `at`.
pub(super) fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while let Some(&byte) = bytes.get(at) {
        if is_whitespace(byte) {
            at += 1;
        } else if byte == b'%' {
            while bytes.get(at).is_some_and(|b| *b != b'\r' && *b != b'\n') {
                at += 1;
            }
        } else {
            break;
        }
    }
    at
}

fn skip_whitespace(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).copied().is_some_and(is_whitespace) {
        at += 1;
    }
    at
}

fn ends_token(bytes: &[u8], at: usize) -> bool {
    bytes.get(at).is_none_or(|b| !is_regular(*b))
}

fn digits_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    at
}

/// Parse a run of ASCII digits as an unsigned integer.
pub(super) fn parse_uint(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// One top-level dictionary entry. `key` is the decoded name without its
/// slash; `start` is the offset of the slash and `value` the span of the
/// value, both into the bytes the dictionary was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub key: Vec<u8>,
    pub start: usize,
    pub value: Range<usize>,
}

/// Read the dictionary that starts at `at` (which must be `<<`) and return
/// its top-level entries and the offset just after its closing `>>`.
/// A repeated key is refused: which value counts would be undefined.
pub(super) fn dict_entries(
    bytes: &[u8],
    at: usize,
) -> Result<(Vec<Entry>, usize), PdfSignatureError> {
    let (entries, end) = dict_at(bytes, at, 0)?;
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    if !entries
        .iter()
        .all(|entry| seen.insert(entry.key.as_slice()))
    {
        return Err(malformed("a dictionary repeats a key"));
    }
    Ok((entries, end))
}

/// Read the array that starts at `at` (which must be `[`) and return the
/// spans of its elements and the offset just after its closing `]`.
pub(super) fn array_elements(
    bytes: &[u8],
    at: usize,
) -> Result<(Vec<Range<usize>>, usize), PdfSignatureError> {
    array_at(bytes, at, 0)
}

/// Parse exactly `<number> <generation> R`, surrounded by nothing.
pub(super) fn reference(bytes: &[u8]) -> Option<(u32, u16)> {
    let number_end = digits_end(bytes, 0);
    let number = parse_uint(&bytes[..number_end])?;
    let generation_start = skip_whitespace(bytes, number_end);
    if generation_start == number_end {
        return None;
    }
    let generation_end = digits_end(bytes, generation_start);
    let generation = parse_uint(&bytes[generation_start..generation_end])?;
    let r_at = skip_whitespace(bytes, generation_end);
    if r_at == generation_end || bytes.get(r_at..) != Some(&b"R"[..]) {
        return None;
    }
    Some((u32::try_from(number).ok()?, u16::try_from(generation).ok()?))
}

fn value_at(bytes: &[u8], at: usize, depth: usize) -> Result<usize, PdfSignatureError> {
    if depth > MAX_DEPTH {
        return Err(malformed("objects nest too deeply"));
    }
    let Some(&first) = bytes.get(at) else {
        return Err(malformed("an object is cut off"));
    };
    match first {
        b'/' => name_at(bytes, at).map(|(_, end)| end),
        b'(' => literal_string_end(bytes, at),
        b'<' if bytes.get(at + 1) == Some(&b'<') => dict_at(bytes, at, depth).map(|(_, end)| end),
        b'<' => hex_string_end(bytes, at),
        b'[' => array_at(bytes, at, depth).map(|(_, end)| end),
        b'0'..=b'9' | b'+' | b'-' | b'.' => number_or_reference_end(bytes, at),
        byte if is_regular(byte) => keyword_end(bytes, at),
        _ => Err(malformed("an object starts with an unexpected delimiter")),
    }
}

/// Read the name at `at` (the slash) and return it decoded, with the offset
/// just after it.
fn name_at(bytes: &[u8], at: usize) -> Result<(Vec<u8>, usize), PdfSignatureError> {
    let mut end = at + 1;
    while bytes.get(end).copied().is_some_and(is_regular) {
        end += 1;
    }
    let raw = &bytes[at + 1..end];
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'#' {
            // Exactly two hexadecimal digits (ISO 32000-2 7.3.5); a sign
            // that `from_str_radix` would accept is not one.
            let pair = raw
                .get(index + 1..index + 3)
                .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or(malformed("a name has a broken # escape"))?;
            decoded.push(pair);
            index += 3;
        } else {
            decoded.push(raw[index]);
            index += 1;
        }
    }
    Ok((decoded, end))
}

fn literal_string_end(bytes: &[u8], at: usize) -> Result<usize, PdfSignatureError> {
    let mut depth = 0usize;
    let mut index = at;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => index += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    Err(malformed("a literal string is not closed"))
}

fn hex_string_end(bytes: &[u8], at: usize) -> Result<usize, PdfSignatureError> {
    let mut index = at + 1;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'>' {
            return Ok(index + 1);
        }
        if !byte.is_ascii_hexdigit() && !is_whitespace(byte) {
            return Err(malformed("a hex string holds a non-hex character"));
        }
        index += 1;
    }
    Err(malformed("a hex string is not closed"))
}

fn array_at(
    bytes: &[u8],
    at: usize,
    depth: usize,
) -> Result<(Vec<Range<usize>>, usize), PdfSignatureError> {
    if bytes.get(at) != Some(&b'[') {
        return Err(malformed("an array does not start with ["));
    }
    let mut elements = Vec::new();
    let mut index = at + 1;
    loop {
        index = skip_space(bytes, index);
        match bytes.get(index) {
            None => return Err(malformed("an array is not closed")),
            Some(b']') => return Ok((elements, index + 1)),
            Some(_) => {
                let end = value_at(bytes, index, depth + 1)?;
                elements.push(index..end);
                index = end;
            }
        }
    }
}

fn dict_at(
    bytes: &[u8],
    at: usize,
    depth: usize,
) -> Result<(Vec<Entry>, usize), PdfSignatureError> {
    if bytes.get(at..at + 2) != Some(&b"<<"[..]) {
        return Err(malformed("a dictionary does not start with <<"));
    }
    let mut entries = Vec::new();
    let mut index = at + 2;
    loop {
        index = skip_space(bytes, index);
        match bytes.get(index) {
            None => return Err(malformed("a dictionary is not closed")),
            Some(b'>') if bytes.get(index + 1) == Some(&b'>') => {
                return Ok((entries, index + 2));
            }
            Some(b'/') => {
                let (key, key_end) = name_at(bytes, index)?;
                let value_start = skip_space(bytes, key_end);
                let value_end = value_at(bytes, value_start, depth + 1)?;
                entries.push(Entry {
                    key,
                    start: index,
                    value: value_start..value_end,
                });
                index = value_end;
            }
            Some(_) => return Err(malformed("a dictionary key is not a name")),
        }
    }
}

fn number_or_reference_end(bytes: &[u8], at: usize) -> Result<usize, PdfSignatureError> {
    let mut index = at;
    if matches!(bytes.get(index), Some(b'+' | b'-')) {
        index += 1;
    }
    let integer_end = digits_end(bytes, index);
    let mut end = integer_end;
    if bytes.get(end) == Some(&b'.') {
        end = digits_end(bytes, end + 1);
    }
    let has_digit = bytes[index..end].iter().any(u8::is_ascii_digit);
    if !has_digit || !ends_token(bytes, end) {
        return Err(malformed("a number is malformed"));
    }
    if index != at || end != integer_end {
        return Ok(end);
    }
    // An unsigned integer may open `<number> <generation> R`.
    let generation_start = skip_whitespace(bytes, end);
    if generation_start == end {
        return Ok(end);
    }
    let generation_end = digits_end(bytes, generation_start);
    if generation_end == generation_start || !ends_token(bytes, generation_end) {
        return Ok(end);
    }
    let r_at = skip_whitespace(bytes, generation_end);
    if r_at > generation_end && bytes.get(r_at) == Some(&b'R') && ends_token(bytes, r_at + 1) {
        return Ok(r_at + 1);
    }
    Ok(end)
}

fn keyword_end(bytes: &[u8], at: usize) -> Result<usize, PdfSignatureError> {
    let mut end = at;
    while bytes.get(end).copied().is_some_and(is_regular) {
        end += 1;
    }
    match &bytes[at..end] {
        b"true" | b"false" | b"null" => Ok(end),
        _ => Err(malformed("a value is an unknown keyword")),
    }
}

/// The last revision of a file that has exactly one: its cross-reference
/// table, the trailer entries, and where the pieces sit.
#[derive(Debug)]
pub(super) struct Revision {
    /// Offset of the `xref` keyword, the value of `startxref`.
    pub xref_offset: usize,
    /// The trailer's `/Size`: object numbers run from 0 to `size - 1`.
    pub size: u32,
    /// Trailer entries, spans into the file.
    pub trailer: Vec<Entry>,
    /// The catalog named by the trailer's `/Root`.
    pub root: u32,
    /// The span of the first `/ID` element, copied into the update verbatim.
    pub id_first: Range<usize>,
}

struct Subsection {
    first: u64,
    entries: Vec<XrefEntry>,
}

struct XrefEntry {
    offset: u64,
    generation: u64,
    in_use: bool,
}

/// Read the single revision of `pdf`: a header, one cross-reference table
/// covering every object, a trailer without `/Prev`, `/XRefStm` or
/// `/Encrypt`, and nothing after `%%EOF` but one optional EOL. The value of
/// every object in use must read as a PDF value nested at most `MAX_DEPTH`
/// deep that ends before the table; a stream must be one `hayro-syntax`
/// reads (`check_stream`), and its data is not read. Every offset, `startxref` and `/Size` must fit the 32-bit
/// numbers `hayro-syntax` reads them as. The page tree
/// must nest at most `MAX_PAGE_TREE_DEPTH` nodes deep and reach each node
/// once.
pub(super) fn read_revision(pdf: &[u8]) -> Result<Revision, PdfSignatureError> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(malformed("the file does not start with a %PDF- header"));
    }
    let (startxref_at, xref_offset) = read_tail(pdf)?;
    if xref_offset >= startxref_at {
        return Err(malformed(
            "startxref points past the cross-reference section",
        ));
    }
    if !pdf[xref_offset..].starts_with(b"xref") {
        if pdf[xref_offset].is_ascii_digit() {
            return Err(PdfSignatureError::CrossReferenceStream);
        }
        return Err(malformed(
            "startxref does not point at a cross-reference table",
        ));
    }
    let (subsections, trailer_keyword) = read_xref_table(pdf, xref_offset + 4, startxref_at)?;

    // `hayro-syntax` allows white-space here but not a comment.
    let trailer_at = skip_whitespace(pdf, trailer_keyword + b"trailer".len());
    let (trailer, trailer_end) = dict_entries(&pdf[..startxref_at], trailer_at)?;
    if skip_space(pdf, trailer_end) != startxref_at {
        return Err(malformed("bytes sit between the trailer and startxref"));
    }
    let value = |key: &[u8]| {
        trailer
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| &pdf[entry.value.clone()])
    };
    if value(b"Encrypt").is_some() {
        return Err(PdfSignatureError::Encrypted);
    }
    if value(b"Prev").is_some() || value(b"XRefStm").is_some() {
        return Err(PdfSignatureError::NotSingleRevision);
    }

    // `hayro-syntax` numbers objects with 32-bit signed numbers.
    let size = value(b"Size")
        .and_then(parse_uint)
        .filter(|size| i32::try_from(*size).is_ok())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(malformed("the trailer has no numeric /Size"))?;
    let offsets = cover(&subsections, size)?;
    let last_endstream = pdf[..xref_offset]
        .windows(b"endstream".len())
        .rposition(|window| window == b"endstream");
    let mut values = Vec::with_capacity(offsets.len());
    for (number, offset) in offsets.iter().enumerate() {
        let Some(offset) = offset else {
            values.push(None);
            continue;
        };
        let body = (*offset < xref_offset)
            .then(|| object_body_at(pdf, *offset, number))
            .flatten()
            .ok_or(malformed(
                "a cross-reference entry does not point at its object",
            ))?;
        // `hayro-syntax` recurses without a depth limit; walking every
        // object here first keeps its recursion within `MAX_DEPTH`. The
        // value is read in the whole file, as `hayro-syntax` reads it, so
        // a token that runs on into `xref` is one token here too.
        let value = skip_space(pdf, body);
        let end = value_at(pdf, value, 0)?;
        if end > xref_offset {
            return Err(malformed("an object runs into the cross-reference table"));
        }
        if pdf[value..].starts_with(b"<<") {
            check_stream(&pdf[..xref_offset], value, end, last_endstream)?;
        }
        values.push(Some(value));
    }

    let (root, root_generation) = value(b"Root")
        .and_then(reference)
        .ok_or(malformed("the trailer has no /Root reference"))?;
    if root_generation != 0 || offsets.get(root as usize).is_none_or(Option::is_none) {
        return Err(malformed("the trailer /Root names no object"));
    }
    check_page_tree(&pdf[..xref_offset], &values, root)?;

    let id = trailer
        .iter()
        .find(|entry| entry.key == b"ID")
        .ok_or(malformed("the trailer has no /ID"))?;
    let (ids, ids_end) = array_elements(pdf, id.value.start)?;
    let is_string = |span: &Range<usize>| {
        pdf[span.start] == b'('
            || (pdf[span.start] == b'<' && pdf.get(span.start + 1) != Some(&b'<'))
    };
    if ids_end != id.value.end || ids.len() != 2 || !ids.iter().all(is_string) {
        return Err(malformed("the trailer /ID is not two strings"));
    }

    Ok(Revision {
        xref_offset,
        size,
        trailer,
        root,
        id_first: ids[0].clone(),
    })
}

/// Find the last `startxref` and parse `startxref EOL offset EOL %%EOF`
/// with at most one EOL after it. Returns the keyword's offset and the
/// cross-reference offset.
fn read_tail(pdf: &[u8]) -> Result<(usize, usize), PdfSignatureError> {
    let startxref_at = pdf
        .windows(b"startxref".len())
        .rposition(|window| window == b"startxref")
        .ok_or(malformed("the file has no startxref"))?;
    let digits_start = skip_whitespace(pdf, startxref_at + b"startxref".len());
    let digits_stop = digits_end(pdf, digits_start);
    // `hayro-syntax` reads the offset as a 32-bit signed number.
    let xref_offset = parse_uint(&pdf[digits_start..digits_stop])
        .and_then(|offset| i32::try_from(offset).ok())
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(malformed("startxref has no offset"))?;
    let eof_at = skip_whitespace(pdf, digits_stop);
    if eof_at == digits_stop || !pdf[eof_at..].starts_with(b"%%EOF") {
        return Err(malformed("the file does not end with %%EOF"));
    }
    match &pdf[eof_at + b"%%EOF".len()..] {
        b"" | b"\n" | b"\r" | b"\r\n" => Ok((startxref_at, xref_offset)),
        _ => Err(malformed("bytes follow the last %%EOF")),
    }
}

/// Read cross-reference subsections from `at` (just after `xref`) up to the
/// `trailer` keyword, and return them with the keyword's offset.
fn read_xref_table(
    pdf: &[u8],
    mut at: usize,
    limit: usize,
) -> Result<(Vec<Subsection>, usize), PdfSignatureError> {
    let table = &pdf[..limit];
    let mut subsections = Vec::new();
    loop {
        at = skip_whitespace(table, at);
        if table[at..].starts_with(b"trailer") {
            return Ok((subsections, at));
        }
        let first_end = digits_end(table, at);
        let first = parse_uint(&table[at..first_end]);
        if table.get(first_end) != Some(&b' ') {
            return Err(malformed(
                "a cross-reference subsection header is malformed",
            ));
        }
        let count_start = first_end + 1;
        let count_end = digits_end(table, count_start);
        let count = parse_uint(&table[count_start..count_end]);
        let (Some(first), Some(count)) = (first, count) else {
            return Err(malformed(
                "a cross-reference subsection header is malformed",
            ));
        };
        at = skip_whitespace(table, count_end);
        if at == count_end {
            return Err(malformed(
                "a cross-reference subsection header is malformed",
            ));
        }
        let length = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(20))
            .filter(|length| {
                at.checked_add(*length)
                    .is_some_and(|end| end <= table.len())
            })
            .ok_or(malformed("a cross-reference subsection is cut off"))?;
        let entries = table[at..at + length]
            .chunks_exact(20)
            .map(xref_entry)
            .collect::<Result<Vec<_>, _>>()?;
        at += length;
        subsections.push(Subsection { first, entries });
    }
}

fn xref_entry(entry: &[u8]) -> Result<XrefEntry, PdfSignatureError> {
    let shaped = entry[10] == b' '
        && entry[16] == b' '
        && matches!(&entry[18..20], b" \r" | b" \n" | b"\r\n");
    // `hayro-syntax` reads every entry's offset, free or in use, as a
    // 32-bit number and drops the whole table when one does not fit.
    let offset = parse_uint(&entry[..10]).filter(|offset| u32::try_from(*offset).is_ok());
    let generation = parse_uint(&entry[11..16]);
    match (shaped, offset, generation, entry[17]) {
        (true, Some(offset), Some(generation), kind @ (b'n' | b'f')) => Ok(XrefEntry {
            offset,
            generation,
            in_use: kind == b'n',
        }),
        _ => Err(malformed("a cross-reference entry is malformed")),
    }
}

/// Check the subsections cover objects `0..size` exactly once, with a free
/// object 0 and generation 0 for every object in use, and return the offset
/// of each object in use.
fn cover(subsections: &[Subsection], size: u32) -> Result<Vec<Option<usize>>, PdfSignatureError> {
    let mut ordered: Vec<&Subsection> = subsections.iter().collect();
    ordered.sort_by_key(|subsection| subsection.first);
    let mut offsets = Vec::new();
    for subsection in ordered {
        if subsection.first != offsets.len() as u64 {
            return Err(malformed(
                "the cross-reference table does not cover every object exactly once",
            ));
        }
        for entry in &subsection.entries {
            let number = offsets.len();
            if number == 0 {
                if entry.in_use || entry.generation != 65535 {
                    return Err(malformed("object 0 is not the free-list head"));
                }
                offsets.push(None);
            } else if entry.in_use {
                if entry.generation != 0 {
                    return Err(malformed("an object in use has a non-zero generation"));
                }
                let offset = usize::try_from(entry.offset)
                    .map_err(|_| malformed("a cross-reference offset is too large"))?;
                offsets.push(Some(offset));
            } else {
                offsets.push(None);
            }
        }
    }
    if offsets.len() as u64 != u64::from(size) {
        return Err(malformed(
            "the cross-reference table does not cover every object exactly once",
        ));
    }
    Ok(offsets)
}

/// If the dictionary at `dict..dict_end` opens a stream, check it is one
/// `hayro-syntax` reads. Its stream reader gives up on a stream that names
/// an external file, one whose `stream` keyword is not followed by an
/// end-of-line, and one with no `endstream` after its data; an object it
/// gives up on is missing from its object list, which is all the signature
/// check sees. `/FFilter` and `/FDecodeParms` belong to an external file
/// too. A comment before the keyword is refused because the reader's
/// fallback finds the first `stream` after the dictionary, comments
/// included. `last_endstream` is the offset of the last `endstream` in
/// `objects`. The stream's data is not read.
fn check_stream(
    objects: &[u8],
    dict: usize,
    dict_end: usize,
    last_endstream: Option<usize>,
) -> Result<(), PdfSignatureError> {
    let keyword = skip_space(objects, dict_end);
    if !objects[keyword..].starts_with(b"stream") {
        return Ok(());
    }
    if skip_whitespace(objects, dict_end) != keyword {
        return Err(malformed("a comment sits before a stream keyword"));
    }
    let after = keyword + b"stream".len();
    let data = match &objects[after..] {
        [b'\r', b'\n', ..] => after + 2,
        [b'\n', ..] => after + 1,
        _ => {
            return Err(malformed(
                "a stream keyword is not followed by an end-of-line",
            ));
        }
    };
    if last_endstream.is_none_or(|at| at < data) {
        return Err(malformed("a stream has no endstream"));
    }
    let (entries, _) = dict_entries(objects, dict)?;
    if entries
        .iter()
        .any(|entry| matches!(entry.key.as_slice(), b"F" | b"FFilter" | b"FDecodeParms"))
    {
        return Err(malformed("a stream names an external file"));
    }
    Ok(())
}

/// If `<number> 0 obj` starts at `offset`, the offset just after `obj`.
fn object_body_at(pdf: &[u8], offset: usize, number: usize) -> Option<usize> {
    let number_end = digits_end(pdf, offset);
    if parse_uint(&pdf[offset..number_end]) != Some(number as u64) {
        return None;
    }
    let generation_start = skip_whitespace(pdf, number_end);
    let generation_end = digits_end(pdf, generation_start);
    if generation_start == number_end || &pdf[generation_start..generation_end] != b"0" {
        return None;
    }
    let keyword = skip_whitespace(pdf, generation_end);
    (keyword > generation_end && pdf[keyword..].starts_with(b"obj") && ends_token(pdf, keyword + 3))
        .then_some(keyword + 3)
}

/// Walk the page tree from the catalog's `/Pages` through every `/Kids`
/// reference, at most `MAX_PAGE_TREE_DEPTH` nodes deep, reaching each node
/// once. `hayro-syntax` builds its page list when it opens a file,
/// recursing once per level and visiting a shared node once per parent:
/// a deep chain of shallow objects aborts it on a stack overflow, a cycle
/// never ends, and a node with two parents multiplies its work. The walk
/// follows `/Kids` whatever a node's `/Type` says, so it reaches every node
/// `hayro-syntax` recurses into.
///
/// `values[number]` is the offset in `objects` of object `number`'s value.
fn check_page_tree(
    objects: &[u8],
    values: &[Option<usize>],
    root: u32,
) -> Result<(), PdfSignatureError> {
    let entries_of = |number: u32, not_a_dict: &'static str| -> Result<Vec<Entry>, _> {
        let at = values
            .get(number as usize)
            .copied()
            .flatten()
            .ok_or(malformed("a page tree reference names no object"))?;
        if objects.get(at..at + 2) != Some(&b"<<"[..]) {
            return Err(malformed(not_a_dict));
        }
        dict_entries(objects, at).map(|(entries, _)| entries)
    };
    let object_number = |span: Range<usize>| match reference(&objects[span]) {
        Some((number, 0)) => Ok(number),
        _ => Err(malformed(
            "a page tree reference is not an object reference",
        )),
    };

    let catalog = entries_of(root, "the catalog is not a dictionary")?;
    let pages = catalog
        .iter()
        .find(|entry| entry.key == b"Pages")
        .ok_or(malformed("the catalog has no page tree"))?;
    let mut reached = vec![false; values.len()];
    let mut pending = vec![(object_number(pages.value.clone())?, 1)];
    while let Some((number, depth)) = pending.pop() {
        if depth > super::MAX_PAGE_TREE_DEPTH {
            return Err(malformed("the page tree nests too deeply"));
        }
        let entries = entries_of(number, "a page tree node is not a dictionary")?;
        if std::mem::replace(&mut reached[number as usize], true) {
            return Err(malformed("the page tree reaches a node twice"));
        }
        let Some(kids) = entries.iter().find(|entry| entry.key == b"Kids") else {
            continue;
        };
        if objects[kids.value.start] != b'[' {
            return Err(malformed("a page tree node's /Kids is not an array"));
        }
        for kid in array_elements(objects, kids.value.start)?.0 {
            pending.push((object_number(kid)?, depth + 1));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(entries: &[Entry]) -> Vec<&[u8]> {
        entries.iter().map(|entry| entry.key.as_slice()).collect()
    }

    #[test]
    fn dict_entries_keep_spans_of_every_value_kind() {
        let dict = b"<</Type/Page/Rect[0 0 595.2756 841.8898]/P 12 0 R/N -3 /S(a (nested) \\) string)/H<0aF3>/D<</K[1 2]>>/B true/Z null%c\n/E/#41#62>>";
        let (entries, end) = dict_entries(dict, 0).expect("entries");
        assert_eq!(end, dict.len());
        assert_eq!(
            keys(&entries),
            vec![
                &b"Type"[..],
                b"Rect",
                b"P",
                b"N",
                b"S",
                b"H",
                b"D",
                b"B",
                b"Z",
                b"E"
            ]
        );
        let values: Vec<&[u8]> = entries.iter().map(|e| &dict[e.value.clone()]).collect();
        assert_eq!(
            values,
            vec![
                &b"/Page"[..],
                b"[0 0 595.2756 841.8898]",
                b"12 0 R",
                b"-3",
                b"(a (nested) \\) string)",
                b"<0aF3>",
                b"<</K[1 2]>>",
                b"true",
                b"null",
                b"/#41#62",
            ]
        );
        assert_eq!(&dict[entries[0].start..entries[0].start + 5], b"/Type");
    }

    #[test]
    fn names_are_decoded_for_key_comparison() {
        let (entries, _) = dict_entries(b"<</Ann#6Fts[1 0 R]>>", 0).expect("entries");
        assert_eq!(keys(&entries), vec![&b"Annots"[..]]);
    }

    #[test]
    fn references_and_numbers_split_where_pdf_splits_them() {
        assert!(
            array_elements(b"[1.5 0 R]", 0).is_err(),
            "R after a real is not a value"
        );
        let array = b"[1 2 3 0 R 4 -1 0]";
        let (elements, _) = array_elements(array, 0).expect("array");
        let text: Vec<&[u8]> = elements.iter().map(|span| &array[span.clone()]).collect();
        assert_eq!(text, vec![&b"1"[..], b"2", b"3 0 R", b"4", b"-1", b"0"]);
        assert_eq!(reference(b"63 0 R"), Some((63, 0)));
        assert_eq!(reference(b"63 0 R "), None);
        assert_eq!(reference(b"63 0R"), None);
        assert_eq!(reference(b"-1 0 R"), None);
    }

    #[test]
    fn malformed_values_are_refused_not_panicked_on() {
        for input in [
            &b"<</A"[..],
            b"<</A (open>>",
            b"<</A <0g>>>",
            b"<</A [1 2>>",
            b"<</A 1.2.3>>",
            b"<</A bogus>>",
            b"<</A /B#4>>",
            b"<</A /B#+F>>",
            b"<</#+F 1>>",
            b"<<(key) 1>>",
            b"<</A 1/A 2>>",
            b"<</A )>>",
            b"<",
            b"",
        ] {
            assert!(
                dict_entries(input, 0).is_err(),
                "{:?} should be refused",
                String::from_utf8_lossy(input)
            );
        }
        let mut deep = Vec::new();
        deep.extend_from_slice(b"<</A ");
        deep.extend(std::iter::repeat_n(b'[', 64));
        deep.extend(std::iter::repeat_n(b']', 64));
        deep.extend_from_slice(b">>");
        assert!(dict_entries(&deep, 0).is_err());
    }

    /// A repeated key is found in one pass: a dictionary with many keys
    /// costs time in proportion to its keys, not their square.
    #[test]
    fn a_wide_dictionary_is_checked_for_repeated_keys_in_linear_time() {
        let keys = 200_000;
        let mut wide = b"<<".to_vec();
        for key in 0..keys {
            wide.extend_from_slice(format!("/K{key} 1").as_bytes());
        }
        let unique_end = wide.len();
        wide.extend_from_slice(b">>");
        let started = std::time::Instant::now();
        let (entries, _) = dict_entries(&wide, 0).expect("distinct keys");
        assert_eq!(entries.len(), keys);
        let mut repeated = wide[..unique_end].to_vec();
        repeated.extend_from_slice(b"/K0 2>>");
        assert!(dict_entries(&repeated, 0).is_err(), "the repeat is found");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "two passes over {keys} keys took {:?}",
            started.elapsed()
        );
    }

    fn minimal_pdf(trailer_extra: &str) -> Vec<u8> {
        minimal_pdf_with("", "", trailer_extra)
    }

    /// A minimal file with `catalog_extra` and `pages_extra` appended to the
    /// catalog and page tree dictionaries.
    fn minimal_pdf_with(catalog_extra: &str, pages_extra: &str, trailer_extra: &str) -> Vec<u8> {
        let mut pdf = b"%PDF-2.0\n".to_vec();
        let catalog = pdf.len();
        pdf.extend_from_slice(
            format!("1 0 obj\n<</Type/Catalog/Pages 2 0 R{catalog_extra}>>\nendobj\n").as_bytes(),
        );
        let pages = pdf.len();
        pdf.extend_from_slice(
            format!("2 0 obj\n<</Type/Pages/Count 0/Kids[]{pages_extra}>>\nendobj\n").as_bytes(),
        );
        let xref = pdf.len();
        pdf.extend_from_slice(
            format!(
                "xref\n0 3\n0000000000 65535 f\r\n{catalog:010} 00000 n\r\n{pages:010} 00000 n\r\ntrailer\n<</Size 3/Root 1 0 R/ID[(a)<0b>]{trailer_extra}>>\nstartxref\n{xref}\n%%EOF"
            )
            .as_bytes(),
        );
        pdf
    }

    #[test]
    fn read_revision_reads_a_minimal_single_revision() {
        let pdf = minimal_pdf("");
        let revision = read_revision(&pdf).expect("revision");
        assert_eq!(revision.size, 3);
        assert_eq!(revision.root, 1);
        assert_eq!(&pdf[revision.id_first.clone()], b"(a)");
        assert!(pdf[revision.xref_offset..].starts_with(b"xref\n"));
        assert_eq!(keys(&revision.trailer), vec![&b"Size"[..], b"Root", b"ID"]);
    }

    /// Every object in use is walked with the nesting bound before any
    /// other reader sees it, the catalog and the objects it does not name
    /// alike.
    #[test]
    fn read_revision_refuses_an_object_nested_past_the_bound() {
        let deep = format!("/Deep{}{}", "[".repeat(64), "]".repeat(64));
        for (label, input) in [
            ("catalog", minimal_pdf_with(&deep, "", "")),
            ("page tree", minimal_pdf_with("", &deep, "")),
        ] {
            assert_eq!(
                read_revision(&input).unwrap_err(),
                PdfSignatureError::Malformed("objects nest too deeply"),
                "{label}"
            );
        }
        let shallow = format!("/Deep{}{}", "[".repeat(8), "]".repeat(8));
        read_revision(&minimal_pdf_with(&shallow, &shallow, "")).expect("within the bound");
    }

    #[test]
    fn read_revision_names_encryption_and_extra_revisions() {
        assert_eq!(
            read_revision(&minimal_pdf("/Encrypt 9 0 R")).unwrap_err(),
            PdfSignatureError::Encrypted
        );
        assert_eq!(
            read_revision(&minimal_pdf("/Prev 9")).unwrap_err(),
            PdfSignatureError::NotSingleRevision
        );
        assert_eq!(
            read_revision(&minimal_pdf("/XRefStm 9")).unwrap_err(),
            PdfSignatureError::NotSingleRevision
        );
    }

    #[test]
    fn read_revision_refuses_shapes_it_does_not_understand() {
        let good = minimal_pdf("");
        let text = String::from_utf8(good.clone()).expect("ascii");
        let cases = [
            ("no ID", text.replace("/ID[(a)<0b>]", "")),
            ("one ID", text.replace("/ID[(a)<0b>]", "/ID[(a)]")),
            ("size too small", text.replace("/Size 3", "/Size 2")),
            ("size too large", text.replace("/Size 3", "/Size 4")),
            ("no root", text.replace("/Root 1 0 R", "")),
            (
                "root not in use",
                text.replace("/Root 1 0 R", "/Root 0 0 R"),
            ),
            (
                "generation",
                text.replace("00000 n\r\n0000", "00001 n\r\n0000"),
            ),
            (
                "free head",
                text.replace("0000000000 65535 f", "0000000000 00000 f"),
            ),
            (
                "wrong offset",
                text.replace("0000000009 00000 n", "0000000010 00000 n"),
            ),
            ("short entry", text.replace("65535 f\r\n", "65535 f\n")),
            ("bytes after EOF", format!("{text}\n\n")),
            ("comment after EOF", format!("{text}\n%x")),
            ("no header", text.replacen("%PDF-", "%PDX-", 1)),
            (
                "junk before startxref",
                text.replace(">>\nstartxref", ">>\njunk\nstartxref"),
            ),
            (
                "huge subsection count",
                text.replace("xref\n0 3\n", "xref\n0 922337203685477580\n"),
            ),
            (
                "overflowing subsection count",
                text.replace("xref\n0 3\n", "xref\n0 9999999999999999999\n"),
            ),
            (
                "free entry offset past 32 bits",
                text.replace("0000000000 65535 f", "9999999999 65535 f"),
            ),
            (
                "comment before the trailer dictionary",
                text.replace("trailer\n<<", "trailer\n%c\n<<"),
            ),
        ];
        for (label, input) in cases {
            match read_revision(input.as_bytes()) {
                Err(PdfSignatureError::Malformed(_)) => {}
                other => panic!("{label}: expected Malformed, got {other:?}"),
            }
        }
    }

    /// `hayro-syntax` reads `startxref` and object numbers as 32-bit signed
    /// numbers and rebuilds the table when one does not fit, so the bounded
    /// reader refuses what it would not read as written. Only a file of
    /// gigabytes reaches either bound, so each is checked where it is read.
    #[test]
    fn startxref_and_size_fit_what_hayro_syntax_reads() {
        assert_eq!(
            read_tail(b"startxref\n2147483647\n%%EOF"),
            Ok((0, 2_147_483_647))
        );
        assert_eq!(
            read_tail(b"startxref\n2147483648\n%%EOF"),
            Err(malformed("startxref has no offset"))
        );
        let text = String::from_utf8(minimal_pdf("")).expect("ascii");
        assert_eq!(
            read_revision(text.replace("/Size 3", "/Size 2147483648").as_bytes()).unwrap_err(),
            malformed("the trailer has no numeric /Size")
        );
    }

    #[test]
    fn read_revision_names_a_cross_reference_stream() {
        let good = minimal_pdf("");
        let text = String::from_utf8(good).expect("ascii");
        let at = text.find("xref\n").expect("xref");
        // The object now sits where startxref points, as an xref stream would.
        let stream = format!(
            "{}3 0 obj\n<</Type/XRef>>stream\nendstream\nendobj\n{}",
            &text[..at],
            &text[at..]
        );
        assert_eq!(
            read_revision(stream.as_bytes()).unwrap_err(),
            PdfSignatureError::CrossReferenceStream
        );
    }
}
