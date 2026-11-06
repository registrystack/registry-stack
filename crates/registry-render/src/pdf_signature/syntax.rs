//! Byte-level reading of the few PDF structures the signature update copies
//! or replaces: the last cross-reference table and its trailer, and the
//! top-level entries of a dictionary.
//!
//! Objects are read with `hayro-syntax`. This code exists because a parsed
//! object model cannot give back the original bytes of an entry, and the
//! update copies every entry it does not replace byte for byte. Callers
//! cross-check the keys found here against `hayro-syntax`.

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
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index].iter().any(|seen| seen.key == entry.key) {
            return Err(malformed("a dictionary repeats a key"));
        }
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
            let pair = raw
                .get(index + 1..index + 3)
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
/// `/Encrypt`, and nothing after `%%EOF` but one optional EOL.
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

    let trailer_at = skip_space(pdf, trailer_keyword + b"trailer".len());
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

    let size = value(b"Size")
        .and_then(parse_uint)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(malformed("the trailer has no numeric /Size"))?;
    let offsets = cover(&subsections, size)?;
    for (number, offset) in offsets.iter().enumerate() {
        if let Some(offset) = offset {
            if *offset >= xref_offset || !object_header_matches(pdf, *offset, number) {
                return Err(malformed(
                    "a cross-reference entry does not point at its object",
                ));
            }
        }
    }

    let (root, root_generation) = value(b"Root")
        .and_then(reference)
        .ok_or(malformed("the trailer has no /Root reference"))?;
    if root_generation != 0 || offsets.get(root as usize).is_none_or(Option::is_none) {
        return Err(malformed("the trailer /Root names no object"));
    }

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
    let xref_offset = parse_uint(&pdf[digits_start..digits_stop])
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
    let offset = parse_uint(&entry[..10]);
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

/// Whether `<number> 0 obj` starts at `offset`.
fn object_header_matches(pdf: &[u8], offset: usize, number: usize) -> bool {
    let number_end = digits_end(pdf, offset);
    if parse_uint(&pdf[offset..number_end]) != Some(number as u64) {
        return false;
    }
    let generation_start = skip_whitespace(pdf, number_end);
    let generation_end = digits_end(pdf, generation_start);
    if generation_start == number_end || &pdf[generation_start..generation_end] != b"0" {
        return false;
    }
    let keyword = skip_whitespace(pdf, generation_end);
    keyword > generation_end && pdf[keyword..].starts_with(b"obj") && ends_token(pdf, keyword + 3)
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

    fn minimal_pdf(trailer_extra: &str) -> Vec<u8> {
        let mut pdf = b"%PDF-2.0\n".to_vec();
        let catalog = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n");
        let pages = pdf.len();
        pdf.extend_from_slice(b"2 0 obj\n<</Type/Pages/Count 0/Kids[]>>\nendobj\n");
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
        ];
        for (label, input) in cases {
            match read_revision(input.as_bytes()) {
                Err(PdfSignatureError::Malformed(_)) => {}
                other => panic!("{label}: expected Malformed, got {other:?}"),
            }
        }
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
