// SPDX-License-Identifier: Apache-2.0

//! Signed-PDF extraction shared only by tests that inspect Render seals.

/// The two byte ranges a PDF signature covers and the DER CMS carried in its
/// `/Contents` string. `reserved` includes the CMS and its zero padding.
pub struct SignedFile {
    pub signed_parts: [Vec<u8>; 2],
    pub cms_der: Vec<u8>,
    pub reserved: usize,
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The length of a DER value from its tag and length octets.
fn der_len(der: &[u8]) -> usize {
    assert_eq!(der[0], 0x30, "a CMS ContentInfo is a SEQUENCE");
    match der[1] {
        short if short < 0x80 => 2 + usize::from(short),
        long => {
            let count = usize::from(long & 0x7f);
            let length = der[2..2 + count]
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            2 + count + length
        }
    }
}

/// Read the signed byte ranges and CMS from a sealed PDF. `first_revision_len`
/// starts the search at the incremental signature update, avoiding any marker
/// text in the original revision.
pub fn read_signed_file(pdf: &[u8], first_revision_len: usize) -> SignedFile {
    let update = &pdf[first_revision_len..];
    let at = first_revision_len + find(update, b"/ByteRange [").expect("a ByteRange");
    let close = at + find(&pdf[at..], b"]").expect("ByteRange end");
    let values: Vec<usize> = std::str::from_utf8(&pdf[at + 12..close])
        .unwrap()
        .split_whitespace()
        .map(|number| number.parse().unwrap())
        .collect();
    let [start, gap_start, gap_end, tail] = values[..] else {
        panic!("four ByteRange values: {values:?}")
    };
    assert_eq!(start, 0);
    assert_eq!(gap_end + tail, pdf.len(), "the byte range covers the file");
    let hex_digits = &pdf[gap_start + 1..gap_end - 1];
    let contents = hex::decode(hex_digits).expect("hex contents");
    let cms_der = contents[..der_len(&contents)].to_vec();
    assert!(
        contents[cms_der.len()..].iter().all(|byte| *byte == 0),
        "the reserved space after the CMS is zero padding"
    );
    SignedFile {
        signed_parts: [pdf[..gap_start].to_vec(), pdf[gap_end..].to_vec()],
        cms_der,
        reserved: contents.len(),
    }
}
