// SPDX-License-Identifier: Apache-2.0
//! The full path-canonicalizer acceptance / rejection matrix, via the public
//! API. (Unit tests in `src/path.rs` assert the exact `PathError` variants;
//! this matrix is the higher-level accept/reject contract.)

use registry_notary_source_adapter_rhai::{canonicalize_target_relative_path as canon, PathError};

// NOTE: an encoded forward slash (`%2f`/`%2F`) is rejected outright (B2.3); it
// is no longer decoded into a real separator, so paths like `/a%2fb` are in the
// reject set below rather than the accept set.

#[test]
fn accept_matrix() {
    let accept: &[(&str, &str)] = &[
        ("/", "/"),
        ("/trackedEntityInstances", "/trackedEntityInstances"),
        ("/api/33/metadata", "/api/33/metadata"),
        ("/a/b/c/d", "/a/b/c/d"),
        ("/v1.2/foo_bar-baz", "/v1.2/foo_bar-baz"),
        ("/data.json", "/data.json"),
        ("/a%20b", "/a b"), // encoded space inside a segment
        ("/%61bc", "/abc"), // encoded letter
        ("/files/report-2024", "/files/report-2024"),
    ];
    for (raw, want) in accept {
        assert_eq!(canon(raw).as_deref(), Ok(*want), "should accept {raw:?}");
    }
}

#[test]
fn reject_matrix() {
    // Each entry must be rejected; the comment notes the class.
    let reject: &[&str] = &[
        "",               // empty
        "relative/path",  // missing leading slash
        "a",              // missing leading slash
        "//evil.com/x",   // protocol-relative / multiple leading slashes
        "//",             // multiple leading slashes
        "///a",           // multiple leading slashes
        "/.",             // dot segment
        "/..",            // dotdot segment
        "/a/../b",        // traversal
        "/a/./b",         // dot segment
        "/../etc/passwd", // traversal
        "/a//b",          // empty interior segment
        "/a/",            // trailing empty segment
        "/%2e",           // encoded dot
        "/%2e%2e",        // encoded dotdot
        "/%2E%2e/x",      // mixed-case encoded dotdot
        "/a%2fb",         // encoded forward slash (rejected outright)
        "/a%2Fb",         // encoded forward slash, upper hex
        "/a%2f..%2fb",    // encoded slash building traversal
        "/a%5cb",         // encoded backslash
        "/%5c",           // encoded backslash
        "/%252e",         // double-encoded dot
        "/a%252fb",       // double-encoded slash
        "/%",             // invalid percent
        "/%2",            // truncated percent
        "/%zz",           // non-hex percent
        "/a?b=1",         // query
        "/a#frag",        // fragment
        "/a%3fb",         // encoded query char
        "/a%23b",         // encoded fragment char
        "/a%00b",         // NUL
        "/a%0ab",         // newline
        "/a%09b",         // tab
        "/a%7fb",         // DEL
        "/%ff",           // invalid UTF-8 after decode
    ];
    for raw in reject {
        assert!(canon(raw).is_err(), "should reject {raw:?}");
    }
}

#[test]
fn specific_error_classes_are_distinguishable() {
    assert_eq!(canon(""), Err(PathError::Empty));
    assert_eq!(canon("a"), Err(PathError::MissingLeadingSlash));
    assert_eq!(canon("//x"), Err(PathError::MultipleLeadingSlashes));
    assert_eq!(canon("/.."), Err(PathError::TraversalSegment));
    assert_eq!(canon("/a//b"), Err(PathError::EmptySegment));
    assert_eq!(canon("/%252e"), Err(PathError::InvalidPercentEncoding));
    assert_eq!(canon("/a?x"), Err(PathError::ContainsQuery));
    assert_eq!(canon("/a#x"), Err(PathError::ContainsFragment));
    assert_eq!(canon("/a%5cb"), Err(PathError::DisallowedCharacter));
    assert_eq!(canon("/a%2fb"), Err(PathError::EncodedSeparator));
}
