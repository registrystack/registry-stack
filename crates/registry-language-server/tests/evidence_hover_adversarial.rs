// SPDX-License-Identifier: Apache-2.0
//! What a card may and may not draw, asked by an author who wants it to draw something else.
//!
//! A card is the one answer this server hands a client as markup. Everything else it says is stated
//! as text: a diagnostic is a sentence, a log line is a line. The card is rendered, and it is
//! rendered by the reader's editor, under the reader's own chrome, which is why the reader reads it
//! as their tooling speaking. The text inside one comes from a project the reader did not write.
//! Reading a project someone else wrote is the ordinary case rather than the exotic one: a shared
//! template, a branch under review, an example downloaded to learn from. Nothing between the YAML
//! scalar an author typed and the markup a client renders validates a character set.
//!
//! So the question every test here asks is the same one: can the author of a project decide what the
//! reader of that project sees, beyond the name the card is quoting. The tests are split into the
//! properties that hold and the ones that do not, and the second group is expected to fail until
//! the defect it names is fixed.

mod support;

use std::{fs, path::Path};

use support::{
    adult_status_project, replacing, EvidenceProject, ADAPTER, QUESTION, QUESTION_PATH, SOURCE,
};
use tower_lsp_server::ls_types::Position;

/// The shared project with its answered concept, and the disclosure that spells it back, both
/// written as the double quoted scalar `payload`.
///
/// Quoting is what lets a test write a name YAML would otherwise read as structure, which is the
/// form an author reaches for when the name is meant to carry something. The card is taken over the
/// disclosure rather than over the answer, so it is the reference path through `hover_at` that is
/// under test: a card composed for a name that resolved, with the `Defined in` line the resolution
/// adds.
fn card_over_concept(payload: &str) -> String {
    let question = QUESTION
        .replace("<|concept|>is_adult", &format!("\"<|concept|>{payload}\""))
        .replace("<|allow|>is_adult", &format!("\"<|allow|>{payload}\""));
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &question,
    ));
    let index = project.index();
    index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .unwrap_or_else(|| panic!("the concept named {payload:?} describes itself"))
        .markdown
}

/// Every card this project can draw, taken by sweeping each document it holds.
///
/// A test that hovers the positions a fixture marked asks only about the places its author thought
/// of. Sweeping asks about the rest, which is where a path nobody meant to draw would be drawn.
fn every_card(project: &EvidenceProject) -> Vec<String> {
    let index = project.index();
    let paths = index
        .document_paths()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    let mut cards = Vec::new();
    for path in paths {
        for line in 0..48 {
            for character in 0..72 {
                if let Some(hover) = index.hover_at(&path, Position::new(line, character)) {
                    cards.push(hover.markdown);
                }
            }
        }
    }
    cards.sort();
    cards.dedup();
    cards
}

// ---------------------------------------------------------------------------
// Properties that hold.
// ---------------------------------------------------------------------------

/// The backtick is the character the code span is made of, and the fix that put it out of reach
/// holds wherever a name comes from.
///
/// A name that is nothing but backticks, and a name whose backtick sits past the width a name is cut
/// at, are the two places an implementation that replaced before it cut, or that replaced only the
/// first occurrence, would let one through.
#[test]
fn no_backtick_an_author_writes_reaches_the_card() {
    for payload in [
        "is_adult` **not what it says**",
        "```",
        &format!("{}`closed", "a".repeat(200)),
        "`",
    ] {
        let card = card_over_concept(payload);
        let quoted = card
            .strip_prefix("**concept** `")
            .and_then(|rest| rest.split_once('`'))
            .map(|(name, _)| name.to_owned())
            .unwrap_or_else(|| {
                panic!("the card opens with the span its name is drawn in: {card:?}")
            });
        assert!(
            !quoted.contains('`'),
            "a backtick reached the span the name is drawn in: {card:?}"
        );
    }
}

/// A name is one line of the card because the card decides where its lines are, and a control
/// character an author wrote is replaced before it can decide otherwise.
///
/// The newline is the one worth naming: it is what would end the code span, end the line, and start
/// a paragraph of the author's own under a heading the reader trusts. It is a C0 control, so
/// [`registry_language_server`]'s bound catches it, and this holds that it still does.
#[test]
fn no_control_character_an_author_writes_reaches_the_card() {
    for payload in [
        "is_adult\\n\\n# A heading of my own",
        "is_adult\\r\\n",
        "is_adult\\u001b[2J",
        "is_adult\\u0000",
        "is_adult\\u0085",
    ] {
        let card = card_over_concept(payload);
        assert!(
            card.lines().count() == 3,
            "a name added a line to the card: {card:?}"
        );
        assert!(
            !card
                .chars()
                .any(|character| character.is_control() && character != '\n'),
            "a control character reached the card: {card:?}"
        );
    }
}

/// The card names a range in the buffer, and the client uses it to underline what the card is about.
/// A character outside the basic plane costs two UTF-16 units and a combining mark costs one of its
/// own, so a range counted in anything else underlines the wrong text or spills past the end of the
/// line.
#[test]
fn the_range_a_card_claims_is_counted_in_utf16_units() {
    for name in ["pe\u{1f600}ple", "pe\u{301}\u{301}ople", "people"] {
        let project = EvidenceProject::new(&replacing(
            &replacing(
                &adult_status_project(),
                &format!("sources/{name}.yaml"),
                SOURCE,
            ),
            QUESTION_PATH,
            &QUESTION.replace("<|source-ref|>people", &format!("<|source-ref|>{name}")),
        ));
        let index = project.index();
        let start = project.cursor(QUESTION_PATH, "source-ref");
        let hover = index
            .hover_at(&project.path(QUESTION_PATH), start)
            .unwrap_or_else(|| panic!("the source {name} describes itself"));

        assert_eq!(hover.range.start, start, "{name}");
        assert_eq!(
            hover.range.end,
            Position::new(
                start.line,
                start.character + name.encode_utf16().count() as u32
            ),
            "{name}"
        );
    }
}

/// A document the loader refused is a document the server did not read, and a card is not a way to
/// ask it to read one anyway.
///
/// Both refusals are exercised, because they refuse at different points: a document past its
/// ceiling is never opened for its bytes, and a document that is not UTF-8 is opened and then put
/// down. What each one still declares is the name its own path spells, which is how the documents
/// that point at it stop being told it does not exist. That name is a path, and a path is not
/// content.
#[test]
fn a_card_over_a_refused_document_carries_no_text_from_it() {
    let oversized = format!("# {}\nref: hunter2\n", "p".repeat(1024 * 1024));
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "sources/oversized.yaml",
        &oversized,
    ));
    fs::write(
        project.path("sources/binary.yaml"),
        [0xff, 0xfe, 0x00, 0x41],
    )
    .expect("the binary document is written");
    let index = project.index();

    assert!(
        index
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("exceeds")),
        "the oversized document is refused, or this asserts nothing"
    );
    for relative in ["sources/oversized.yaml", "sources/binary.yaml"] {
        let path = project.path(relative);
        for line in 0..4 {
            for character in 0..8 {
                let Some(hover) = index.hover_at(&path, Position::new(line, character)) else {
                    continue;
                };
                assert!(
                    !hover.markdown.contains("hunter2")
                        && !hover.markdown.contains("pppp")
                        && !hover.markdown.contains('A'),
                    "{relative} put its own text in a card: {hover:?}"
                );
            }
        }
    }
}

/// `.evidence/` is tooling state rather than authored input, and `secrets/` is key material. The
/// loader keeps both out of the project, and a card is another way of asking about a document, so it
/// answers nothing over either.
#[test]
fn no_card_is_drawn_over_a_document_the_layout_keeps_out() {
    let project = EvidenceProject::new(&replacing(
        &replacing(
            &adult_status_project(),
            ".evidence/sources/people.yaml",
            SOURCE,
        ),
        "secrets/sources/people.yaml",
        SOURCE,
    ));
    let index = project.index();

    for relative in [
        ".evidence/sources/people.yaml",
        "secrets/sources/people.yaml",
    ] {
        let path = project.path(relative);
        for line in 0..6 {
            for character in 0..24 {
                let position = Position::new(line, character);
                assert!(
                    index.hover_at(&path, position).is_none(),
                    "{relative} described itself at {position:?}"
                );
            }
        }
    }
}

/// Every path a card draws is a path from the root of the project, which is how an author reads one.
///
/// The route a path takes to a card is `ProjectIndex::relative`, which falls back to the whole path
/// when the strip fails. Nothing should reach that fallback: the containment walk in `safety.rs`
/// refuses an absolute pointer, a `..` component and a symbolic link at any depth, so every document
/// a symbol is anchored in sits under the root. This sweeps the project rather than the positions a
/// fixture marked, because a path drawn from somewhere nobody looked is the one that would be
/// absolute.
#[test]
fn every_path_a_card_draws_is_relative_to_the_project_root() {
    let project = EvidenceProject::new(&adult_status_project());
    let drawn = every_card(&project);
    assert!(
        drawn.iter().any(|card| card.contains("Defined in")),
        "the sweep found a card that names where something is defined, or this asserts nothing"
    );

    for card in &drawn {
        for line in card.lines().filter(|line| line.starts_with("Defined in ")) {
            let path = line
                .trim_start_matches("Defined in ")
                .trim_matches('`')
                .to_owned();
            assert!(
                !path.starts_with('/'),
                "a card drew an absolute path: {card:?}"
            );
            assert!(
                !path.split('/').any(|component| component == ".."),
                "a card drew a path that walks out of the project: {card:?}"
            );
            assert!(
                !path.contains(project.root().to_string_lossy().as_ref()),
                "a card drew the reader's own directory layout: {card:?}"
            );
        }
    }
}

/// A file name is author written text on the same footing as a YAML scalar: a project carries its
/// own file names, and a filesystem takes a backtick in one.
#[test]
fn no_backtick_in_a_file_name_reaches_the_card() {
    let name = "adult-`status";
    let files = replacing(
        &replacing(
            &adult_status_project(),
            &format!("derivations/{name}.rhai"),
            ADAPTER,
        ),
        QUESTION_PATH,
        &QUESTION.replace(
            "<|derivation|>derivations/adult-status.rhai",
            &format!("\"<|derivation|>derivations/{name}.rhai\""),
        ),
    );
    let project = EvidenceProject::new(&files);
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "derivation"),
        )
        .expect("the derivation file describes itself");
    assert_eq!(
        hover.markdown.chars().filter(|c| *c == '`').count(),
        4,
        "the file name closed a span it was drawn in: {hover:?}"
    );
}

// ---------------------------------------------------------------------------
// Defects. Each test below fails, and the sentence above it is what it proves.
// ---------------------------------------------------------------------------

/// A card replaces the characters a terminal obeys and none of the characters a renderer obeys.
///
/// `bounded` decides what to replace with `char::is_control`, which names exactly the Unicode
/// control category: the C0 range, delete, and the C1 range. That is the right set for a terminal,
/// which is what the ceiling it lives under was written for. It is not the set a renderer obeys. The
/// bidirectional formatting characters are category `Cf` and the two separators are `Zl` and `Zp`,
/// so `char::is_control` says false for every one of them and every one of them reaches the card
/// whole.
///
/// A code span does not contain them. A markdown code span becomes an HTML `code` element, which
/// carries no `unicode-bidi: isolate` of its own, so an override opened inside the span stays open
/// across the closing backtick and applies to the words this crate wrote after it: the scope, the
/// `Defined in` line, and the path. The backtick was replaced because it let the author draw the
/// rest of the card; these let the author reorder it.
#[test]
fn no_character_a_renderer_obeys_reaches_the_card() {
    let obeyed = [
        ("soft hyphen", '\u{ad}'),
        ("zero width space", '\u{200b}'),
        ("zero width non-joiner", '\u{200c}'),
        ("left to right mark", '\u{200e}'),
        ("right to left mark", '\u{200f}'),
        ("left to right embedding", '\u{202a}'),
        ("right to left embedding", '\u{202b}'),
        ("pop directional formatting", '\u{202c}'),
        ("left to right override", '\u{202d}'),
        ("right to left override", '\u{202e}'),
        ("word joiner", '\u{2060}'),
        ("left to right isolate", '\u{2066}'),
        ("right to left isolate", '\u{2067}'),
        ("first strong isolate", '\u{2068}'),
        ("pop directional isolate", '\u{2069}'),
        ("line separator", '\u{2028}'),
        ("paragraph separator", '\u{2029}'),
        ("byte order mark", '\u{feff}'),
    ];

    let reached = obeyed
        .into_iter()
        .filter(|(_, character)| {
            card_over_concept(&format!("is_adult{character}")).contains(*character)
        })
        .map(|(label, character)| format!("{label} (U+{:04X})", character as u32))
        .collect::<Vec<_>>();

    assert!(
        reached.is_empty(),
        "{} of {} characters a renderer obeys reached the card whole: {reached:?}",
        reached.len(),
        obeyed.len()
    );
}

/// The override a card carries applies to the words the card wrote, not only to the name it quotes.
///
/// This is the consequence of the test above, stated as the shape it takes on one card. The name is
/// drawn first and the scope after it, both on one line, so an unterminated right to left override
/// inside the name is still in force over ` in question `, over the question's own name, and over
/// every `Defined in` line under it. Nothing this crate writes closes it: the card emits no
/// `U+202C` and no `U+2069`, because it never expected to have opened anything.
///
/// The author does not even have to make the override visible to a reviewer reading the raw YAML.
/// A double quoted scalar takes the JSON escape, so the file holds six ASCII characters and the
/// card renders the override they spell. `rustc` refuses that same codepoint in its own source by
/// default, under `text_direction_codepoint_in_literal`, which is this judgement one layer down.
#[test]
fn a_bidi_override_does_not_get_to_reorder_what_the_card_says() {
    let question = QUESTION
        .replace("<|concept|>is_adult", "\"is_\\u202Eadult\"")
        .replace("<|allow|>is_adult", "\"<|allow|>is_\\u202Eadult\"");
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &question,
    ));
    let index = project.index();

    let card = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .expect("the concept describes itself")
        .markdown;

    let Some(opened) = card.find('\u{202e}') else {
        return;
    };
    let after = &card[opened..];
    assert!(
        !after.contains(" in question ") || after.contains('\u{202c}'),
        "the card left an override open over its own words and never closed it: {card:?}"
    );
}

/// A name and a name that renders identically to it are two names, and a card that draws only the
/// second one tells its reader the first.
///
/// This is what the missing replacement costs a reader rather than what it costs the layout. A zero
/// width space is drawn as nothing, so `is_adult` with one appended is the card `is_adult`. The
/// disclosure that spells such a name is the field the index deliberately reports nothing about,
/// because `registry_evidence_authoring::validate` owns that sentence, so the editor's only account
/// of what a project discloses is the card, and the card cannot tell the two apart.
#[test]
fn a_card_draws_two_different_names_differently() {
    /// The card as a reader sees it: the characters that are drawn as nothing are drawn as nothing.
    fn as_drawn(card: &str) -> String {
        card.chars()
            .filter(|character| {
                !matches!(
                    character,
                    '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}'
                )
            })
            .collect()
    }

    let plain = card_over_concept("is_adult");
    let disguised = card_over_concept("is_adult\u{200b}");
    assert_ne!(
        plain, disguised,
        "the two concepts are the same name, or this asserts nothing"
    );

    assert_ne!(
        as_drawn(&plain),
        as_drawn(&disguised),
        "two concepts a project holds apart draw one card: {disguised:?}"
    );
}

/// A card cut at its ceiling is still a card, which means every span it opened it also closed and
/// every line it kept is one the server wrote whole.
///
/// A card that does not fit is cut back to the last line boundary below its ceiling, so what the
/// reader is shown is a shorter card rather than a prefix of a longer one, and the mark saying lines
/// were dropped is a line of its own. Were the cut taken at the ceiling itself it would land between
/// the backticks of a `Defined in` line about as often as anywhere else, leaving a line ending in a
/// backtick this crate wrote with no partner. Under CommonMark that backtick is drawn as itself, so
/// the reader would see punctuation the card did not mean to draw and an ellipsis sitting outside
/// the span it was cut out of.
///
/// The card is composed the same way an author reaches it: one question answering the same concept
/// many times over, so the name the disclosure spells resolves to one definition per answer and the
/// card grows a line for each.
#[test]
fn a_card_cut_at_its_ceiling_closes_every_span_it_opened() {
    let answers =
        "  - concept: is_adult\n    id: urn:example:concepts:is-adult\n    type: boolean\n"
            .repeat(140);
    let question = QUESTION.replace(
        "answers:\n  - concept: <|concept|>is_adult\n    id: urn:example:concepts:is-adult\n    \
         type: boolean\n",
        &format!("answers:\n{answers}"),
    );
    assert!(
        !question.contains("<|concept|>"),
        "the answers block was rewritten, or this asserts nothing"
    );
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &question,
    ));
    let index = project.index();

    let card = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .expect("the concept describes itself")
        .markdown;
    assert!(
        card.ends_with("\n\n…"),
        "the card reached its ceiling, or this asserts nothing: {} chars",
        card.chars().count()
    );

    let backticks = card.chars().filter(|character| *character == '`').count();
    assert_eq!(
        backticks % 2,
        0,
        "the cut left a span open; the card ends {:?}",
        card.chars()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    );

    for line in card.lines().filter(|line| !line.is_empty()) {
        assert!(
            line == "…"
                || line == "**concept** `is_adult` in question `adult-status`"
                || line == "Defined in `questions/adult-status.yaml`",
            "the cut kept a line the server did not write whole: {line:?}"
        );
    }
}

/// A name with nothing in it draws no delimiters of its own.
///
/// An empty scalar is a name the walkers index like any other, and the card quotes it the way it
/// quotes every name: between two backticks, with nothing between them. Two backticks with nothing
/// between them are not an empty code span. They are a backtick string of length two, and CommonMark
/// looks for another of length two to close it; the card has none, so both are drawn as themselves.
/// The reader sees the card's own punctuation where the name should be, and no indication that the
/// name is empty rather than the card broken.
#[test]
fn a_name_with_nothing_in_it_draws_no_delimiters() {
    let card = card_over_concept("");

    assert!(
        !card.contains("``"),
        "the card drew a backtick string no span closes: {card:?}"
    );
}
