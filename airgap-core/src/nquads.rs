//! Read a CIP-100 canonical body back into what it says.
//!
//! A rationale author witness signs blake2b-256 of the document body
//! canonicalized to N-Quads. The canonicalization runs in the online tool's
//! browser, so the signer receives N-Quads it did not produce, and raw
//! N-Quads are not something an operator can hold against the rationale they
//! wrote. This module lets the signer show the content of the exact bytes it
//! is about to sign: every statement is read from those bytes, split into
//! the field it sets and the text it carries. Nothing here is trusted input
//! from the online tool beyond the bytes themselves, and nothing here
//! decides whether to sign: a line that cannot be read is reported as such
//! and shown raw, never dropped.

use serde::Serialize;

/// One line of a canonical body, as the signer shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BodyLine {
    /// A statement whose object is a literal: text the document carries.
    Text {
        subject: String,
        /// Short name of the predicate (its fragment or last path segment).
        field: String,
        predicate: String,
        value: String,
        language: Option<String>,
        datatype: Option<String>,
    },
    /// A statement whose object is an IRI.
    Link {
        subject: String,
        field: String,
        predicate: String,
        value: String,
    },
    /// A statement that points at another node of the document.
    Node {
        subject: String,
        field: String,
        predicate: String,
        value: String,
    },
    /// A line that is not a well-formed N-Quads statement, shown as it is.
    Unreadable { raw: String },
}

/// Split a canonical body into its lines and read each one. The result has
/// exactly one entry per non-empty line, in order.
pub fn read_canonical_body(body: &str) -> Vec<BodyLine> {
    body.split('\n')
        .filter(|l| !l.is_empty())
        .map(|l| parse_line(l).unwrap_or_else(|| BodyLine::Unreadable { raw: visible(l) }))
        .collect()
}

enum Term {
    Iri(String),
    Blank(String),
    Literal {
        value: String,
        language: Option<String>,
        datatype: Option<String>,
    },
}

struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    fn eat(&mut self, prefix: &str) -> bool {
        match self.rest.strip_prefix(prefix) {
            Some(r) => {
                self.rest = r;
                true
            }
            None => false,
        }
    }

    /// One or more spaces or tabs between terms.
    fn gap(&mut self) -> Option<()> {
        let trimmed = self.rest.trim_start_matches([' ', '\t']);
        if trimmed.len() == self.rest.len() {
            return None;
        }
        self.rest = trimmed;
        Some(())
    }

    /// `<...>`: no whitespace, `<`, `>` or `"` inside.
    fn iri(&mut self) -> Option<String> {
        let r = self.rest.strip_prefix('<')?;
        let end = r.find('>')?;
        let inner = &r[..end];
        if inner.is_empty()
            || inner
                .chars()
                .any(|c| c.is_whitespace() || c == '<' || c == '"')
        {
            return None;
        }
        self.rest = &r[end + 1..];
        Some(inner.to_string())
    }

    /// `_:label`, up to the next whitespace.
    fn blank(&mut self) -> Option<String> {
        let r = self.rest.strip_prefix("_:")?;
        let end = r.find([' ', '\t']).unwrap_or(r.len());
        if end == 0 {
            return None;
        }
        self.rest = &r[end..];
        Some(format!("_:{}", &r[..end]))
    }

    /// `"..."` with N-Quads escapes, then an optional `@lang` or `^^<iri>`.
    fn literal(&mut self) -> Option<Term> {
        let r = self.rest.strip_prefix('"')?;
        let mut value = String::new();
        let mut chars = r.char_indices();
        let close = loop {
            let (i, c) = chars.next()?;
            match c {
                '"' => break i,
                '\\' => {
                    let (_, e) = chars.next()?;
                    match e {
                        't' => value.push('\t'),
                        'b' => value.push('\u{8}'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        'f' => value.push('\u{c}'),
                        '"' => value.push('"'),
                        '\'' => value.push('\''),
                        '\\' => value.push('\\'),
                        'u' | 'U' => {
                            let n = if e == 'u' { 4 } else { 8 };
                            let mut code = 0u32;
                            for _ in 0..n {
                                let (_, h) = chars.next()?;
                                code = code.checked_mul(16)?.checked_add(h.to_digit(16)?)?;
                            }
                            value.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                _ => value.push(c),
            }
        };
        self.rest = &r[close + 1..];
        let mut language = None;
        let mut datatype = None;
        if self.eat("^^") {
            datatype = Some(self.iri()?);
        } else if self.eat("@") {
            let end = self.rest.find([' ', '\t']).unwrap_or(self.rest.len());
            let tag = &self.rest[..end];
            let well_formed = !tag.is_empty()
                && tag
                    .split('-')
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric()));
            if !well_formed {
                return None;
            }
            language = Some(tag.to_string());
            self.rest = &self.rest[end..];
        }
        Some(Term::Literal {
            value,
            language,
            datatype,
        })
    }

    fn subject_or_graph(&mut self) -> Option<String> {
        if self.rest.starts_with('<') {
            self.iri()
        } else {
            self.blank()
        }
    }

    fn object(&mut self) -> Option<Term> {
        if self.rest.starts_with('<') {
            self.iri().map(Term::Iri)
        } else if self.rest.starts_with("_:") {
            self.blank().map(Term::Blank)
        } else {
            self.literal()
        }
    }
}

fn parse_line(line: &str) -> Option<BodyLine> {
    let mut c = Cursor { rest: line };
    let subject = c.subject_or_graph()?;
    c.gap()?;
    let predicate = c.iri()?;
    c.gap()?;
    let object = c.object()?;
    c.gap()?;
    // Optional graph label, then the terminating dot and nothing after it.
    if !c.rest.starts_with('.') {
        c.subject_or_graph()?;
        c.gap()?;
    }
    if c.rest != "." {
        return None;
    }
    let field = visible(field_name(&predicate));
    let subject = visible(&subject);
    let predicate = visible(&predicate);
    Some(match object {
        Term::Literal {
            value,
            language,
            datatype,
        } => BodyLine::Text {
            subject,
            field,
            predicate,
            value: visible(&value),
            language,
            datatype: datatype.map(|d| visible(&d)),
        },
        Term::Iri(v) => BodyLine::Link {
            subject,
            field,
            predicate,
            value: visible(&v),
        },
        Term::Blank(v) => BodyLine::Node {
            subject,
            field,
            predicate,
            value: visible(&v),
        },
    })
}

/// The part of a predicate IRI an author would recognise: its fragment, or
/// failing that its last path segment, or failing that all of it.
fn field_name(predicate: &str) -> &str {
    let tail = match predicate.rsplit_once('#') {
        Some((_, f)) => f,
        None => predicate
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(predicate),
    };
    if tail.is_empty() {
        predicate
    } else {
        tail
    }
}

/// Characters that draw nothing or change how the text around them is
/// drawn: every format character (Unicode category Cf, which holds the
/// bidirectional controls, the zero-width characters and the tag characters),
/// the line and paragraph separators, and the invisible combining marks and
/// fillers that render as blank space.
fn is_hidden(ch: char) -> bool {
    (ch.is_control() && ch != '\n' && ch != '\t')
        || matches!(ch,
            '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}')
}

/// Make characters that could hide or reorder text on screen visible: every
/// character [`is_hidden`] names is written as `\u{...}`. The one exception
/// is a single text or emoji presentation selector (U+FE0E, U+FE0F) right
/// after a character that is shown as is, which is how an emoji such as a
/// red heart is written. A second selector in a row, or one with nothing
/// visible before it, is written out, so a run of selectors cannot carry
/// hidden text behind one emoji. What the operator reads must be what the
/// bytes say.
fn visible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut after_shown = false;
    for ch in s.chars() {
        let presentation = matches!(ch, '\u{FE0E}' | '\u{FE0F}');
        if presentation && after_shown {
            out.push(ch);
            after_shown = false;
        } else if is_hidden(ch) {
            out.push_str(&format!("\\u{{{:04X}}}", ch as u32));
            after_shown = false;
        } else {
            out.push(ch);
            after_shown = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CIP100: &str =
        "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md";

    fn text(lines: &[BodyLine], field: &str) -> Vec<String> {
        lines
            .iter()
            .filter_map(|l| match l {
                BodyLine::Text {
                    field: f, value, ..
                } if f == field => Some(value.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn reads_a_canonical_rationale_body() {
        let body = format!(
            "_:c14n0 <{CIP100}#body> _:c14n1 .\n\
             _:c14n1 <{CIP100}#comment> \"I vote yes because\\nthe budget is sound.\"@en-us .\n\
             _:c14n1 <{CIP100}#references> _:c14n2 .\n\
             _:c14n2 <{CIP100}#reference-label> \"Budget\"@en-us .\n\
             _:c14n2 <{CIP100}#reference-uri> \"https://example.org/budget\"@en-us .\n\
             _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <{CIP100}#OtherReference> .\n"
        );
        let lines = read_canonical_body(&body);
        assert_eq!(lines.len(), 6, "one entry per line");
        assert!(lines
            .iter()
            .all(|l| !matches!(l, BodyLine::Unreadable { .. })));
        assert_eq!(
            text(&lines, "comment"),
            vec!["I vote yes because\nthe budget is sound."]
        );
        assert_eq!(text(&lines, "reference-label"), vec!["Budget"]);
        assert_eq!(
            text(&lines, "reference-uri"),
            vec!["https://example.org/budget"]
        );
        assert_eq!(
            lines[0],
            BodyLine::Node {
                subject: "_:c14n0".into(),
                field: "body".into(),
                predicate: format!("{CIP100}#body"),
                value: "_:c14n1".into(),
            }
        );
        assert!(matches!(&lines[5], BodyLine::Link { field, value, .. }
            if field == "type" && value.ends_with("#OtherReference")));
        assert!(
            matches!(&lines[1], BodyLine::Text { language: Some(l), datatype: None, .. } if l == "en-us")
        );
    }

    #[test]
    fn unescapes_literals() {
        let body =
            "_:b <http://x/#f> \"a \\\"quoted\\\" \\\\ back\\tslash \\u00e9 \\U0001F600\" .\n";
        let lines = read_canonical_body(body);
        assert_eq!(
            text(&lines, "f"),
            vec!["a \"quoted\" \\ back\tslash \u{e9} \u{1F600}"]
        );
    }

    #[test]
    fn reads_datatype_and_graph_label() {
        let body = "<http://x/s> <http://x/count> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> _:g .\n";
        let lines = read_canonical_body(body);
        assert_eq!(
            lines,
            vec![BodyLine::Text {
                subject: "http://x/s".into(),
                field: "count".into(),
                predicate: "http://x/count".into(),
                value: "42".into(),
                language: None,
                datatype: Some("http://www.w3.org/2001/XMLSchema#integer".into()),
            }]
        );
    }

    #[test]
    fn a_line_that_is_not_a_statement_is_shown_raw_not_dropped() {
        let body = "_:b <http://x/#f> \"fine\" .\n\
                    this is not n-quads .\n\
                    _:b <http://x/#g> \"unterminated .\n\
                    _:b <http://x/#h> \"bad \\q escape\" .\n\
                    _:b <http://x/#i> \"trailing\" . extra\n\
                    _:b <http://x/#j> \"no dot\"\n";
        let lines = read_canonical_body(body);
        assert_eq!(lines.len(), 6);
        assert!(matches!(lines[0], BodyLine::Text { .. }));
        for l in &lines[1..] {
            assert!(matches!(l, BodyLine::Unreadable { .. }), "{l:?}");
        }
        assert_eq!(
            lines[1],
            BodyLine::Unreadable {
                raw: "this is not n-quads .".into()
            }
        );
    }

    #[test]
    fn tag_characters_and_separators_are_made_visible() {
        // "hi" followed by the tag characters for "ok", invisible on screen.
        assert_eq!(
            visible("hi\u{E0001}\u{E006F}\u{E006B}"),
            "hi\\u{E0001}\\u{E006F}\\u{E006B}"
        );
        assert_eq!(visible("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
        assert_eq!(
            visible("x\u{180E}y\u{3164}z\u{115F}"),
            "x\\u{180E}y\\u{3164}z\\u{115F}"
        );
        assert_eq!(visible("q\u{034F}r\u{2800}s"), "q\\u{034F}r\\u{2800}s");
        // Newline and tab stay as they are.
        assert_eq!(visible("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn one_emoji_selector_is_kept_and_a_run_is_written_out() {
        // A red heart is U+2764 with one emoji presentation selector.
        assert_eq!(visible("\u{2764}\u{FE0F}"), "\u{2764}\u{FE0F}");
        assert_eq!(visible("\u{263A}\u{FE0E} ok"), "\u{263A}\u{FE0E} ok");
        // A second selector in a row can only be there to carry data.
        assert_eq!(
            visible("\u{2764}\u{FE0F}\u{FE0F}"),
            "\u{2764}\u{FE0F}\\u{FE0F}"
        );
        assert_eq!(
            visible("\u{2764}\u{FE0F}\u{FE01}"),
            "\u{2764}\u{FE0F}\\u{FE01}"
        );
        // Any other selector is written out, even after a visible character.
        assert_eq!(visible("a\u{FE00}"), "a\\u{FE00}");
        assert_eq!(visible("a\u{E0100}\u{E01EF}"), "a\\u{E0100}\\u{E01EF}");
        // A selector with nothing shown before it is written out.
        assert_eq!(visible("\u{FE0F}x"), "\\u{FE0F}x");
        assert_eq!(visible("a\u{200B}\u{FE0F}"), "a\\u{200B}\\u{FE0F}");
    }

    #[test]
    fn hidden_and_reordering_characters_are_made_visible() {
        // A right-to-left override would show "evil" text reversed on screen.
        let body = "_:b <http://x/#comment> \"yes\\u202Eon\\u200B\" .\n";
        let lines = read_canonical_body(body);
        assert_eq!(text(&lines, "comment"), vec!["yes\\u{202E}on\\u{200B}"]);
        // The same characters raw (unescaped) in an unreadable line.
        let lines = read_canonical_body("bad \u{202E} line\n");
        assert_eq!(
            lines,
            vec![BodyLine::Unreadable {
                raw: "bad \\u{202E} line".into()
            }]
        );
    }

    #[test]
    fn field_name_prefers_the_fragment() {
        assert_eq!(field_name("http://x/a/b#frag"), "frag");
        assert_eq!(field_name("http://x/a/b"), "b");
        assert_eq!(field_name("http://x/a/b/"), "b");
        assert_eq!(field_name("http://x/a#"), "http://x/a#");
    }

    #[test]
    fn serializes_with_a_kind_tag() {
        let lines = read_canonical_body("_:b <http://x/#f> \"v\" .\n");
        let json = serde_json::to_value(&lines).unwrap();
        assert_eq!(json[0]["kind"], "text");
        assert_eq!(json[0]["field"], "f");
        assert_eq!(json[0]["value"], "v");
    }

    #[test]
    fn empty_body_has_no_lines() {
        assert!(read_canonical_body("").is_empty());
        assert!(read_canonical_body("\n\n").is_empty());
    }
}
