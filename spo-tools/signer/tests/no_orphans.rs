//! Repository-structure guard: every `.rs` file under `src/` — including the
//! handlers in `src/handlers/` — must be wired into the module tree via a
//! `mod` declaration in its parent module file (`main.rs` at the crate root,
//! `mod.rs` inside subdirectories). A stale, uncompiled duplicate of a
//! security-critical handler would otherwise sit on disk with no compiler
//! warning, inviting an edit to the wrong file. An identical copy of this
//! guard lives in `online-tool/tests/no_orphans.rs`.

use std::path::Path;

/// True when `module_src` declares module `name` — `mod name;`,
/// `pub(...) mod name;` or an inline `mod name {` — matched on token
/// boundaries, with `//` comments stripped so a commented-out declaration
/// does not count as wired.
fn declares_mod(module_src: &str, name: &str) -> bool {
    for line in module_src.lines() {
        let code = line.split("//").next().unwrap_or("");
        let mut rest = code;
        while let Some(pos) = rest.find("mod") {
            let boundary_before = rest[..pos]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_');
            let after = &rest[pos + 3..];
            let tail = after.trim_start();
            let boundary_after = tail.len() < after.len();
            if boundary_before && boundary_after {
                if let Some(t) = tail.strip_prefix(name) {
                    // `;` or `{` right after the name doubles as the
                    // end-of-identifier boundary (`mod handlers_old;` does
                    // not count as declaring `handlers`).
                    let t = t.trim_start();
                    if t.starts_with(';') || t.starts_with('{') {
                        return true;
                    }
                }
            }
            rest = &rest[pos + 3..];
        }
    }
    false
}

/// Walk `dir`, requiring every `.rs` file and every subdirectory to be
/// declared in `module_src` (the contents of the module file owning `dir`),
/// then recurse into subdirectories via their `mod.rs` (or the 2018-style
/// `<name>.rs` sibling).
fn collect_orphans(dir: &Path, module_src: &str, orphans: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if path.is_dir() {
            if !declares_mod(module_src, name) {
                orphans.push(format!("{}/", path.display()));
                continue;
            }
            let mod_rs = path.join("mod.rs");
            let module_file = if mod_rs.is_file() {
                mod_rs
            } else {
                dir.join(format!("{name}.rs"))
            };
            match std::fs::read_to_string(&module_file) {
                Ok(src) => collect_orphans(&path, &src, orphans),
                // No mod.rs / <name>.rs: nothing can wire the children in.
                Err(_) => orphans.push(format!("{}/", path.display())),
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        // Module files are wired by their parent (or are the crate root).
        if stem == "main" || stem == "lib" || stem == "mod" {
            continue;
        }
        if !declares_mod(module_src, stem) {
            orphans.push(path.display().to_string());
        }
    }
}

#[test]
fn no_orphaned_source_files() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root = std::fs::read_to_string(src.join("main.rs")).unwrap();
    let mut orphans = Vec::new();
    collect_orphans(&src, &root, &mut orphans);
    assert!(
        orphans.is_empty(),
        "orphaned (uncompiled) source files not declared as `mod` in their parent module file: {orphans:?}"
    );
}

#[test]
fn declares_mod_matches_real_declarations_only() {
    assert!(declares_mod("mod foo;", "foo"));
    assert!(declares_mod("pub mod foo;", "foo"));
    assert!(declares_mod("pub(crate) mod foo {", "foo"));
    assert!(declares_mod("#[path = \"other.rs\"]\nmod foo;", "foo"));
    assert!(!declares_mod("// mod foo;", "foo"));
    assert!(!declares_mod("mod foobar;", "foo"));
    assert!(!declares_mod("mod foo_old;", "foo"));
    assert!(!declares_mod("my_mod foo;", "foo"));
    assert!(!declares_mod("modfoo;", "foo"));
}
