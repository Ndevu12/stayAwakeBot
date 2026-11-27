//! The git stand-in's tables, which saw reads too: the subcommands and global options it reads as
//! bringing no files, what a command that brings none may still name, and gh's commands that bring
//! files.

use std::collections::HashMap;
use std::sync::OnceLock;

const TABLES: &str = include_str!("../../../../lib/data/git_runs_directly.json");

/// Return one of the stand-in's tables. Takes its name. Panics when the tables built into the
/// stand-in cannot be read.
pub fn table(name: &str) -> &'static [&'static str] {
    static READ: OnceLock<HashMap<String, Vec<&'static str>>> = OnceLock::new();
    let tables = READ.get_or_init(|| {
        let parsed: HashMap<String, Vec<String>> = serde_json::from_str(TABLES).expect("saw's git tables");
        parsed
            .into_iter()
            .map(|(name, words)| (name, words.into_iter().map(|w| &*Box::leak(w.into_boxed_str())).collect()))
            .collect()
    });
    tables.get(name).map(Vec::as_slice).unwrap_or_else(|| panic!("saw's git tables have no {name}"))
}
