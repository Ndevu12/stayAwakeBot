//! Lists, identifies and stops the processes running on this machine.

pub mod identity;
pub mod listing;
pub mod program_gone;
pub mod stopping;
pub mod windows_rows;

pub use identity::{identify, started, Identity, Reading, Start};
pub use listing::{parent_map, program_path, ps_signature, snapshot, Process, Snapshot};

/// Split text into words. Takes the text. Returns the words.
pub(crate) fn words(text: &str) -> Vec<&str> {
    text.split(crate::env::is_python_space).filter(|word| !word.is_empty()).collect()
}

/// Return the fields of a `/proc/<pid>/stat` line after the program name. Takes the line.
/// Returns the fields, or none.
pub(crate) fn stat_fields(raw: &str) -> Option<Vec<&str>> {
    let close = raw.rfind(')')?;
    Some(words(raw.get(close + 2..)?))
}

/// Return this platform's name, as saw writes it.
pub(crate) fn platform_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}
