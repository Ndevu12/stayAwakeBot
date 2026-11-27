//! The record of the git settings the operator kept for each repository, which saw's Python
//! `bots/security/kept_settings.py` writes. It is read only while it lies outside every repository.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{paths, surface, Environment};
use crate::git_tables::table;

const RECORDS_FOLDER: &str = "saw";
const RECORD_LIMIT: u64 = 1 << 20;

/// Name the record: under saw's record folder in the operator's cache folder. Takes the
/// environment. Returns its path, or None with no cache folder to name.
pub fn record_path(environ: &Environment) -> Option<PathBuf> {
    let cache = match environ.get("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        Some(cache) => PathBuf::from(cache),
        None => Path::new(environ.get("HOME")?).join(".cache"),
    };
    Some(table("kept_settings_record").iter().fold(cache.join(RECORDS_FOLDER), |path, part| path.join(part)))
}

/// Read the fingerprint the operator kept for a repository, from a record that lies outside every
/// repository. Takes the environment and the repository's key. Returns its digest, or None.
pub fn kept_digest(environ: &Environment, repository: &Path) -> Option<String> {
    let record = record_path(environ)?;
    if lies_inside_a_repository(&record) {
        return None;
    }
    let mut text = String::new();
    fs::File::open(&record).ok()?.take(RECORD_LIMIT).read_to_string(&mut text).ok()?;
    let kept: serde_json::Value = serde_json::from_str(&text).ok()?;
    kept.get("repositories")?.get(repository.to_str()?)?.as_str().map(str::to_string)
}

/// Whether the folder a record lies in, every link followed, is inside a git repository.
fn lies_inside_a_repository(record: &Path) -> bool {
    let resolved = paths::real_path(record);
    let folder = resolved.parent().unwrap_or(&resolved);
    folder.ancestors().any(|at| paths::lexists(&at.join(".git")) || surface::is_git_directory(at))
}
