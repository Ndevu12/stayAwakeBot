//! The record of the git settings the operator kept for each repository, and of those a person
//! answered no to, which saw's Python `bots/security/kept_settings.py` writes. It is read only while
//! it lies outside every repository.

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
        None => PathBuf::from(crate::platform::home_folder(environ)?).join(".cache"),
    };
    Some(table("kept_settings_record").iter().fold(cache.join(RECORDS_FOLDER), |path, part| path.join(part)))
}

/// What the record holds for one repository: the fingerprint the operator kept and the one a person
/// answered no to, each as its digest.
#[derive(Debug, Default)]
pub struct Recorded {
    kept: Option<String>,
    declined: Option<String>,
}

impl Recorded {
    /// Whether the operator kept the settings with this digest.
    pub fn keeps(&self, digest: &str) -> bool {
        self.kept.as_deref() == Some(digest)
    }

    /// Whether a person answered no to the settings with this digest.
    pub fn declined(&self, digest: &str) -> bool {
        self.declined.as_deref() == Some(digest)
    }
}

/// Read what the record holds for a repository, from a record that lies outside every repository.
/// Takes the environment and the repository's key. Returns it, empty without a record.
pub fn read(environ: &Environment, repository: &Path) -> Recorded {
    read_record(environ).map(|record| {
        let digest = |table: &str| repository.to_str().and_then(|key| record.get(table)?.get(key)?.as_str().map(str::to_string));
        Recorded { kept: digest("repositories"), declined: digest("declined") }
    }).unwrap_or_default()
}

fn read_record(environ: &Environment) -> Option<serde_json::Value> {
    let record = record_path(environ)?;
    let resolved = paths::real_path(&record);
    if surface::lies_inside_a_repository(resolved.parent().unwrap_or(&resolved)) {
        return None;
    }
    let mut text = String::new();
    fs::File::open(&record).ok()?.take(RECORD_LIMIT).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}
