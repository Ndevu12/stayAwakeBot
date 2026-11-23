//! The `watch-status` document: what `saw watch status --json` prints.

use serde::{Deserialize, Serialize};

/// Whether `saw watch` is in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Schedule {
    InPlace,
    FromNextLogin,
    NotInPlace,
    Changed,
    CouldNotTell,
}

/// One matter still open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matter {
    pub kind: String,
    pub line: String,
    pub urgent: bool,
}

/// What happened since the last report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Since {
    pub heading: String,
    pub lines: Vec<String>,
}

/// Where the watcher stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchStatusDocument {
    pub schema_version: u32,
    pub schedule: Schedule,
    pub matters: Vec<Matter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Since>,
}
