//! The `fix` document: what `saw fix --json` prints.

use serde::{Deserialize, Serialize};

/// A choice the operator made while fixing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Decision {
    Delivery { commit: String, action: String, chosen: Vec<String> },
    Package { name: String, action: String },
    File { path: String, action: String },
}

/// The uncommitted work a fix put aside, or could not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Uncommitted {
    pub branch: String,
    pub files: u64,
    pub withheld: u64,
    pub unsaved: u64,
    pub unread: u64,
    pub reason: String,
}

/// What one repository's fix did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixRecord {
    pub repository: String,
    pub remediation: String,
    pub cause: String,
    pub pull_request: Option<u64>,
    pub url: String,
    pub partial: bool,
    pub branch: String,
    pub base: String,
    pub removed: Vec<String>,
    pub history_holds_payload: bool,
    pub needs_review: Vec<String>,
    pub decisions: Vec<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncommitted: Option<Uncommitted>,
}

/// What a fix run did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixDocument {
    pub schema_version: u32,
    pub results: Vec<FixRecord>,
}
