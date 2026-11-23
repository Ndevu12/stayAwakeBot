//! The `guard-drift` document: what `saw guard drift --json` prints.

use serde::{Deserialize, Serialize};

/// One repository's drift check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftRecord {
    pub repository: String,
    pub state: String,
    pub issue_action: String,
    pub issue: Option<u64>,
    pub detail: String,
}

/// Every repository's drift check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardDriftDocument {
    pub schema_version: u32,
    pub results: Vec<DriftRecord>,
}
