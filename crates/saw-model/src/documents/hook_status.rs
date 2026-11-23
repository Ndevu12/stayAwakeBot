//! The `hook-status` document: what `saw hook status --json` prints, and `hook install` and
//! `hook repair` with `--json`.

use serde::{Deserialize, Serialize};

/// One problem with the hooks, and how to repair it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookProblem {
    pub code: String,
    pub message: String,
    pub repair: Option<String>,
}

/// Whether saw's git hooks are in place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookStatusDocument {
    pub schema_version: u32,
    pub installed: bool,
    pub events: Vec<String>,
    pub via: Vec<String>,
    pub disabled_by_env: bool,
    pub problems: Vec<HookProblem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
}
