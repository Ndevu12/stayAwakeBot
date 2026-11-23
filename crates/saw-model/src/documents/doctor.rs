//! The `doctor` document: what `saw doctor --json` prints.

use serde::{Deserialize, Serialize};

/// How saw is installed and signed in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorDocument {
    pub schema_version: u32,
    pub saw_on_path: Option<String>,
    pub credential: Option<String>,
    pub actor: Option<String>,
    pub live: bool,
    pub scopes: Option<Vec<String>>,
    pub capabilities: Option<Vec<String>>,
    pub app_configured: bool,
    pub open_fix_pr: bool,
    pub open_guard_pr: bool,
    pub health_scripts_installed: bool,
    pub version: String,
}
