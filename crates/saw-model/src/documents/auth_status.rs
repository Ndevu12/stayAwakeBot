//! The `auth-status` document: what `saw auth status --json` prints.

use serde::{Deserialize, Serialize};

/// A way to get access an intent lacks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    pub kind: String,
    pub detail: String,
    pub command: Option<String>,
}

/// Whether one thing saw does on GitHub is allowed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentAccess {
    pub intent: String,
    pub allowed: bool,
    pub missing: Vec<String>,
    pub reason: String,
    pub upgrades: Vec<Upgrade>,
}

/// The GitHub access saw has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthStatusDocument {
    pub schema_version: u32,
    pub source: Option<String>,
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub live: bool,
    pub scopes: Option<Vec<String>>,
    pub capabilities: Option<Vec<String>>,
    pub app_configured: bool,
    pub intents: Vec<IntentAccess>,
}
