//! The `audit` document: what `saw audit --json` prints.

use serde::{Deserialize, Serialize};

/// Whether rotating credentials is safe now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotationVerdict {
    Safe,
    SafeOnceConfirmed,
    Unsafe,
    Incomplete,
}

/// The rotation answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub verdict: RotationVerdict,
    pub sentence: String,
    pub to_confirm: Vec<String>,
}

/// One thing the audit found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub fix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// A check the audit could not finish.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unfinished {
    pub probe: String,
    pub reason: String,
    pub title: String,
    pub fix: String,
}

/// What the audit found on this machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDocument {
    pub schema_version: u32,
    pub rotation: Rotation,
    pub findings: Vec<AuditFinding>,
    pub incomplete: Vec<Unfinished>,
    pub scope_notes: Vec<String>,
}
