//! The `scan` document: what `saw scan --json` prints.

use serde::{Deserialize, Serialize};

use crate::ordered::Ordered;

pub use crate::finding::{Confidence, Finding, Remediation, Severity};

/// The schema version the `scan` document is written in.
pub const SCAN_SCHEMA_VERSION: u32 = 1;

/// One target's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Residue,
    Suspicious,
    Infected,
}

/// The counts for one target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSummary {
    pub total: u64,
    pub by_severity: Ordered<u64>,
    pub by_category: Ordered<u64>,
    pub by_confidence: Ordered<u64>,
    pub max_severity: Option<Severity>,
    pub advisories: u64,
}

/// What saw found in one target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResult {
    pub target: String,
    pub source: String,
    pub verdict: Verdict,
    pub infected: bool,
    pub suspicious: bool,
    pub residue: bool,
    pub error: Option<String>,
    pub summary: TargetSummary,
    pub findings: Vec<Finding>,
    pub advisories: Vec<Finding>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub informational: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_payload: Option<String>,
}

/// The counts for the whole run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub targets: u64,
    pub infected: u64,
    pub suspicious: u64,
    pub residue: u64,
    pub findings: u64,
    pub critical: u64,
    pub high: u64,
    pub advisories: u64,
}

/// The whole `scan` document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanDocument {
    pub schema_version: u32,
    pub generated_at: String,
    pub summary: RunSummary,
    pub any_infected: bool,
    pub any_suspicious: bool,
    pub any_residue: bool,
    pub any_error: bool,
    pub results: Vec<TargetResult>,
}
