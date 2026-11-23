//! What saw found: one detection, how serious it is, how sure saw is, and what saw does about it.

use serde::{Deserialize, Serialize};

/// How serious a finding is, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// How sure saw is of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Heuristic,
    Residue,
    Informational,
}

/// What saw does about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Remediation {
    Manual,
    Recover,
    RemoveFile,
    RemoveForeignVscode,
    StripGitignoreMarkers,
    RemoveGitExecPayload,
    Report,
}

/// One detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub signature_id: String,
    pub category: String,
    pub severity: Severity,
    pub path: String,
    pub description: String,
    pub remediation: Remediation,
    pub line: Option<u64>,
    pub evidence: Option<String>,
    pub vector: Option<String>,
    pub confidence: Confidence,
    pub related_paths: Vec<String>,
    pub payload_paths: Vec<String>,
    pub commit_sha: Option<String>,
    pub composed_evidence: bool,
    pub advisory_only: bool,
    pub fix_advice: Option<String>,
    pub fixed_version: Option<String>,
    pub dependency_state: Option<String>,
    pub fix_command: Option<String>,
    pub package: Option<String>,
    pub package_name: Option<String>,
    pub reference: Option<String>,
    /// Set by `saw govern` on a finding the folder already had before an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_existing: Option<bool>,
}
