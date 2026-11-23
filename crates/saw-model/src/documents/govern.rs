//! The `govern` document: what `saw govern prepare`, `apply`, `verdict` and `restore` print.

use serde::{Deserialize, Serialize};

use crate::documents::scan::{Finding, ScanDocument};

/// The way through for an update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Decision {
    /// An update saw held: let it in after review, or leave the folder unchanged.
    Held(HeldDecision),
    /// An update saw could not check: run it as typed, or leave the folder unchanged.
    Unchecked(UncheckedDecision),
}

/// The way through an update saw held.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldDecision {
    pub choices: Vec<String>,
    pub let_in: Vec<String>,
    pub confirm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_to_confirm: Option<String>,
}

/// The way through an update saw could not check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncheckedDecision {
    pub choices: Vec<String>,
    pub scan_after: Vec<String>,
}

/// Every answer `saw govern` prints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GovernDocument {
    Passthrough(Passthrough),
    Checked(Checked),
    Unchecked(Unchecked),
    Verdict(Verdict),
    Applied(Applied),
    Restored(Restored),
    Refused(Refused),
}

/// A command that brings nothing in, for the caller to run as typed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Passthrough {
    pub schema_version: u32,
    pub passthrough: bool,
    pub reason: String,
}

/// An update saw checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checked {
    pub schema_version: u32,
    pub scan: ScanDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_existing: Option<Vec<Finding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_steps: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

/// An update saw could not check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unchecked {
    pub schema_version: u32,
    pub reason: String,
    pub decision: Decision,
}

/// Whether the folder's tree is one saw let in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub schema_version: u32,
    pub governed: String,
    pub code: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub let_in: Option<String>,
}

/// Whether a checked update was applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    pub schema_version: u32,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Whether the folder was put back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restored {
    pub schema_version: u32,
    pub restored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A request saw refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refused {
    pub schema_version: u32,
    pub reason: String,
}
