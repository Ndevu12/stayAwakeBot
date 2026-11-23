//! The `capabilities` document: what `saw capabilities --json` prints.

use serde::{Deserialize, Serialize};

use crate::ordered::Ordered;

/// The system saw is running on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub supported: bool,
}

/// What this saw supports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesDocument {
    pub schema_version: u32,
    pub version: String,
    pub schema_versions: Ordered<u32>,
    pub features: Vec<String>,
    pub platform: Platform,
}
