//! The progress events `--progress=jsonl` writes, one per line.

use serde::{Deserialize, Serialize};

/// One progress event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase", deny_unknown_fields)]
pub enum ProgressEvent {
    /// The run began.
    Start {
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        steps: Option<u64>,
    },
    /// A step is underway.
    Step {
        id: String,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        of: Option<u64>,
    },
    /// A repository or path is underway.
    Target {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        of: Option<u64>,
    },
    /// What a target holds and how long it should take.
    Plan {
        target: String,
        files: u64,
        bytes: u64,
        commits: u64,
        workers: u64,
        estimate_seconds: u64,
        budget_seconds: u64,
    },
    /// How far a target has come.
    Progress {
        target: String,
        phase: String,
        total: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        done: Option<u64>,
    },
    /// The run finished, with the status the command returns.
    Done { exit: i64 },
}
