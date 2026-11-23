//! The engine's judgement of one subject.

use crate::finding::Finding;

/// The outcome of a judgement, lowest precedence first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    Clean,
    Residue,
    Suspicious,
    NotVerified,
    Infected,
}

/// Why part of a subject was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapKind {
    /// The subject could not be read at all.
    NotRead,
    /// A file or object could not be read.
    Unreadable,
    /// A part was left out by the reading rules.
    Pruned,
    /// The budget ran out first.
    OutOfTime,
    /// The engine read less than the whole subject.
    Narrowed,
}

/// One part of a subject that was not read, and what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub kind: GapKind,
    pub detail: String,
}

/// How much of a subject was read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    pub gaps: Vec<Gap>,
}

impl Coverage {
    /// Return whether every part of the subject was read.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// Where a judged subject came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Remote,
}

/// The judgement of one subject: what `main` reports as one target's result, with its coverage.
#[derive(Debug, Clone, PartialEq)]
pub struct Judgement {
    pub target: String,
    pub source: Source,
    pub findings: Vec<Finding>,
    pub advisories: Vec<Finding>,
    pub informational: Vec<Finding>,
    pub notes: Vec<String>,
    pub stored_payload: Option<String>,
    pub coverage: Coverage,
}
