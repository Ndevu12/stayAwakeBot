//! What the engine decides about one subject: the findings, how much of the subject was read,
//! and the outcome.

use crate::finding::Finding;

/// The outcome of a judgement, ordered by precedence: a later outcome outranks every earlier
/// one, and a judgement takes the highest that applies.
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
    /// Whether every part of the subject was read.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcomes_rank_as_the_plan_orders_them() {
        let mut ranked = [Outcome::Suspicious, Outcome::Clean, Outcome::Infected, Outcome::Residue, Outcome::NotVerified];
        ranked.sort();
        assert_eq!(ranked, [Outcome::Clean, Outcome::Residue, Outcome::Suspicious, Outcome::NotVerified, Outcome::Infected]);
    }

    #[test]
    fn coverage_is_complete_only_with_no_gap() {
        assert!(Coverage::default().is_complete());
        let cut = Coverage { gaps: vec![Gap { kind: GapKind::OutOfTime, detail: "the deadline".into() }] };
        assert!(!cut.is_complete());
    }
}
